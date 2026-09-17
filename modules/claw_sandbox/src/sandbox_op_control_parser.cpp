/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Op-control JSON parsing (AddOperationControlRuleGroups) and the model -> TLV rebuild /
// serialization. Entry points (ConvertOperationControlToTlv, BuildAlPolicyContext,
// ParseOperationControlRuleGroups, SandboxPolicyTlv methods) are defined here. Parsing
// carries a SandboxPolicyParsePhase: startup vs. later dynamic delivery differ only in
// EnforcePhaseRules, so the common schema parsers stay phase-agnostic.

#include "sandbox_cmd_parser.h"
#include "sandbox_error.h"
#include "sandbox_log.h"
#include <cstdlib>
#include <iostream>
#include <cstring>
#include <cctype>
#include <unordered_map>
#include "cJSON.h"
#include <functional>
#include <securec.h>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

/* ============================================================================
 * [1] RuleGroup parsing + per-group model->TLV conversion (config model side)
 * ============================================================================ */

static const std::unordered_map<std::string, DEC_POLICY_SCOPE_TYPE> g_ocScopeTypeMap = {
    {"global", DEC_POLICY_SCOPE_TYPE_GLOBAL},
    {"specific_user", DEC_POLICY_SCOPE_TYPE_SPECIFIC_USER},
    {"specific_app", DEC_POLICY_SCOPE_TYPE_SPECIFIC_APP},
    {"self_app", DEC_POLICY_SCOPE_TYPE_SELF_APP},
    {"specific_task", DEC_POLICY_SCOPE_TYPE_SPECIFIC_TASK},
    {"self_task", DEC_POLICY_SCOPE_TYPE_SELF_TASK},
    {"self_session", DEC_POLICY_SCOPE_TYPE_SELF_SESSION},
};

// Shared DefaultAction vocabulary for the Network/File/Process parsers; holds all four words.
// Network is the strictest: only "deny"/"allow" are admitted (checked at its site), while
// File/Process accept the full allow/deny/ask/none set.
static const std::unordered_map<std::string, DEC_POLICY_ACTION> g_ocActionMap = {
    {"allow", DEC_POLICY_ACTION_ALLOW},
    {"deny", DEC_POLICY_ACTION_DENY},
    {"ask", DEC_POLICY_ACTION_ASK},
    {"none", DEC_POLICY_ACTION_NONE},
};

// Helper: parse a required string field with no length cap. Use for fields whose
// value is already constrained by a following vocabulary/exact-match lookup.
static int ParseStringField(cJSON *root, const char *key, std::string &out)
{
    cJSON *item = cJSON_GetObjectItem(root, key);
    if (!cJSON_IsString(item) || item->valuestring == nullptr) {
        std::cerr << "Error: Config field '" << key << "' missing or not a string" << std::endl;
        SANDBOX_LOGE("Config field '%{public}s' missing or not a string", key);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    out = item->valuestring;
    return SANDBOX_SUCCESS;
}

// Helper: parse an optional string field. Absent → SANDBOX_SUCCESS with *found=false; present
// but not a JSON string → error. The caller picks its default when *found is false.
static int ParseOptionalStringField(cJSON *root, const char *key, std::string &out, bool &found)
{
    found = false;
    cJSON *item = cJSON_GetObjectItem(root, key);
    if (item == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsString(item) || item->valuestring == nullptr) {
        std::cerr << "Error: Config field '" << key << "' missing or not a string" << std::endl;
        SANDBOX_LOGE("Config field '%{public}s' missing or not a string", key);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    found = true;
    out = item->valuestring;
    return SANDBOX_SUCCESS;
}

// Post-parse content check hook for ParseOptionalStringArrayField: returns an error code on a
// bad value. Today only the exec-cmd bare-name rule; signature matches ValidateExecCmdArray.
using ArrayFieldValidator = int (*)(const char *key, const std::vector<std::string> &values);

// Helper: parse an optional string array field. When validate is non-null, the
// collected array is checked through it before this returns success.
static int ParseOptionalStringArrayField(cJSON *root, const char *key,
    std::vector<std::string> &out, ArrayFieldValidator validate = nullptr)
{
    cJSON *array = cJSON_GetObjectItem(root, key);
    if (array == nullptr) {
        return SANDBOX_SUCCESS; // field absent → skip
    }
    if (!cJSON_IsArray(array)) {
        std::cerr << "Error: Config field '" << key << "' type mismatch: expected array" << std::endl;
        SANDBOX_LOGE("Config field '%{public}s' type mismatch: expected array", key);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    int size = cJSON_GetArraySize(array);
    for (int i = 0; i < size; i++) {
        cJSON *item = cJSON_GetArrayItem(array, i);
        if (!cJSON_IsString(item) || item->valuestring == nullptr) {
            std::cerr << "Error: Config field '" << key << "' contains non-string item" << std::endl;
            SANDBOX_LOGE("Config field '%{public}s' contains non-string item", key);
            return SANDBOX_ERR_CONFIG_INVALID;
        }
        out.push_back(item->valuestring);
    }
    if (validate != nullptr) {
        int vret = validate(key, out);
        if (vret != SANDBOX_SUCCESS) {
            return vret;
        }
    }
    return SANDBOX_SUCCESS;
}

// Parse and validate Scope.Type (required; only "self_session" is supported
// this version). Unknown types are rejected.
static int ParseOperationControlScopeType(cJSON *scopeObj, SandboxPolicyScope &scope)
{
    std::string typeStr;
    int ret = ParseStringField(scopeObj, "Type", typeStr);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Parse config field 'Scope.Type' failed, ret=%{public}d", ret);
        return ret;
    }
    auto typeIt = g_ocScopeTypeMap.find(typeStr);
    if (typeIt == g_ocScopeTypeMap.end()) {
        std::cerr << "Error: Config field 'Scope.Type' has invalid value: " << typeStr << std::endl;
        SANDBOX_LOGE("Config field 'Scope.Type' has invalid value: %{public}s", typeStr.c_str());
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    scope.type = typeIt->second;
    if (scope.type != DEC_POLICY_SCOPE_TYPE_SELF_SESSION) {
        std::cerr << "Error: Config field 'Scope.Type' value '" << typeStr <<
                     "' is not supported this version (only self_session)" << std::endl;
        SANDBOX_LOGE("Config field 'Scope.Type' value '%{public}s' is not supported "
            "this version (only self_session)", typeStr.c_str());
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    return SANDBOX_SUCCESS;
}

// Parse the required Scope object: only Scope.Type is recognized (must be "self_session").
static int ParseOperationControlScope(cJSON *ruleGroupItem, SandboxPolicyScope &scope)
{
    cJSON *scopeObj = cJSON_GetObjectItem(ruleGroupItem, "Scope");
    if (!cJSON_IsObject(scopeObj)) {
        std::cerr << "Error: Config field 'Scope' missing or not an object" << std::endl;
        SANDBOX_LOGE("Config field 'Scope' missing or not an object");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    int ret = ParseOperationControlScopeType(scopeObj, scope);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Parse 'Scope.Type' failed, ret=%{public}d", ret);
        return ret;
    }
    return SANDBOX_SUCCESS;
}

// Parse the Network object (optional). When Network is present its DefaultAction is
// REQUIRED and must be "deny" or "allow": a network policy always states an explicit
// default, unlike File/Process. "ask"/"none"/absent are all rejected.
static int ParseNetworkOperationControl(cJSON *ruleGroupItem,
    bool &hasNetwork, SandboxPolicyNetworkConfig &networkRules)
{
    cJSON *networkObj = cJSON_GetObjectItem(ruleGroupItem, "Network");
    if (networkObj == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsObject(networkObj)) {
        std::cerr << "Error: Config field 'Network' not an object" << std::endl;
        SANDBOX_LOGE("Config field 'Network' not an object");
        return SANDBOX_ERR_CONFIG_INVALID;
    }

    // Network.DefaultAction is required and admits only "deny" or "allow".
    std::string actionStr;
    int ret = ParseStringField(networkObj, "DefaultAction", actionStr);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Parse config field 'Network.DefaultAction' failed, ret=%{public}d", ret);
        return ret;
    }
    auto actionIt = g_ocActionMap.find(actionStr);
    if (actionIt == g_ocActionMap.end() ||
        (actionIt->second != DEC_POLICY_ACTION_DENY &&
         actionIt->second != DEC_POLICY_ACTION_ALLOW)) {
        std::cerr << "Error: Config field 'Network.DefaultAction' must be \"deny\" or " <<
                     "\"allow\": " << actionStr << std::endl;
        SANDBOX_LOGE("Config field 'Network.DefaultAction' must be deny or allow: %{public}s",
                     actionStr.c_str());
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    networkRules.defaultAction = actionIt->second;
    hasNetwork = true;
    return SANDBOX_SUCCESS;
}

// Parse the File object (optional, all sub-fields optional string arrays)
static int ParseFileOperationControl(cJSON *ruleGroupItem,
    bool &hasFile, SandboxPolicyFileConfig &fileRules)
{
    cJSON *fileObj = cJSON_GetObjectItem(ruleGroupItem, "File");
    if (fileObj == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsObject(fileObj)) {
        std::cerr << "Error: Config field 'File' not an object" << std::endl;
        SANDBOX_LOGE("Config field 'File' not an object");
        return SANDBOX_ERR_CONFIG_INVALID;
    }

    // File.DefaultAction is optional; default to NONE when not configured.
    std::string actionStr;
    bool found = false;
    int ret = ParseOptionalStringField(fileObj, "DefaultAction", actionStr, found);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Parse config field 'File.DefaultAction' failed, ret=%{public}d", ret);
        return ret;
    }
    if (found) {
        auto actionIt = g_ocActionMap.find(actionStr);
        if (actionIt == g_ocActionMap.end()) {
            std::cerr << "Error: Config field 'File.DefaultAction' has invalid value: " << actionStr << std::endl;
            SANDBOX_LOGE("Config field 'File.DefaultAction' has invalid value: %{public}s", actionStr.c_str());
            return SANDBOX_ERR_CONFIG_INVALID;
        }
        fileRules.defaultAction = actionIt->second;
    }

    // File sub-fields are optional path arrays, all parsed through one loop; a new operation only
    // needs a new table row plus the matching field on SandboxPolicyFileConfig.
    struct FileArrayField {
        const char *key;
        std::vector<std::string> *values;
    };
    const FileArrayField fileArrayFields[] = {
        {"DenyDelete", &fileRules.denyDelete},
        {"AllowDelete", &fileRules.allowDelete},
        {"AskDelete", &fileRules.askDelete},
    };
    for (const auto &field : fileArrayFields) {
        int ret = ParseOptionalStringArrayField(fileObj, field.key, *(field.values));
        if (ret != SANDBOX_SUCCESS) {
            SANDBOX_LOGE("Parse 'File.%{public}s' failed, ret=%{public}d", field.key, ret);
            return ret;
        }
    }

    hasFile = true;
    return SANDBOX_SUCCESS;
}

// Exec cmds must be bare names ("ls"), never paths ("/bin/ls"): a path would make the kernel
// match depend on the subject's PATH resolution. Reject entries with a path separator.
static bool IsExecCmdPathful(const std::string &cmd)
{
    return cmd.find('/') != std::string::npos;
}

// Validate a parsed exec-cmd array: reject every entry that carries a path.
static int ValidateExecCmdArray(const char *key, const std::vector<std::string> &cmds)
{
    for (const auto &cmd : cmds) {
        if (IsExecCmdPathful(cmd)) {
            std::cerr << "Error: Config field '" << key << "' item '" << cmd <<
                         "' must be a bare command name (no '/' allowed)" << std::endl;
            SANDBOX_LOGE("Config field '%{public}s' item must be a bare command "
                "name (no '/' allowed)", key);
            return SANDBOX_ERR_CONFIG_INVALID;
        }
    }
    return SANDBOX_SUCCESS;
}

// Parse the Process object (optional, DefaultAction required if present)
static int ParseProcessOperationControl(cJSON *ruleGroupItem,
    bool &hasProcess, SandboxPolicyProcessConfig &processRules)
{
    cJSON *processObj = cJSON_GetObjectItem(ruleGroupItem, "Process");
    if (processObj == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsObject(processObj)) {
        std::cerr << "Error: Config field 'Process' not an object" << std::endl;
        SANDBOX_LOGE("Config field 'Process' not an object");
        return SANDBOX_ERR_CONFIG_INVALID;
    }

    // Process DefaultAction is optional (default NONE); when present it allows
    // "allow", "deny", "ask", or explicit "none".
    std::string actionStr;
    bool found = false;
    int ret = ParseOptionalStringField(processObj, "DefaultAction", actionStr, found);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Parse config field 'Process.DefaultAction' failed, ret=%{public}d", ret);
        return ret;
    }
    if (found) {
        auto actionIt = g_ocActionMap.find(actionStr);
        if (actionIt == g_ocActionMap.end()) {
            std::cerr << "Error: Config field 'Process.DefaultAction' has invalid value: " << actionStr << std::endl;
            SANDBOX_LOGE("Config field 'Process.DefaultAction' has invalid value: %{public}s", actionStr.c_str());
            return SANDBOX_ERR_CONFIG_INVALID;
        }
        processRules.defaultAction = actionIt->second;
    }

    // Process sub-fields are optional bare-name arrays, parsed and validated through one loop (the
    // bare-name check runs in ParseOptionalStringArrayField via the passed-in validator). A new
    // operation needs a new table row plus the matching field on SandboxPolicyProcessConfig.
    struct ProcessArrayField {
        const char *key;
        std::vector<std::string> *values;
    };
    const ProcessArrayField processArrayFields[] = {
        {"DenyExecCmd", &processRules.denyExecCmd},
        {"AllowExecCmd", &processRules.allowExecCmd},
        {"AskExecCmd", &processRules.askExecCmd},
    };
    for (const auto &field : processArrayFields) {
        ret = ParseOptionalStringArrayField(processObj, field.key, *(field.values), ValidateExecCmdArray);
        if (ret != SANDBOX_SUCCESS) {
            SANDBOX_LOGE("Parse 'Process.%{public}s' failed, ret=%{public}d", field.key, ret);
            return ret;
        }
    }

    hasProcess = true;
    return SANDBOX_SUCCESS;
}

static int EnforcePhaseRules(SandboxPolicyParsePhase phase,
    const SandboxPolicyRuleGroup &ruleGroup)
{
    if (phase == SANDBOX_POLICY_PARSE_DYNAMIC && ruleGroup.hasNetwork) {
        std::cerr << "Error: a dynamic policy must not include a Network module" << std::endl;
        SANDBOX_LOGE("a dynamic policy must not include a Network module");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    return SANDBOX_SUCCESS;
}

// Parse a single item in the AddOperationControlRuleGroups array
static int ParseOperationControlRuleGroupItem(cJSON *item,
    SandboxPolicyRuleGroup &ruleGroup, SandboxPolicyParsePhase phase)
{
    int ret = ParseOperationControlScope(item, ruleGroup.scope);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Parse rule group Scope failed, ret=%{public}d", ret);
        return ret;
    }
    ret = ParseNetworkOperationControl(item, ruleGroup.hasNetwork, ruleGroup.networkRules);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Parse rule group Network failed, ret=%{public}d", ret);
        return ret;
    }
    ret = ParseFileOperationControl(item, ruleGroup.hasFile, ruleGroup.fileRules);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Parse rule group File failed, ret=%{public}d", ret);
        return ret;
    }
    ret = ParseProcessOperationControl(item, ruleGroup.hasProcess, ruleGroup.processRules);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Parse rule group Process failed, ret=%{public}d", ret);
        return ret;
    }
    // Common schema parsed; apply this phase's rules over the parsed group.
    ret = EnforcePhaseRules(phase, ruleGroup);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Parse rule group failed phase rules, ret=%{public}d", ret);
        return ret;
    }
    return SANDBOX_SUCCESS;
}

// Main entry: parse AddOperationControlRuleGroups array from the policy object.
// phase tells whether this is the sandbox boot-time profile or a later dynamic policy;
// each group is phase-checked by EnforcePhaseRules after its common schema is parsed.
int CmdParser::ParseOperationControlRuleGroups(cJSON *policyObj,
    std::vector<SandboxPolicyRuleGroup> &ruleGroups,
    SandboxPolicyParsePhase phase)
{
    cJSON *array = cJSON_GetObjectItem(policyObj, "AddOperationControlRuleGroups");
    if (array == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsArray(array)) {
        std::cerr << "Error: Config field 'AddOperationControlRuleGroups' type mismatch: expected array" << std::endl;
        SANDBOX_LOGE("Config field 'AddOperationControlRuleGroups' type mismatch: expected array");
        return SANDBOX_ERR_CONFIG_INVALID;
    }

    int size = cJSON_GetArraySize(array);
    for (int i = 0; i < size; i++) {
        cJSON *item = cJSON_GetArrayItem(array, i);
        if (!cJSON_IsObject(item)) {
            std::cerr << "Error: Config field 'AddOperationControlRuleGroups' should contain objects" << std::endl;
            SANDBOX_LOGE("Config field 'AddOperationControlRuleGroups' should contain objects");
            return SANDBOX_ERR_CONFIG_INVALID;
        }

        SandboxPolicyRuleGroup ruleGroup;
        int ret = ParseOperationControlRuleGroupItem(item, ruleGroup, phase);
        if (ret != SANDBOX_SUCCESS) {
            SANDBOX_LOGE("Parse AddOperationControlRuleGroups[%{public}d] failed, ret=%{public}d", i, ret);
            return ret;
        }
        // The array exists to carry several DISTINCT Scope types; a group repeating an
        // earlier group's Scope.Type is rejected. (self_session is the only allowed type
        // today, so this caps the list at one group.)
        for (const SandboxPolicyRuleGroup &pushed : ruleGroups) {
            if (pushed.scope.type == ruleGroup.scope.type) {
                std::cerr << "Error: Config field 'AddOperationControlRuleGroups' has duplicate "
                    "Scope.Type" << std::endl;
                SANDBOX_LOGE("Config field 'AddOperationControlRuleGroups' has duplicate Scope.Type");
                return SANDBOX_ERR_CONFIG_INVALID;
            }
        }
        ruleGroups.push_back(ruleGroup);
    }

    return SANDBOX_SUCCESS;
}

// --- convert each rule group of one module into its own policy ---

// Convert a delete path array into TLV rules: each path becomes its own rule (action +
// eventType + one PATH object), never aggregated; subjectRules stay empty.
static void ConvertFileDeleteRulesToTlv(const std::vector<std::string> &paths,
    uint32_t action, SandboxPolicyTlv::Policy &policy)
{
    if (paths.empty()) {
        return;
    }
    const uint32_t eventType = static_cast<uint32_t>(DEC_POLICY_FILE_EVENT_RMDIR | DEC_POLICY_FILE_EVENT_UNLINK);
    for (const auto &path : paths) {
        SandboxPolicyTlv::FilterRule objectRule;
        objectRule.cmpType = DEC_POLICY_CMP_EQ;
        objectRule.itemType = DEC_POLICY_ITEM_TYPE_PATH;
        objectRule.path = path;
        SandboxPolicyTlv::Rule rule;
        rule.action = action;
        rule.eventType = eventType;
        rule.objectRules.push_back(std::vector<SandboxPolicyTlv::FilterRule>{objectRule});
        policy.rules.push_back(rule);
    }
}

// Convert an exec cmd array into TLV rules: each cmd becomes its own rule, never aggregated;
// subjectRules stay empty.
static void ConvertProcessExecRulesToTlv(const std::vector<std::string> &cmds,
    uint32_t action, SandboxPolicyTlv::Policy &policy)
{
    if (cmds.empty()) {
        return;
    }
    const uint32_t eventType = static_cast<uint32_t>(DEC_POLICY_PROCESS_EVENT_EXEC);
    for (const auto &cmd : cmds) {
        SandboxPolicyTlv::FilterRule objectRule;
        objectRule.cmpType = DEC_POLICY_CMP_EQ;
        objectRule.itemType = DEC_POLICY_ITEM_TYPE_CMD;
        objectRule.cmd = cmd;
        SandboxPolicyTlv::Rule rule;
        rule.action = action;
        rule.eventType = eventType;
        rule.objectRules.push_back(std::vector<SandboxPolicyTlv::FilterRule>{objectRule});
        policy.rules.push_back(rule);
    }
}

// Map an action enum value to its config-facing name for log messages.
static const char *ActionToString(uint32_t action)
{
    switch (action) {
        case DEC_POLICY_ACTION_ALLOW:
            return "ALLOW";
        case DEC_POLICY_ACTION_DENY:
            return "DENY";
        case DEC_POLICY_ACTION_ASK:
            return "ASK";
        case DEC_POLICY_ACTION_NONE:
            return "NONE";
        default:
            return "UNKNOWN";
    }
}

// Report one clash. A caller that collects gets it in errors; the one that does not gets it
// printed, because a monitor answering the app over a socket owns no terminal to print to.
static void ReportActionConflict(const std::string &opLabel, const std::string &object,
    uint32_t firstAction, uint32_t secondAction, std::vector<PolicyError> *errors)
{
    SANDBOX_LOGE("object '%{public}s' appears under both action %{public}s and %{public}s "
        "in operation '%{public}s'", object.c_str(), ActionToString(firstAction),
        ActionToString(secondAction), opLabel.c_str());
    if (errors == nullptr) {
        std::cerr << "Error: object '" << object << "' appears under both action " <<
                     ActionToString(firstAction) << " and " << ActionToString(secondAction) <<
                     " in operation '" << opLabel << "'" << std::endl;
        return;
    }
    errors->push_back(PolicyError::ActionConflict(opLabel, object,
        ActionToString(firstAction), ActionToString(secondAction)));
}

/*
 * How two rule objects are told apart, following the kernel's own key.
 *
 * A PATH rule is bound to an inode, and rule fds open O_NOFOLLOW, so lstat is
 * the exact match: a symlink is its own object, separate from whatever it points
 * at. That separation is deliberate - a policy is allowed to name the symlink
 * itself - and following the link here would report a rule on the link and a
 * rule on its target as a clash and refuse both. lstat also catches what
 * comparing spellings cannot: "/a/x" and "/a/./x", or two hard links to one
 * file, are a single object to the kernel.
 *
 * A CMD rule is a bare command name - ValidateExecCmdArray rejects any '/' - so
 * comparing the names is the whole job. It must not be stat'ed either: lstat of
 * a name like "rm" would succeed whenever the working directory happens to hold
 * a file by that name, silently keying the rule on an inode instead.
 *
 * A path with nothing to stat falls back to its spelling: a rule naming a file
 * that does not exist yet still has to be checked against its twin, and the
 * open failure is reported on its own.
 */
static std::string ObjectIdentity(const std::string &object, uint32_t itemType)
{
    if (itemType != DEC_POLICY_ITEM_TYPE_PATH) {
        return "cmd:" + object;
    }
    struct stat st = {};
    if (lstat(object.c_str(), &st) != 0) {
        return "path:" + object;
    }
    return "inode:" + std::to_string(st.st_dev) + ":" + std::to_string(st.st_ino);
}

// Reject one path/cmd under two different actions of an operation (deny+allow, deny+ask,
// allow+ask). objectAction is per group, so only intra-group conflicts are caught; cross-group
// overlap is legal (groups deliver independently, never merged).
// One operation's objects grouped by action, plus what it takes to judge them: the label a
// clash is reported under, and the item type that decides how two objects are told apart.
struct OperationActionSets {
    const char *opLabel;
    uint32_t itemType;
    const std::vector<std::string> *deny;
    const std::vector<std::string> *allow;
    const std::vector<std::string> *ask;
};

static int ValidateOperationActionConflict(const OperationActionSets &op,
    std::map<std::string, uint32_t> &objectAction,
    std::vector<PolicyError> *errors)
{
    const std::string opLabel = op.opLabel;
    const struct {
        const std::vector<std::string> *objects;
        uint32_t action;
    } actionArrays[] = {
        {op.deny, DEC_POLICY_ACTION_DENY},
        {op.allow, DEC_POLICY_ACTION_ALLOW},
        {op.ask, DEC_POLICY_ACTION_ASK},
    };
    bool conflicted = false;
    for (const auto &entry : actionArrays) {
        for (const auto &obj : *entry.objects) {
            // Keyed the way the kernel keys the rule, not on the spelling; see
            // ObjectIdentity. A string key would miss "/a/x" against "/a/./x",
            // deliver both, and let the later action silently win.
            const std::string key = opLabel + ":" + ObjectIdentity(obj, op.itemType);
            auto it = objectAction.find(key);
            if (it != objectAction.end() && it->second != entry.action) {
                ReportActionConflict(opLabel, obj, it->second, entry.action, errors);
                conflicted = true;
                // Keep the first action recorded, so a third entry for the same
                // object is reported against it rather than against the second.
                continue;
            }
            objectAction[key] = entry.action;
        }
    }
    // Scanned to the end on purpose: the caller has to fix every clash, so it
    // gets told about every clash rather than one per round trip.
    return conflicted ? SANDBOX_ERR_CONFIG_INVALID : SANDBOX_SUCCESS;
}

// Each Convert*RuleGroupToTlv writes a SINGLE group's header (operation_type + its own default
// action) and rules; groups never merge, so there is no first-group-wins latch.

// NETWORK module: a group currently carries only a default action -- no per-object
// rules yet, so converting one group yields a header-only policy.
static int ConvertNetworkRuleGroupToTlv(const SandboxPolicyRuleGroup &group,
    SandboxPolicyTlv::Policy &policy)
{
    policy.operationType = DEC_POLICY_OP_TYPE_NETWORK;
    policy.defaultAction = static_cast<uint32_t>(group.networkRules.defaultAction);
    return SANDBOX_SUCCESS;
}

// FILE module: write the header, catch same-path conflicts within this group, emit delete rules.
static int ConvertFileRuleGroupToTlv(const SandboxPolicyRuleGroup &group,
    SandboxPolicyTlv::Policy &policy, std::map<std::string, uint32_t> &objectAction,
    std::vector<PolicyError> *errors)
{
    // File.DefaultAction is optional; defaults to NONE when not configured.
    // Explicit per-rule actions always win.
    policy.operationType = DEC_POLICY_OP_TYPE_FILE;
    policy.defaultAction = static_cast<uint32_t>(group.fileRules.defaultAction);
    const OperationActionSets fileOp = {
        .opLabel = "FileDelete",
        .itemType = DEC_POLICY_ITEM_TYPE_PATH,
        .deny = &group.fileRules.denyDelete,
        .allow = &group.fileRules.allowDelete,
        .ask = &group.fileRules.askDelete,
    };
    int ret = ValidateOperationActionConflict(fileOp, objectAction, errors);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("ConvertFileRuleGroupToTlv: FileDelete action conflict, ret=%{public}d", ret);
        return ret;
    }
    ConvertFileDeleteRulesToTlv(group.fileRules.denyDelete, DEC_POLICY_ACTION_DENY, policy);
    ConvertFileDeleteRulesToTlv(group.fileRules.allowDelete, DEC_POLICY_ACTION_ALLOW, policy);
    ConvertFileDeleteRulesToTlv(group.fileRules.askDelete, DEC_POLICY_ACTION_ASK, policy);
    return SANDBOX_SUCCESS;
}

// PROCESS module: write the module header, reject the same cmd under two actions,
// then turn the exec cmd arrays into rules (bare-name check runs at parse time).
static int ConvertProcessRuleGroupToTlv(const SandboxPolicyRuleGroup &group,
    SandboxPolicyTlv::Policy &policy, std::map<std::string, uint32_t> &objectAction,
    std::vector<PolicyError> *errors)
{
    policy.operationType = DEC_POLICY_OP_TYPE_PROCESS;
    policy.defaultAction = static_cast<uint32_t>(group.processRules.defaultAction);
    const OperationActionSets processOp = {
        .opLabel = "ProcessExecCmd",
        .itemType = DEC_POLICY_ITEM_TYPE_CMD,
        .deny = &group.processRules.denyExecCmd,
        .allow = &group.processRules.allowExecCmd,
        .ask = &group.processRules.askExecCmd,
    };
    int ret = ValidateOperationActionConflict(processOp, objectAction, errors);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("ConvertProcessRuleGroupToTlv: ProcessExecCmd action conflict, ret=%{public}d", ret);
        return ret;
    }
    ConvertProcessExecRulesToTlv(group.processRules.denyExecCmd, DEC_POLICY_ACTION_DENY, policy);
    ConvertProcessExecRulesToTlv(group.processRules.allowExecCmd, DEC_POLICY_ACTION_ALLOW, policy);
    ConvertProcessExecRulesToTlv(group.processRules.askExecCmd, DEC_POLICY_ACTION_ASK, policy);
    return SANDBOX_SUCCESS;
}

int CmdParser::ConvertOperationControlToTlv(
    const std::vector<SandboxPolicyRuleGroup> &ruleGroups,
    DEC_POLICY_OP_TYPE moduleType,
    SandboxPolicyTlv &tlv,
    std::vector<PolicyError> *errors)
{
    // Convert each rule group that carries moduleType into its own self-contained policy;
    // tlv.policies holds one entry per contributing group (delivery passes a single group).
    // objectAction is per group: intra-group conflicts caught, cross-group overlap legal.
    for (const SandboxPolicyRuleGroup &group : ruleGroups) {
        SandboxPolicyTlv::Policy policy;
        // Action-conflict tracking within THIS group: keyed opLabel:object.
        std::map<std::string, uint32_t> objectAction;
        int ret = SANDBOX_SUCCESS;
        bool contributed = false;
        if (moduleType == DEC_POLICY_OP_TYPE_NETWORK && group.hasNetwork) {
            ret = ConvertNetworkRuleGroupToTlv(group, policy);
            contributed = true;
        } else if (moduleType == DEC_POLICY_OP_TYPE_FILE && group.hasFile) {
            ret = ConvertFileRuleGroupToTlv(group, policy, objectAction, errors);
            contributed = true;
        } else if (moduleType == DEC_POLICY_OP_TYPE_PROCESS && group.hasProcess) {
            ret = ConvertProcessRuleGroupToTlv(group, policy, objectAction, errors);
            contributed = true;
        }
        if (ret != SANDBOX_SUCCESS) {
            SANDBOX_LOGE("ConvertOperationControlToTlv: module conversion failed, ret=%{public}d", ret);
            return ret;
        }
        if (contributed) {
            tlv.policies.push_back(policy);
        }
    }
    return SANDBOX_SUCCESS;
}

/* ============================================================================
 * [2] SandboxPolicyTlv serialization, PATH-rule fds, DEC_CMD_POLICY_ADD payload
 * ============================================================================ */

// LE byte-width constants for the writers below: BYTE_BITS is one octet and
// BYTE_MASK isolates it; U32_BITS is the word width and the high-word shift of a u64.
constexpr uint32_t BYTE_BITS = 8;
constexpr uint32_t BYTE_MASK = 0xFF;
constexpr uint32_t U32_BITS = 32;

// Append a uint32 in little-endian (lowest byte first)
static void AppendU32LE(std::vector<uint8_t> &out, uint32_t value)
{
    for (uint32_t shift = 0; shift < U32_BITS; shift += BYTE_BITS) {
        out.push_back(static_cast<uint8_t>((value >> shift) & BYTE_MASK));
    }
}

// Append a uint64 in little-endian: low word first, then the high word.
static void AppendU64LE(std::vector<uint8_t> &out, uint64_t value)
{
    AppendU32LE(out, static_cast<uint32_t>(value));             // low 32 bits (cast truncates)
    AppendU32LE(out, static_cast<uint32_t>(value >> U32_BITS)); // high 32 bits
}

// Append a TLV whose value is a uint32
static void AppendTlvU32(std::vector<uint8_t> &out, uint32_t type, uint32_t value)
{
    AppendU32LE(out, type);
    AppendU32LE(out, sizeof(uint32_t));
    AppendU32LE(out, value);
}

// Append a TLV whose value is a raw byte array
static void AppendTlvBytes(std::vector<uint8_t> &out, uint32_t type, const uint8_t *data, uint32_t len)
{
    AppendU32LE(out, type);
    AppendU32LE(out, len);
    out.insert(out.end(), data, data + len);
}

// Serialize one filter rule: [11]cmp_type [12]item_type [13]item (single value; its length
// comes from the TLV header, no item_size tag). PATH->path_str, CMD->cmd_str, FD->4-byte fd
// in its own entity (see AppendRuleEntitySection).
static int AppendFilterRuleBlock(std::vector<uint8_t> &out, const SandboxPolicyTlv::FilterRule &rule)
{
    switch (rule.cmpType) {
        case DEC_POLICY_CMP_EQ:
            break;
        default:
            SANDBOX_LOGE("AppendFilterRuleBlock: unsupported cmpType=%{public}u", rule.cmpType);
            return SANDBOX_ERR_CONFIG_INVALID;
    }

    std::vector<uint8_t> item;
    switch (rule.itemType) {
        case DEC_POLICY_ITEM_TYPE_PATH:
            item.insert(item.end(), rule.path.begin(), rule.path.end());
            item.push_back(0); // path_str, null-terminated
            break;
        case DEC_POLICY_ITEM_TYPE_CMD:
            item.insert(item.end(), rule.cmd.begin(), rule.cmd.end());
            item.push_back(0); // cmd_str, null-terminated
            break;
        case DEC_POLICY_ITEM_TYPE_FD:
            AppendU32LE(item, static_cast<uint32_t>(rule.fd)); // fd value, no terminator
            break;
        default:
            SANDBOX_LOGE("AppendFilterRuleBlock: unsupported itemType=%{public}u", rule.itemType);
            return SANDBOX_ERR_CONFIG_INVALID;
    }
    AppendTlvU32(out, DEC_POLICY_TLV_FILTER_RULE_CMP_TYPE, rule.cmpType);
    AppendTlvU32(out, DEC_POLICY_TLV_FILTER_RULE_ITEM_TYPE, rule.itemType);
    AppendTlvBytes(out, DEC_POLICY_TLV_FILTER_RULE_ITEM, item.data(), static_cast<uint32_t>(item.size()));
    return SANDBOX_SUCCESS;
}

// Wire entities one PATH rule expands into: an FD entity + a PATH entity (named so the count
// pass and the emit pass share one value).
static constexpr uint32_t PATH_RULE_WIRE_ENTITY_CNT = 2u;

// Wire entities a single filter rule expands into: only PATH expands (PATH_RULE_WIRE_ENTITY_CNT),
// CMD/FD stay single. Kept here so the expansion is not hard-coded at the call site.
static uint32_t GetFilterRuleWireEntityCnt(const SandboxPolicyTlv::FilterRule &rule)
{
    if (rule.itemType == DEC_POLICY_ITEM_TYPE_PATH) {
        return PATH_RULE_WIRE_ENTITY_CNT;
    }
    return 1u;
}

// One filter rule's wire entities. A PATH rule goes out as an FD entity followed by the PATH
// entity itself, so the kernel gets both the handle it matches on and the name it reports.
static int AppendFilterRuleEntities(std::vector<uint8_t> &out,
    const SandboxPolicyTlv::FilterRule &fr)
{
    if (fr.itemType != DEC_POLICY_ITEM_TYPE_PATH) {
        return AppendFilterRuleBlock(out, fr);
    }
    SandboxPolicyTlv::FilterRule fdRule;
    fdRule.cmpType = DEC_POLICY_CMP_EQ;
    fdRule.itemType = DEC_POLICY_ITEM_TYPE_FD;
    fdRule.fd = fr.fd;
    int ret = AppendFilterRuleBlock(out, fdRule);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    return AppendFilterRuleBlock(out, fr);
}

// Append a rule's subject (10) or object (14) section: entity_cnt tag + filter-rule blocks
// (subject/object_item_cnt dropped -- each entity carries one rule). A PATH rule expands to an
// FD entity + a PATH entity, both with a valid fd (open failure is fatal, see OpenFileFds).
// Wire entities a whole section expands into. The count has to go out before the blocks,
// so it is its own pass over the same rules.
static uint32_t CountSectionWireEntities(
    const std::vector<std::vector<SandboxPolicyTlv::FilterRule>> &entities)
{
    uint32_t total = 0;
    for (const auto &entity : entities) {
        for (const auto &fr : entity) {
            total += GetFilterRuleWireEntityCnt(fr);
        }
    }
    return total;
}

// One entity's filter rules, in order.
static int AppendEntityRules(std::vector<uint8_t> &out,
    const std::vector<SandboxPolicyTlv::FilterRule> &entity)
{
    for (const auto &fr : entity) {
        int ret = AppendFilterRuleEntities(out, fr);
        if (ret != SANDBOX_SUCCESS) {
            return ret;
        }
    }
    return SANDBOX_SUCCESS;
}

static int AppendRuleEntitySection(std::vector<uint8_t> &out, uint32_t entityCntTag,
    const std::vector<std::vector<SandboxPolicyTlv::FilterRule>> &entities)
{
    AppendTlvU32(out, entityCntTag, CountSectionWireEntities(entities));
    for (const auto &entity : entities) {
        int ret = AppendEntityRules(out, entity);
        if (ret != SANDBOX_SUCCESS) {
            return ret;
        }
    }
    return SANDBOX_SUCCESS;
}

// Append one rule block: [8]action [9]event [10]subject_cnt ... [14]object_cnt ...
static int AppendRuleBlock(std::vector<uint8_t> &out, const SandboxPolicyTlv::Rule &rule)
{
    AppendTlvU32(out, DEC_POLICY_TLV_RULE_ACTION, rule.action);
    AppendTlvU32(out, DEC_POLICY_TLV_RULE_EVENT_TYPE, rule.eventType);
    int ret = AppendRuleEntitySection(out, DEC_POLICY_TLV_FILTER_RULE_SUBJECT_CNT, rule.subjectRules);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    return AppendRuleEntitySection(out, DEC_POLICY_TLV_FILTER_RULE_OBJECT_CNT, rule.objectRules);
}

// Append the scope block: [1]scope = SandboxPolicyScopeBody packed little-endian, no padding;
// the former scope_size prefix is gone (the scope TLV header carries the length).
static void AppendScopeBlock(std::vector<uint8_t> &out, const SandboxPolicyScopeBody &scope)
{
    std::vector<uint8_t> scopeBytes;
    AppendU32LE(scopeBytes, scope.scope_id);
    AppendU32LE(scopeBytes, scope.scope_userid);
    AppendU64LE(scopeBytes, scope.scope_appidentifier);
    AppendU64LE(scopeBytes, scope.scope_taskid);
    AppendTlvBytes(out, DEC_POLICY_TLV_SCOPE, scopeBytes.data(), static_cast<uint32_t>(scopeBytes.size()));
}

int SandboxPolicyTlv::Serialize(std::vector<uint8_t> &out) const
{
    AppendScopeBlock(out, scope);

    AppendTlvU32(out, DEC_POLICY_TLV_POLICY_CNT, static_cast<uint32_t>(policies.size()));

    for (const Policy &policy : policies) {
        // Serialize the policy content first to compute operation_size
        // (tag 4 = byte length from operation_type to the last filter rule).
        std::vector<uint8_t> policyBlock;
        AppendTlvU32(policyBlock, DEC_POLICY_TLV_OPERATION_TYPE, policy.operationType);
        AppendTlvU32(policyBlock, DEC_POLICY_TLV_DEFAULT_ACTION, policy.defaultAction);
        AppendTlvU32(policyBlock, DEC_POLICY_TLV_ASK_TIMEOUT_DEFAULT_ACTION, policy.askTimeoutDefaultAction);
        AppendTlvU32(policyBlock, DEC_POLICY_TLV_RULESLIST_CNT, static_cast<uint32_t>(policy.rules.size()));
        for (const Rule &rule : policy.rules) {
            int ret = AppendRuleBlock(policyBlock, rule);
            if (ret != SANDBOX_SUCCESS) {
                return ret;
            }
        }
        AppendTlvU32(out, DEC_POLICY_TLV_OPERATION_SIZE, static_cast<uint32_t>(policyBlock.size()));
        out.insert(out.end(), policyBlock.begin(), policyBlock.end());
    }
    return SANDBOX_SUCCESS;
}

// "Not open" marker for a PATH-rule fd: -1 is never a valid fd, so CloseFileFds() skips rules
// still marked INVALID_PATH_FD. OpenFileFds() re-marks every PATH rule before opening.
static constexpr int INVALID_PATH_FD = -1;

// Apply fn to every PATH filter rule in the entity list (CMD rules untouched).
static void ForEachPathRule(std::vector<std::vector<SandboxPolicyTlv::FilterRule>> &entities,
    const std::function<void(SandboxPolicyTlv::FilterRule &)> &fn)
{
    for (auto &entity : entities) {
        for (SandboxPolicyTlv::FilterRule &fr : entity) {
            if (fr.itemType == DEC_POLICY_ITEM_TYPE_PATH) {
                fn(fr);
            }
        }
    }
}

// Open one PATH rule's file, recording why when it will not open.
static bool OpenOnePathRule(SandboxPolicyTlv::FilterRule &fr, std::vector<PolicyError> *errors)
{
    // O_PATH pins the path as-is: a symlink opens as the symlink itself (never followed),
    // so no O_RDONLY-to-O_PATH retry is needed. Kernel matches the rule on this fd.
    int fd = open(fr.path.c_str(), O_PATH | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        const int error = errno;
        SANDBOX_LOGE("OpenFileFds: open %{public}s failed: %{public}s",
            fr.path.c_str(), std::strerror(error));
        if (errors != nullptr) {
            errors->push_back(PolicyError::OpenFailed(fr.path, std::strerror(error)));
        }
        return false;
    }
    SANDBOX_FDSAN_MARK(fd, SANDBOX_FDSAN_SITE_RULE_PATH);
    fr.fd = fd;
    return true;
}

// Open every PATH rule's file, reporting each one that fails. The rules that did not open
// keep the INVALID_PATH_FD marker; the caller frees the rest through CloseFileFds().
static int OpenPathRules(std::vector<std::vector<SandboxPolicyTlv::FilterRule>> &entities,
    std::vector<PolicyError> *errors)
{
    bool failed = false;
    ForEachPathRule(entities, [&failed, errors](SandboxPolicyTlv::FilterRule &fr) {
        if (!OpenOnePathRule(fr, errors)) {
            failed = true;
        }
    });
    return failed ? SANDBOX_ERR_PATH_INVALID : SANDBOX_SUCCESS;
}

// Open every PATH-rule file for kernel fd matching. Every PATH rule opens with O_PATH|O_NOFOLLOW,
// so a regular file and a symlink alike resolve to the path itself -- no O_RDONLY-to-O_PATH retry.
// A genuine failure (missing file, perms, ...) is fatal -- no path-string fallback;
// CloseFileFds() still frees prior fds.
int SandboxPolicyTlv::OpenFileFds(std::vector<PolicyError> *errors)
{
    // Re-mark every PATH rule as "not open" (-1) before opening so a partial-failure CloseFileFds()
    // never closes an fd we did not open (or an fd from a previous OpenFileFds on a reused tlv).
    auto markUnopened = [](FilterRule &fr) {
        fr.fd = INVALID_PATH_FD;
    };
    for (Policy &policy : policies) {
        for (Rule &rule : policy.rules) {
            ForEachPathRule(rule.subjectRules, markUnopened);
            ForEachPathRule(rule.objectRules, markUnopened);
        }
    }

    // Every rule is attempted even after one fails, so the caller hears about all
    // the paths it has to fix. CloseFileFds() frees the ones that did open.
    bool failed = false;
    for (Policy &policy : policies) {
        for (Rule &rule : policy.rules) {
            failed |= OpenPathRules(rule.subjectRules, errors) != SANDBOX_SUCCESS;
            failed |= OpenPathRules(rule.objectRules, errors) != SANDBOX_SUCCESS;
        }
    }
    return failed ? SANDBOX_ERR_PATH_INVALID : SANDBOX_SUCCESS;
}

// Close every fd opened by OpenFileFds() (skips fds still marked as not open).
void SandboxPolicyTlv::CloseFileFds()
{
    auto closeFd = [](FilterRule &fr) {
        if (fr.fd != INVALID_PATH_FD) {
            SANDBOX_FDSAN_CLOSE(fr.fd, SANDBOX_FDSAN_SITE_RULE_PATH);
            fr.fd = INVALID_PATH_FD;
        }
    };
    for (Policy &policy : policies) {
        for (Rule &rule : policy.rules) {
            ForEachPathRule(rule.subjectRules, closeFd);
            ForEachPathRule(rule.objectRules, closeFd);
        }
    }
}

// --- build the ioctl payload carrier from a serialized SandboxPolicyTlv ---

// Kernel cap on the serialized policy TLV payload (mirror of kernel_struct.h; never include it
// in this TU).
constexpr size_t DEC_POLICY_TLV_MAX_SIZE = 64 * 1024;

// Build the SandboxPolicyArg for DEC_CMD_POLICY_ADD: serialize the TLV into data; module_id is
// left zeroed for the caller to set per ioctl. Caller frees the buffer with std::free().
int CmdParser::BuildAlPolicyContext(const SandboxPolicyTlv &tlv,
    struct SandboxPolicyArg *&context)
{
    std::vector<uint8_t> tlvBytes;
    int ret = tlv.Serialize(tlvBytes);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Serialize policy TLV failed, ret=%{public}d", ret);
        return ret;
    }
    if (tlvBytes.empty()) {
        SANDBOX_LOGE("Serialized policy TLV is empty");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    if (tlvBytes.size() > DEC_POLICY_TLV_MAX_SIZE) {
        SANDBOX_LOGE("Serialized policy TLV size (%{public}zu) exceeds kernel max "
            "(%{public}zu)", tlvBytes.size(), DEC_POLICY_TLV_MAX_SIZE);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    size_t totalSize = sizeof(struct SandboxPolicyArg) + tlvBytes.size();
    context = static_cast<struct SandboxPolicyArg *>(std::malloc(totalSize));
    if (context == nullptr) {
        SANDBOX_LOGE("Failed to allocate memory for SandboxPolicyArg");
        return SANDBOX_ERR_GENERIC;
    }
    if (memset_s(context, totalSize, 0, totalSize) != 0) {
        SANDBOX_LOGE("Failed to initialize memory for SandboxPolicyArg");
        std::free(context);
        context = nullptr;
        return SANDBOX_ERR_GENERIC;
    }
    context->version = tlv.version;
    context->size = static_cast<uint32_t>(tlvBytes.size());
    if (memcpy_s(context->data, tlvBytes.size(), tlvBytes.data(), tlvBytes.size()) != 0) {
        SANDBOX_LOGE("Failed to copy TLV bytes into SandboxPolicyArg");
        std::free(context);
        context = nullptr;
        return SANDBOX_ERR_GENERIC;
    }
    return SANDBOX_SUCCESS;
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
