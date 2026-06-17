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

#include "sandbox_cmd_parser.h"
#include "sandbox_error.h"
#include "sandbox_log.h"
#include <cstdlib>
#include <iostream>
#include <cstring>
#include "cJSON.h"
#include <sched.h>
#include <functional>
#include <securec.h>

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

// Maximum safe integer value representable by double's 53-bit mantissa (2^53)
constexpr double DOUBLE_SAFE_MAX = 9007199254740992.0;

// Maximum value for uint32 (2^32 - 1)
constexpr double UINT32_MAX_VALUE = 4294967295.0;

// Maximum length for hex sandbox name
constexpr size_t MAX_NAME_LENGTH = 64;

// Maximum length constraints for config string fields
constexpr size_t MAX_CLI_NAME_LENGTH = 256;
constexpr size_t MAX_SUB_CLI_NAME_LENGTH = 256;
constexpr size_t MAX_CHALLENGE_LENGTH = 40960;
constexpr size_t MAX_APP_IDENTIFIER_LENGTH = 64;
constexpr size_t MAX_BUNDLE_NAME_LENGTH = 256;
constexpr size_t MAX_WORKDIR_LENGTH = 1024;
constexpr size_t MAX_ENV_LENGTH = 10240;
constexpr size_t MAX_POLICY_LENGTH = 102400;
constexpr size_t MAX_TYPE_LENGTH = 10;

// Maximum constraints for nsFlags array
constexpr size_t MAX_NS_FLAGS_COUNT = 10;
constexpr size_t MAX_NS_FLAG_STRING_LENGTH = 24;

// Maximum constraints for agentlock policy
constexpr size_t MAX_POLICY_COUNT = 1024;
constexpr size_t MAX_ACTION_STR_LENGTH = 6;
constexpr size_t MAX_SCOPE_NAME_LENGTH = 16;

// Default Namespace flags if not specified in config
// mnt|net namespaces are required for sandbox isolation, so they are included in the default flags.
// The rest of the namespaces are optional and can be added via the "nsFlags" config field.
constexpr uint32_t DEFAULT_NS_FLAGS = CLONE_NEWNS | CLONE_NEWNET;

// Helper: clean up cJSON root and return error code
static inline int CleanupAndReturn(cJSON *root, int ret)
{
    cJSON_Delete(root);
    return ret;
}

static inline int CleanupParsedObjectAndReturn(cJSON *parsedObject, int ret)
{
    if (parsedObject != nullptr) {
        cJSON_Delete(parsedObject);
    }
    return ret;
}

static int GetOptionalObjectField(cJSON *root, const char *key, cJSON *&object, cJSON *&parsedObject, size_t maxLen)
{
    object = cJSON_GetObjectItem(root, key);
    parsedObject = nullptr;
    if (object == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (cJSON_IsObject(object)) {
        return SANDBOX_SUCCESS;
    }
    if (cJSON_IsString(object) && object->valuestring != nullptr) {
        if (object->valuestring[0] == '\0') {
            object = nullptr;
            return SANDBOX_SUCCESS;
        }
        std::string objectStr = object->valuestring;
        if (objectStr.length() > maxLen) {
            std::cerr << "Error: Config field '" << key << "' exceeds max length (" <<
                maxLen << ")" << std::endl;
            SANDBOX_LOGE("Config field '%{public}s' exceeds max length (%{public}zu)", key, maxLen);
            return SANDBOX_ERR_CONFIG_INVALID;
        }
        parsedObject = cJSON_Parse(objectStr.c_str());
        if (!cJSON_IsObject(parsedObject)) {
            std::cerr << "Error: Config field '" << key <<
                "' type mismatch: expected object or JSON object string" << std::endl;
            SANDBOX_LOGE("Config field '%{public}s' type mismatch: expected object or JSON object string", key);
            return CleanupParsedObjectAndReturn(parsedObject, SANDBOX_ERR_CONFIG_INVALID);
        }
        object = parsedObject;
        return SANDBOX_SUCCESS;
    }
    std::cerr << "Error: Config field '" << key <<
        "' type mismatch: expected object or JSON object string" << std::endl;
    SANDBOX_LOGE("Config field '%{public}s' type mismatch: expected object or JSON object string", key);
    return SANDBOX_ERR_CONFIG_INVALID;
}

// Helper: parse a required uint64 field
// Uses cJSON_GetNumberValue() for better precision; falls back to string parsing
// for values that may exceed double's 53-bit mantissa precision.
static int ParseUint64Field(cJSON *root, const char *key, uint64_t &out)
{
    cJSON *item = cJSON_GetObjectItem(root, key);
    if (!cJSON_IsNumber(item)) {
        std::cerr << "Error: Config field '" << key << "' missing or not a number" << std::endl;
        SANDBOX_LOGE("Config field '%{public}s' missing or not a number (expected uint64)", key);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    double d = cJSON_GetNumberValue(item);
    // If the value fits safely in double's 53-bit mantissa, use direct cast
    if (d >= 0 && d <= DOUBLE_SAFE_MAX) {
        out = static_cast<uint64_t>(d);
    } else {
        // For values exceeding 2^53, parse from the raw JSON string to avoid precision loss
        out = static_cast<uint64_t>(item->valuedouble);
    }
    return SANDBOX_SUCCESS;
}

// Helper: parse a required uint32 field
// Uses valuedouble and range check to avoid cJSON valueint truncation for
// values exceeding INT_MAX.
static int ParseUint32Field(cJSON *root, const char *key, uint32_t &out)
{
    cJSON *item = cJSON_GetObjectItem(root, key);
    if (!cJSON_IsNumber(item)) {
        std::cerr << "Error: Config field '" << key << "' missing or not a number" << std::endl;
        SANDBOX_LOGE("Config field '%{public}s' missing or not a number (expected uint32)", key);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    double d = cJSON_GetNumberValue(item);
    if (d < 0 || d > UINT32_MAX_VALUE) {
        std::cerr << "Error: Config field '" << key << "' value out of range for uint32: " << d << std::endl;
        SANDBOX_LOGE("Config field '%{public}s' value out of range for uint32: %{public}f", key, d);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    out = static_cast<uint32_t>(d);
    return SANDBOX_SUCCESS;
}

// Helper: parse a required string field with maximum length check
static int ParseStringFieldWithMaxLen(cJSON *root, const char *key,
    std::string &out, size_t maxLen)
{
    cJSON *item = cJSON_GetObjectItem(root, key);
    if (!cJSON_IsString(item) || item->valuestring == nullptr) {
        std::cerr << "Error: Config field '" << key << "' missing or not a string" << std::endl;
        SANDBOX_LOGE("Config field '%{public}s' missing or not a string", key);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    std::string val = item->valuestring;
    if (val.length() > maxLen) {
        std::cerr << "Error: Config field '" << key << "' exceeds max length (" <<
                  maxLen << ")" << std::endl;
        SANDBOX_LOGE("Config field '%{public}s' exceeds max length (%{public}zu)",
            key, maxLen);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    out = val;
    return SANDBOX_SUCCESS;
}

// Helper: parse an optional string field with maximum length check
static int ParseOptionalStringFieldWithMaxLen(cJSON *root, const char *key,
    std::string &out, size_t maxLen)
{
    cJSON *item = cJSON_GetObjectItem(root, key);
    if (item == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsString(item) || item->valuestring == nullptr) {
        std::cerr << "Error: Config field '" << key << "' must be a string" << std::endl;
        SANDBOX_LOGE("Config field '%{public}s' must be a string", key);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    std::string val = item->valuestring;
    if (val.length() > maxLen) {
        std::cerr << "Error: Config field '" << key << "' exceeds max length (" <<
                  maxLen << ")" << std::endl;
        SANDBOX_LOGE("Config field '%{public}s' exceeds max length (%{public}zu)",
            key, maxLen);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    out = val;
    return SANDBOX_SUCCESS;
}

// Helper: parse type field (max length MAX_TYPE_LENGTH)
static int ParseTypeField(cJSON *root, std::string &out)
{
    cJSON *item = cJSON_GetObjectItem(root, "type");
    if (item == nullptr) {
        out = "cli"; // default type is cli
        return SANDBOX_SUCCESS;
    }
    return ParseStringFieldWithMaxLen(root, "type", out, MAX_TYPE_LENGTH);
}

// Helper: parse the 'AddOperationControlRuleGroups' policy array and count the number of policy rules present
static int ParseAgentLockPolicyNum(cJSON *root, uint32_t &number)
{
    cJSON *ruleGroupObj = cJSON_GetObjectItem(root, "AddOperationControlRuleGroups");
    if (ruleGroupObj == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsArray(ruleGroupObj)) {
        std::cerr << "Error: Config field 'AddOperationControlRuleGroups' type mismatch: expected array" << std::endl;
        SANDBOX_LOGE("Config field 'AddOperationControlRuleGroups' type mismatch: expected array");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    int size = cJSON_GetArraySize(ruleGroupObj);
    for (int i = 0; i < size; i++) {
        cJSON *ruleGroupItem = cJSON_GetArrayItem(ruleGroupObj, i);
        if (!cJSON_IsObject(ruleGroupItem)) {
            std::cerr << "Error: Config field 'AddOperationControlRuleGroups' should contain objects" << std::endl;
            SANDBOX_LOGE("Config field 'AddOperationControlRuleGroups' should contain objects");
            return SANDBOX_ERR_CONFIG_INVALID;
        }
        for (const std::string &typeItem : typeSet) {
            if (cJSON_HasObjectItem(ruleGroupItem, typeItem.c_str())) {
                number++;
            }
        }
    }
    if (static_cast<size_t>(number) > MAX_POLICY_COUNT) {
        std::cerr << "Error: Total number of agentlock policies exceeds max (" <<
                  MAX_POLICY_COUNT << ")" << std::endl;
        SANDBOX_LOGE("Total number of agentlock policies exceeds max (%{public}zu)", MAX_POLICY_COUNT);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    return SANDBOX_SUCCESS;
}

// Helper: parse the 'Scope' field of an agentlock policy
static int ParseScopeField(cJSON *root, struct AgentLockPolicy &scope)
{
    cJSON *scopeObj = cJSON_GetObjectItem(root, "Scope");
    if (!cJSON_IsObject(scopeObj)) {
        std::cerr << "Error: Config field 'Scope' missing or not an object" << std::endl;
        SANDBOX_LOGE("Config field 'Scope' missing or not an object");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    std::string typeStr;
    int ret = ParseStringFieldWithMaxLen(scopeObj, "Type", typeStr, MAX_SCOPE_NAME_LENGTH);
    if (ret != SANDBOX_SUCCESS) {
        std::cerr << "Error: Failed to parse Scope.Type field" << std::endl;
        SANDBOX_LOGE("Failed to parse Scope.Type field");
        return ret;
    }
    auto scopyTypeItem = validScopeTypeMap.find(typeStr);
    if (scopyTypeItem == validScopeTypeMap.end()) {
        std::cerr << "Error: Config field 'Scope.Type' has invalid value: " << typeStr << std::endl;
        SANDBOX_LOGE("Config field 'Scope.Type' has invalid value: %{public}s", typeStr.c_str());
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    scope.scope.type = scopyTypeItem->second;
    return SANDBOX_SUCCESS;
}

// Helper: parse the 'Network' policy field of an agentlock policy with default action policy
static int ParseNetworkField(cJSON *root, AgentLockPolicy &policy)
{
    cJSON *netRuleObj = cJSON_GetObjectItem(root, "Network");
    if (!cJSON_IsObject(netRuleObj)) {
        std::cerr << "Error: Config field 'Network' missing or not an object" << std::endl;
        SANDBOX_LOGE("Config field 'Network' missing or not an object");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    policy.operationType = OP_TYPE_NETWORK;
    policy.defaultAction = AGENT_LOCK_DEFAULT_NETWORK_ACTION;
    policy.rulesListCnt = 0;

    std::string actionStr;
    int ret = ParseStringFieldWithMaxLen(netRuleObj, "DefaultAction", actionStr, MAX_ACTION_STR_LENGTH);
    if (ret != SANDBOX_SUCCESS) {
        std::cerr << "Error: Failed to parse Network.DefaultAction field" << std::endl;
        SANDBOX_LOGE("Failed to parse Network.DefaultAction field");
        return ret;
    }
    auto actionItem = actionMap.find(actionStr);
    if (actionItem == actionMap.end()) {
        std::cerr << "Error: Config field 'Network.DefaultAction' has invalid value: " << actionStr << std::endl;
        SANDBOX_LOGE("Config field 'Network.DefaultAction' has invalid value: %{public}s", actionStr.c_str());
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    policy.defaultAction = actionItem->second;
    return SANDBOX_SUCCESS;
}

// Helper: parse the 'AddOperationControlRuleGroups' policy array and fill in the AgentLockPolicy structures
static int ParseAgentLockField(cJSON *root, struct AgentLockPolicy policy[])
{
    cJSON *ruleGroupObj = cJSON_GetObjectItem(root, "AddOperationControlRuleGroups");
    if (ruleGroupObj == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsArray(ruleGroupObj)) {
        std::cerr << "Error: Config field 'AddOperationControlRuleGroups' type mismatch: expected array" << std::endl;
        SANDBOX_LOGE("Config field 'AddOperationControlRuleGroups' type mismatch: expected array");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    int ret = SANDBOX_SUCCESS;
    uint32_t policyIndex = 0;
    int size = cJSON_GetArraySize(ruleGroupObj);
    for (int i = 0; i < size; i++) {
        cJSON *ruleGroupItem = cJSON_GetArrayItem(ruleGroupObj, i);
        if (!cJSON_IsObject(ruleGroupItem)) {
            std::cerr << "Error: Config field 'AddOperationControlRuleGroups' should contain objects" << std::endl;
            SANDBOX_LOGE("Config field 'AddOperationControlRuleGroups' should contain objects");
            return SANDBOX_ERR_CONFIG_INVALID;
        }
        if (cJSON_HasObjectItem(ruleGroupItem, "Network")) {
            ret = ParseScopeField(ruleGroupItem, policy[policyIndex]);
            if (ret != SANDBOX_SUCCESS) {
                std::cerr << "Error: Failed to parse Scope field for Network policy at index " <<
                          policyIndex << std::endl;
                SANDBOX_LOGE("Failed to parse Scope field for Network policy at index %{public}u", policyIndex);
                return ret;
            }
            ret = ParseNetworkField(ruleGroupItem, policy[policyIndex]);
            if (ret != SANDBOX_SUCCESS) {
                std::cerr << "Error: Failed to parse Network field for Network policy at index " <<
                          policyIndex << std::endl;
                SANDBOX_LOGE("Failed to parse Network field for Network policy at index %{public}u", policyIndex);
                return ret;
            }
            policyIndex++;
        }
    }
    return ret;
}

// Helper: parse the 'policy' field for agentlock and fill in the AgentLockAddPolicyArg structure
static int ParseAgentLockAddPolicyArg(cJSON *root, struct AgentLockAddPolicyArg* &policyArg)
{
    cJSON *policyArgObj = cJSON_GetObjectItem(root, "policy");
    if (policyArgObj == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsObject(policyArgObj)) {
        std::cerr << "Error: Config field 'policy' missing or not an object" << std::endl;
        SANDBOX_LOGE("Config field 'policy' missing or not an object");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    uint32_t policyNum = 0;
    int ret = ParseAgentLockPolicyNum(policyArgObj, policyNum);
    if (ret != SANDBOX_SUCCESS) {
        std::cerr << "Error: Failed to parse agentlock policy number" << std::endl;
        SANDBOX_LOGE("Failed to parse agentlock policy number");
        return ret;
    }
    size_t totalSize = sizeof(struct AgentLockAddPolicyArg) + policyNum * sizeof(struct AgentLockPolicy);
    if (totalSize < sizeof(struct AgentLockAddPolicyArg) || totalSize > MAX_MALLOC_SIZE) {
        std::cerr << "Error: Policy size overflow or exceeds limit" << std::endl;
        SANDBOX_LOGE("Policy size overflow or exceeds limit");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    policyArg = (struct AgentLockAddPolicyArg *)std::malloc(totalSize);
    if (policyArg == nullptr) {
        std::cerr << "Error: Failed to allocate memory for AgentLockAddPolicyArg" << std::endl;
        SANDBOX_LOGE("Failed to allocate memory for AgentLockAddPolicyArg");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    if (memset_s(policyArg, totalSize, 0, totalSize) != 0) {
        std::cerr << "Error: Failed to initialize memory for AgentLockAddPolicyArg" << std::endl;
        SANDBOX_LOGE("Failed to initialize memory for AgentLockAddPolicyArg");
        std::free(policyArg);
        policyArg = nullptr;
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    policyArg->policyCnt = policyNum;
    ret = ParseAgentLockField(policyArgObj, policyArg->policy);
    if (ret != SANDBOX_SUCCESS) {
        std::cerr << "Error: Failed to parse agentlock policy rules" << std::endl;
        SANDBOX_LOGE("Failed to parse agentlock policy rules");
        std::free(policyArg);
        policyArg = nullptr;
        return ret;
    }
    return SANDBOX_SUCCESS;
}

// Helper: parse optional hex name field (max 64 chars)
static int ParseNameField(cJSON *root, std::string &out)
{
    cJSON *item = cJSON_GetObjectItem(root, "name");
    if (item == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsString(item) || item->valuestring == nullptr) {
        std::cerr << "Error: Config field 'name' must be a string" << std::endl;
        SANDBOX_LOGE("Config field 'name' must be a string");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    std::string nameVal = item->valuestring;
    if (nameVal.length() > MAX_NAME_LENGTH) {
        std::cerr << "Error: Config field 'name' exceeds max length (" << MAX_NAME_LENGTH << ")" << std::endl;
        SANDBOX_LOGE("Config field 'name' exceeds max length (%{public}zu)", MAX_NAME_LENGTH);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    for (char c : nameVal) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            std::cerr << "Error: Config field 'name' must be a hex string" << std::endl;
            SANDBOX_LOGE("Config field 'name' must be a hex string");
            return SANDBOX_ERR_CONFIG_INVALID;
        }
    }
    out = nameVal;
    return SANDBOX_SUCCESS;
}

// Helper: parse optional env object
static int ParseEnvField(cJSON *root, std::map<std::string, std::string> &out)
{
    cJSON *item = nullptr;
    cJSON *parsedEnv = nullptr;
    int ret = GetOptionalObjectField(root, "env", item, parsedEnv, MAX_ENV_LENGTH);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    if (item == nullptr) {
        return SANDBOX_SUCCESS;
    }
    cJSON *envItem = nullptr;
    cJSON_ArrayForEach(envItem, item) {
        if (envItem == nullptr || envItem->string == nullptr ||
            !cJSON_IsString(envItem) || envItem->valuestring == nullptr) {
            std::cerr << "Error: Config field 'env' should contain string key-value pairs" << std::endl;
            SANDBOX_LOGE("Config field 'env' should contain string key-value pairs");
            return CleanupParsedObjectAndReturn(parsedEnv, SANDBOX_ERR_CONFIG_INVALID);
        }
        if (envItem->string[0] == '\0' || strchr(envItem->string, '=') != nullptr) {
            std::cerr << "Error: Config field 'env' key must not be empty or contain '='" << std::endl;
            SANDBOX_LOGE("Config field 'env' key must not be empty or contain '='");
            return CleanupParsedObjectAndReturn(parsedEnv, SANDBOX_ERR_CONFIG_INVALID);
        }
        out[envItem->string] = envItem->valuestring;
    }
    return CleanupParsedObjectAndReturn(parsedEnv, SANDBOX_SUCCESS);
}

static int ParsePolicyMountSource(cJSON *mountItem, SandboxConfig::PolicyMount &mount)
{
    cJSON *source = cJSON_GetObjectItem(mountItem, "source");
    if (!cJSON_IsString(source) || source->valuestring == nullptr) {
        std::cerr << "Error: Config field 'policy.mounts[].source' missing or not a string" << std::endl;
        SANDBOX_LOGE("Config field 'policy.mounts[].source' missing or not a string");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    std::string path = source->valuestring;
    if (path.empty() || path[0] != '/') {
        std::cerr << "Error: Config field 'policy.mounts[].source' contains invalid path" << std::endl;
        SANDBOX_LOGE("Config field 'policy.mounts[].source' contains invalid path");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    mount.source = path;
    return SANDBOX_SUCCESS;
}

static int ParsePolicyMountMode(cJSON *mountItem, SandboxConfig::PolicyMount &mount)
{
    cJSON *mode = cJSON_GetObjectItem(mountItem, "mode");
    if (!cJSON_IsString(mode) || mode->valuestring == nullptr) {
        std::cerr << "Error: Config field 'policy.mounts[].mode' missing or not a string" << std::endl;
        SANDBOX_LOGE("Config field 'policy.mounts[].mode' missing or not a string");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    if (strcmp(mode->valuestring, "ro") == 0) {
        mount.readOnly = true;
        return SANDBOX_SUCCESS;
    }
    if (strcmp(mode->valuestring, "rw") == 0) {
        mount.readOnly = false;
        return SANDBOX_SUCCESS;
    }
    std::cerr << "Error: Config field 'policy.mounts[].mode' must be 'ro' or 'rw'" << std::endl;
    SANDBOX_LOGE("Config field 'policy.mounts[].mode' must be 'ro' or 'rw'");
    return SANDBOX_ERR_CONFIG_INVALID;
}

static int ParsePolicyMountItem(cJSON *mountItem, SandboxConfig::Policy &out)
{
    if (!cJSON_IsObject(mountItem)) {
        std::cerr << "Error: Config field 'policy.mounts' should contain objects" << std::endl;
        SANDBOX_LOGE("Config field 'policy.mounts' should contain objects");
        return SANDBOX_ERR_CONFIG_INVALID;
    }

    SandboxConfig::PolicyMount mount;
    int ret = ParsePolicyMountSource(mountItem, mount);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    ret = ParsePolicyMountMode(mountItem, mount);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    out.mounts.push_back(mount);
    return SANDBOX_SUCCESS;
}

static int ParsePolicyMounts(cJSON *policy, SandboxConfig::Policy &out)
{
    cJSON *mounts = cJSON_GetObjectItem(policy, "mounts");
    if (mounts == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsArray(mounts)) {
        std::cerr << "Error: Config field 'policy.mounts' type mismatch: expected array" << std::endl;
        SANDBOX_LOGE("Config field 'policy.mounts' type mismatch: expected array");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    int size = cJSON_GetArraySize(mounts);
    for (int i = 0; i < size; i++) {
        int ret = ParsePolicyMountItem(cJSON_GetArrayItem(mounts, i), out);
        if (ret != SANDBOX_SUCCESS) {
            return ret;
        }
    }
    return SANDBOX_SUCCESS;
}

static int ParsePolicyField(cJSON *root, SandboxConfig::Policy &out)
{
    cJSON *item = nullptr;
    cJSON *parsedPolicy = nullptr;
    int ret = GetOptionalObjectField(root, "policy", item, parsedPolicy, MAX_POLICY_LENGTH);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    if (item == nullptr) {
        return SANDBOX_SUCCESS;
    }
    ret = ParsePolicyMounts(item, out);
    return CleanupParsedObjectAndReturn(parsedPolicy, ret);
}

// Helper: parse optional nsFlags string array and convert directly to bitmask
static int ParseNsFlagsField(cJSON *root, int &out)
{
    out = DEFAULT_NS_FLAGS;
    cJSON *item = cJSON_GetObjectItem(root, "nsFlags");
    if (item == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsArray(item)) {
        std::cerr << "Error: Config field 'nsFlags' type mismatch: expected array" << std::endl;
        SANDBOX_LOGE("Config field 'nsFlags' type mismatch: expected array");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    int size = cJSON_GetArraySize(item);
    if (static_cast<size_t>(size) > MAX_NS_FLAGS_COUNT) {
        std::cerr << "Error: nsFlags array size (" << size << ") exceeds max (" <<
                  MAX_NS_FLAGS_COUNT << ")" << std::endl;
        SANDBOX_LOGE("nsFlags array size (%{public}d) exceeds max (%{public}zu)",
            size, MAX_NS_FLAGS_COUNT);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    std::vector<std::string> flags;
    for (int i = 0; i < size; i++) {
        cJSON *flagItem = cJSON_GetArrayItem(item, i);
        if (!cJSON_IsString(flagItem) || flagItem->valuestring == nullptr) {
            std::cerr << "Error: nsFlags[" << i << "] should be string" << std::endl;
            SANDBOX_LOGE("nsFlags[%{public}d] should be string", i);
            return SANDBOX_ERR_CONFIG_INVALID;
        }
        std::string flagVal = flagItem->valuestring;
        if (flagVal.length() > MAX_NS_FLAG_STRING_LENGTH) {
            std::cerr << "Error: nsFlags[" << i << "] exceeds max length (" <<
                      MAX_NS_FLAG_STRING_LENGTH << ")" << std::endl;
            SANDBOX_LOGE("nsFlags[%{public}d] exceeds max length (%{public}zu)",
                i, MAX_NS_FLAG_STRING_LENGTH);
            return SANDBOX_ERR_CONFIG_INVALID;
        }
        flags.push_back(flagVal);
    }
    out = CmdParser::ConvertNsFlags(flags);
    return SANDBOX_SUCCESS;
}

int CmdParser::ParseConfig(const std::string &jsonStr, SandboxConfig &config)
{
    config = SandboxConfig();

    cJSON *root = cJSON_Parse(jsonStr.c_str());
    if (root == nullptr) {
        const char *p = cJSON_GetErrorPtr();
        std::cerr << "Error: Failed to parse config JSON: " <<
                  (p != nullptr ? p : "unknown") << std::endl;
        SANDBOX_LOGE("Failed to parse config JSON: %{public}s",
            p != nullptr ? p : "unknown");
        return SANDBOX_ERR_CONFIG_INVALID;
    }

    std::function<int()> parseSteps[] = {
        [&]() -> int { return ParseUint64Field(root, "callerTokenId", config.callerTokenId); },
        [&]() -> int { return ParseUint32Field(root, "callerPid", config.callerPid); },
        [&]() -> int { return ParseUint32Field(root, "uid", config.uid); },
        [&]() -> int { return ParseUint32Field(root, "gid", config.gid); },
        [&]() -> int {
            return ParseOptionalStringFieldWithMaxLen(root, "challenge", config.challenge, MAX_CHALLENGE_LENGTH);
        },
        [&]() -> int {
            return ParseStringFieldWithMaxLen(root, "appIdentifier", config.appIdentifier, MAX_APP_IDENTIFIER_LENGTH);
        },
        [&]() -> int {
            return ParseStringFieldWithMaxLen(root, "bundleName", config.bundleName, MAX_BUNDLE_NAME_LENGTH);
        },
        [&]() -> int {
            int ret = ParseTypeField(root, config.type);
            if (ret != SANDBOX_SUCCESS) {
                return ret;
            }
            if (config.type == "cli") {
                ret = ParseStringFieldWithMaxLen(root, "cliName", config.cliName, MAX_CLI_NAME_LENGTH);
                if (ret != SANDBOX_SUCCESS) {
                    return ret;
                }
                return ParseStringFieldWithMaxLen(root, "subCliName", config.subCliName, MAX_SUB_CLI_NAME_LENGTH);
            } else if (config.type == "shell") {
                config.cliName = "";
                config.subCliName = "";
                return SANDBOX_SUCCESS;
            } else {
                std::cerr << "Error: Config field 'type' must be 'cli' or 'shell'" << std::endl;
                SANDBOX_LOGE("Config field 'type' must be 'cli' or 'shell'");
                return SANDBOX_ERR_CONFIG_INVALID;
            }
        },
        [&]() -> int { return ParseNameField(root, config.name); },
        [&]() -> int {
            return ParseOptionalStringFieldWithMaxLen(root, "workdir", config.workdir, MAX_WORKDIR_LENGTH);
        },
        [&]() -> int { return ParseEnvField(root, config.env); },
        [&]() -> int { return ParsePolicyField(root, config.policy); },
        [&]() -> int { return ParseNsFlagsField(root, config.nsFlags); },
        [&]() -> int { return ParseAgentLockAddPolicyArg(root, config.policyArg); },
    };

    for (const auto& step : parseSteps) {
        int ret = step();
        if (ret != SANDBOX_SUCCESS) {
            return CleanupAndReturn(root, ret);
        }
    }

    cJSON_Delete(root);
    return SANDBOX_SUCCESS;
}

CmdInfo CmdParser::ParseCommandFromArgv(int argc, char *argv[])
{
    CmdInfo info;
    if (argc <= 0 || argv == nullptr) {
        return info;
    }

    for (int i = 0; i < argc; i++) {
        if (argv[i] != nullptr) {
            info.argv.push_back(argv[i]);
        }
    }

    SANDBOX_LOGD("CmdParser: argv array - parsed to %{public}zu args", info.argv.size());
    return info;
}

int CmdParser::ConvertNsFlags(const std::vector<std::string> &nsFlags)
{
    int flags = DEFAULT_NS_FLAGS;
    for (const auto &flag : nsFlags) {
        if (flag == "mnt") {
            flags |= CLONE_NEWNS;
        } else if (flag == "net") {
            flags |= CLONE_NEWNET;
        } else if (flag == "uts") {
            flags |= CLONE_NEWUTS;
        } else if (flag == "ipc") {
            flags |= CLONE_NEWIPC;
        } else if (flag == "pid") {
            flags |= CLONE_NEWPID;
        } else if (flag == "user") {
            flags |= CLONE_NEWUSER;
        }
    }

    return flags;
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
