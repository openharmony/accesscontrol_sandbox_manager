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

#ifndef CLAW_SANDBOX_SANDBOX_CMD_PARSER_H
#define CLAW_SANDBOX_SANDBOX_CMD_PARSER_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include <unordered_map>

#include "accesstoken_kit.h"


namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

/**
 * @brief Max value limits for agentlock parameters
 */
constexpr size_t ACTION_TYPE_CNT               = 4;
constexpr size_t AGENT_LOCK_MAX_RULES_LIST_CNT = 16;
constexpr size_t AGENT_LOCK_MAX_ITEM_CNT       = 8;
constexpr size_t MAX_VAL_LEN                   = 512;

/*
 * @brief Operation types for agentlock
 */
enum OP_TYPE : int {
    OP_TYPE_NETWORK = 0,
    OP_TYPE_FILE,
    OP_TYPE_EXEC
};
static const std::vector<std::string> fieldTypes = {"Network", "File", "Exec"};

/**
 * @brief AgentLock policy actions
 */
enum AGENT_LOCK_POLICY_ACTION : int {
    AL_POLICY_ACTION_ALLOW = 0,
    AL_POLICY_ACTION_DENY,
    AL_POLICY_ACTION_ASK,
    AL_POLICY_ACTION_NR
};
static const std::unordered_map<std::string, AGENT_LOCK_POLICY_ACTION> actionMap = {
    {"allow", AL_POLICY_ACTION_ALLOW},
    {"deny", AL_POLICY_ACTION_DENY}
};
constexpr enum AGENT_LOCK_POLICY_ACTION AGENT_LOCK_DEFAULT_NETWORK_ACTION = AL_POLICY_ACTION_ALLOW;

/**
 * @brief AgentLock filter tags
 */
enum AGENT_LOCK_FILTER_TAG : int {
    AL_FILTER_TAG_NULL = 0,
    AL_FILTER_TAG_PID,
    AL_FILTER_TAG_UID,
    AL_FILTER_TAG_GID,
    AL_FILTER_TAG_PATH,
    AL_FILTER_TAG_NR
};

/**
 * @brief AgentLock filter comparison rules
 */
enum AGENT_LOCK_FILTER_RULE : int {
    AL_FILTER_RULE_EQ = 0,
    AL_FILTER_RULE_NE,
    AL_FILTER_RULE_PREFIX,
    AL_FILTER_RULE_SUFFIX,
    AL_FILTER_RULE_NR
};

/**
 * @brief AgentLock filter types
 */
enum AGENT_LOCK_FILTER_TYPE : int {
    AL_FILTER_TYPE_STR = 0,
    AL_FILTER_TYPE_UINT64,
    AL_FILTER_TYPE_NR
};

/**
 * @brief Event types for agentlock
 */
enum EVENT_TYPE : int {
    EVENT_TYPE_READ = 0,
    EVENT_TYPE_WRITE,
    EVENT_TYPE_MAX
};

/**
 * @brief Scope types for agentlock
 */
enum SCOPE_TYPE : int {
    SCOPE_TYPE_GLOBAL = 0,
    SCOPE_TYPE_SPECIFIC_APP,
    SCOPE_TYPE_SPECIFIC_TASK,
    SCOPE_TYPE_CURRENT_TASK
};
static const std::unordered_map<std::string, SCOPE_TYPE> validScopeTypeMap = {
    {"current_task", SCOPE_TYPE_CURRENT_TASK}
};

/**
 * @brief Filter rule structure for agentlock
 */
struct AgentLockFilterRule {
    enum AGENT_LOCK_FILTER_TAG tag1;
    enum AGENT_LOCK_FILTER_TAG tag2;
    enum AGENT_LOCK_FILTER_RULE cmpRule;
    enum AGENT_LOCK_FILTER_TYPE type;
    uint32_t valSize1;
    uint8_t val1[MAX_VAL_LEN];
    uint32_t valSize2;
    uint8_t val2[MAX_VAL_LEN];
};

/**
 * @brief Rules list item structure for agentlock
 */
struct AgentLockRulesListItem {
    enum AGENT_LOCK_POLICY_ACTION action;
    enum EVENT_TYPE eventType;
    uint32_t subjectRuleCnt;
    uint32_t objectRuleCnt;
    struct AgentLockFilterRule subjectRules[AGENT_LOCK_MAX_ITEM_CNT];
    struct AgentLockFilterRule objectRules[AGENT_LOCK_MAX_ITEM_CNT];
};

/**
 * @brief Scope structure for agentlock, which specifies the scope of a policy
 */
struct Scope {
    enum SCOPE_TYPE type;
    uint64_t appid;
    uint64_t taskid;
};

/**
 * @brief AgentLock policy structure
 */
struct AgentLockPolicy {
    enum OP_TYPE operationType;
    Scope scope;
    enum AGENT_LOCK_POLICY_ACTION defaultAction;
    uint32_t actionPriorityInRelativeRules[ACTION_TYPE_CNT];
    uint32_t rulesListCnt;
    struct AgentLockRulesListItem rulesList[AGENT_LOCK_MAX_RULES_LIST_CNT];
};

/**
 * @brief AgentLock add policy argument structure
 */
struct AgentLockAddPolicyArg {
    uint32_t version;
    uint32_t policyCnt;
    struct AgentLockPolicy policy[];
};
/**
 * @brief  DecConfig is used to pass data or a scalar value to the kernel, used for agentlock init
*/
struct DecConfig {
    union {
        void *data;
        uint64_t value;
    };
    size_t size;
};

/**
 * @brief Sandbox configuration parsed from --config JSON
 */
struct SandboxConfig {
    struct PolicyMount {
        std::string source;
        bool readOnly = true;
    };

    struct Policy {
        std::vector<PolicyMount> mounts;
    };

    uint64_t callerTokenId = 0;
    uint32_t callerPid = 0;
    uint32_t uid = 0;
    uint32_t gid = 0;
    std::string challenge;
    std::string appIdentifier;
    std::string bundleName;                // Bundle name for <PackageName> substitution
    std::string currentUserId;             // Current user ID for <currentUserId> substitution
    std::string name;                      // Optional hex sandbox name (max 64 chars)
    std::string workdir;                   // Optional working directory (max 1024 chars)
    std::map<std::string, std::string> env; // Optional environment variables
    Policy policy;                         // Optional path access policy
    int nsFlags = 0;                       // Optional namespace flags (bitmask), e.g. CLONE_NEWNET | CLONE_NEWPID
    std::string type;                      // CLI type. Valid values: "shell" or "cli" (default: "cli").
    std::string cliName;                   // CLI name (required)
    std::string subCliName;                // Sub-CLI name (required)
    OHOS::Security::AccessToken::AccessTokenIDEx tokenIdEx;             // Temporary tokenId
    std::vector<OHOS::Security::AccessToken::PermissionWithValue> kernelPermList;  // Kernel Permission List
    struct AgentLockAddPolicyArg *policyArg = nullptr; // AgentLock policy argument
};

/**
 * @brief Parsed command info from --cmd argument
 */
struct CmdInfo {
    std::vector<std::string> argv;         // Argument vector
};

/**
 * @brief Command line argument parser
 */
class CmdParser {
public:
    /**
     * @brief Parse --config JSON string into SandboxConfig
     * @param jsonStr JSON string
     * @param config Output config struct
     * @return SANDBOX_SUCCESS on success, SANDBOX_ERR_CONFIG_INVALID on failure
     */
    static int ParseConfig(const std::string &jsonStr, SandboxConfig &config);

    /**
     * @brief Build CmdInfo from an argv array (--cmd <argv> array form)
     * @param argc Number of remaining arguments after --cmd
     * @param argv Pointer to the first argument after --cmd
     * @return Parsed CmdInfo with argv set from the array
     */
    static CmdInfo ParseCommandFromArgv(int argc, char *argv[]);

    /**
     * @brief Convert namespace flag strings to CLONE_XXX bitmask
     * @param nsFlags String array, e.g. ["net", "pid"]
     * @return Combined CLONE_XXX flags (CLONE_NEWNS is always included)
     */
    static int ConvertNsFlags(const std::vector<std::string> &nsFlags);
};

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS

#endif // CLAW_SANDBOX_SANDBOX_CMD_PARSER_H
