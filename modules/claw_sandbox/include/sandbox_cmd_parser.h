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

#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include <sys/types.h>

#include "accesstoken_kit.h"
#ifdef CONFIG_SHELL_SANDBOX
#include "sandbox_op_control_policy.h"
#include "sandbox_policy_result.h"
#endif

struct cJSON;

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

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
#ifdef CONFIG_SHELL_SANDBOX
        std::vector<SandboxPolicyRuleGroup> addOperationControlRuleGroups;
#endif
    };

    uint64_t callerTokenId = 0;
    pid_t callerPid = 0;
    uint32_t uid = 0;
    uint32_t gid = 0;
    std::string challenge;
    std::string appIdentifier;             // App identifier (must parse as a u64)
    uint64_t appIdentifierU64 = 0;         // Numeric form of appIdentifier; set by ParseConfig
    std::string bundleName;                // Bundle name for <PackageName> substitution
    std::string currentUserId;             // Current user ID for <currentUserId> substitution
    std::string name;                      // Optional hex sandbox name (max 64 chars)
    std::string workdir;                   // Optional working directory (max 1024 chars)
    std::map<std::string, std::string> env; // Optional environment variables
    Policy policy;                         // Optional path access policy
    /*
     * Optional namespace flags, e.g. CLONE_NEWNET | CLONE_NEWPID. Unsigned
     * because it is a bitmask: with the accumulator unsigned, the usual
     * arithmetic conversions make every |= and & on it an unsigned operation,
     * even though the CLONE_* macros are signed ints.
     */
    uint32_t nsFlags = 0;
    std::string type;                      // CLI type. Valid values: "shell" or "cli" (default: "cli").
    std::string cliName;                   // CLI name (required)
    std::string subCliName;                // Sub-CLI name (required)
    OHOS::Security::AccessToken::AccessTokenIDEx tokenIdEx;             // Temporary tokenId
    std::vector<OHOS::Security::AccessToken::PermissionWithValue> kernelPermList;  // Kernel Permission List
};

/**
 * @brief Parsed command info from --cmd argument
 */
struct CmdInfo {
    std::vector<std::string> argv;         // Argument vector
};

#ifdef CONFIG_SHELL_SANDBOX
/**
 * @brief Parse phase of an AddOperationControlRuleGroups document. STARTUP = the
 *        sandbox boot-time profile (parsed from the sandbox's own --config);
 *        DYNAMIC = a policy delivered to an already-running sandbox later. Both
 *        phases share one JSON schema but may admit different module sets; the
 *        divergence lives in EnforcePhaseRules (sandbox_op_control_parser.cpp).
 */
enum SandboxPolicyParsePhase : uint8_t {
    SANDBOX_POLICY_PARSE_STARTUP = 0,  // boot-time profile, full module set
    SANDBOX_POLICY_PARSE_DYNAMIC,      // incremental delivery to a running sandbox
};
#endif

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
     * @brief Convert namespace flag strings to a CLONE_XXX bitmask.
     *        An unrecognised name is rejected rather than skipped: a caller that
     *        misspells "net" is asking for an isolation it would not get, and
     *        silently handing back a weaker sandbox than the config describes is
     *        the wrong way to fail.
     * @param nsFlags String array, e.g. ["net", "pid"]
     * @param flags Output combined CLONE_XXX flags (CLONE_NEWNS always included);
     *        untouched unless SANDBOX_SUCCESS is returned
     * @return SANDBOX_SUCCESS on success, SANDBOX_ERR_CONFIG_INVALID on an
     *         unknown namespace name
     */
    static int ConvertNsFlags(const std::vector<std::string> &nsFlags, uint32_t &flags);

#ifdef CONFIG_SHELL_SANDBOX
    /**
     * @brief Parse the AddOperationControlRuleGroups array of the "policy" object
     *        into the rule-group model. Defined in sandbox_op_control_parser.cpp;
     *        the config parser (ParsePolicyField, sandbox_cmd_parser.cpp) calls
     *        into the split op-control parser TU through this entry. The array may
     *        hold several groups, each with its own Scope.Type; a group repeating an
     *        earlier group's Scope.Type is rejected (self_session is the only type
     *        allowed today, so the list is effectively capped at one group).
     * @param policyObj cJSON object node holding the AddOperationControlRuleGroups array
     * @param ruleGroups Output parsed rule groups
     * @param phase Parse phase (SANDBOX_POLICY_PARSE_STARTUP / _DYNAMIC). The two
     *        phases share the schema but may admit different module sets: a DYNAMIC
     *        policy must not carry a Network module (the network default is fixed at
     *        sandbox start). Callers must state the phase explicitly; the boot-time
     *        config path passes SANDBOX_POLICY_PARSE_STARTUP.
     * @return SANDBOX_SUCCESS on success, SANDBOX_ERR_CONFIG_INVALID on invalid data
     */
    static int ParseOperationControlRuleGroups(cJSON *policyObj,
        std::vector<SandboxPolicyRuleGroup> &ruleGroups,
        SandboxPolicyParsePhase phase);

    /**
     * @brief Parse an AddOperationControlRuleGroups policy JSON object handed in
     *        as a string, the form the monitor socket delivers it in. Parsed as
     *        SANDBOX_POLICY_PARSE_DYNAMIC: the sandbox is already running.
     * @param jsonStr JSON object containing AddOperationControlRuleGroups
     * @param ruleGroups Output operation-control rule groups
     * @return SANDBOX_SUCCESS on success, SANDBOX_ERR_CONFIG_INVALID on invalid data
     */
    static int ParseOperationControlPolicy(const std::string &jsonStr,
        std::vector<SandboxPolicyRuleGroup> &ruleGroups);

    /**
     * @brief Convert every rule group of one module type into its own policy in
     *        the TLV carrier class. Each group that carries the module appends
     *        one independent policy -- groups are never merged and no cross-group
     *        conflict detection runs; intra-group conflicts still error. To
     *        convert a single group, pass a one-element vector (as the delivery
     *        path does per (group, module)); tlv.policies then holds at most one
     *        entry (policy_cnt is implicitly 1). operation_type identifies the
     *        module on every appended policy.
     * @param ruleGroups Parsed AddOperationControlRuleGroups
     * @param moduleType Module to convert: DEC_POLICY_OP_TYPE_NETWORK/FILE/PROCESS
     * @param tlv Output TLV carrier (one policy appended per carrying group)
     * @param errors Optional: every conflict found is appended here. The return
     *        value is the same whether or not it is given.
     * @return SANDBOX_SUCCESS on success, SANDBOX_ERR_CONFIG_INVALID on invalid data
     */
    static int ConvertOperationControlToTlv(
        const std::vector<SandboxPolicyRuleGroup> &ruleGroups,
        DEC_POLICY_OP_TYPE moduleType,
        SandboxPolicyTlv &tlv,
        std::vector<PolicyError> *errors = nullptr);

    /**
     * @brief Build a SandboxPolicyArg from the TLV carrier: serialize the class
     *        into TLV bytes and copy them into data. module_id is left zeroed here
     *        and set by the caller right before each ioctl.
     * @param tlv TLV carrier holding all policies
     * @param context Output buffer (caller frees with std::free)
     * @return SANDBOX_SUCCESS on success, error code on failure
     */
    static int BuildAlPolicyContext(const SandboxPolicyTlv &tlv,
        struct SandboxPolicyArg *&context);
#endif
};

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS

#endif // CLAW_SANDBOX_SANDBOX_CMD_PARSER_H
