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

#ifndef CLAW_SANDBOX_SANDBOX_OP_CONTROL_POLICY_H
#define CLAW_SANDBOX_SANDBOX_OP_CONTROL_POLICY_H

/*
 * Operation-control (op control) dynamic policy (AddOperationControlRuleGroups)
 * -> TLV world. This header was renamed from sandbox_policy.h to
 * sandbox_op_control_policy.h to reflect that it carries only op-control types.
 *
 * Organized by functional layer, top to bottom:
 *   [1] TLV wire enums    - wire-ABI values mirrored 1:1 from kernel.
 *   [2] JSON config model - parse-time mirror of AddOperationControlRuleGroups[].
 *   [3] TLV model + ...   - SandboxPolicyScopeBody / SandboxPolicyTlv, the class
 *                            Serialize() turns into TLV bytes for the kernel.
 *   [4] ioctl ABI structs - SandboxPolicyArg carrier and related fixed headers.
 *
 * This header mirrors the kernel ABI copied into kernel_struct.h. kernel_struct.h
 * is a pure reference (never #include'd by any code); the numeric values in the
 * enums below are the wire contract and MUST track kernel_struct.h 1:1. The
 * kernel enum members use lowercase dec_ prefixes (dec_action, dec_scope_type,
 * ...); userspace names them with the uppercase DEC_POLICY_ prefix. Keep the two
 * files in sync by hand when either side changes.
 */

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

#include "sandbox_policy_result.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

/* ============================================================================
 * [1] TLV wire enums
 *     Wire-ABI values mirrored 1:1 from the kernel enums
 *     (dec_policy_tlv_tag / dec_action / dec_scope_type / dec_op_type /
 *     dec_filter_tag / dec_filter_rule_type / dec_file_event_type /
 *     dec_process_event_type). Referenced as field types by [2] and [3].
 * ============================================================================
 */

/**
 * @brief TLV segment tags for the policy payload delivered in SandboxPolicyArg.data.
 *        Mirrors kernel enum dec_policy_tlv_tag (kernel_struct.h). Tags are numbered
 *        contiguously. [1]scope sits at the top, then [2]policy_cnt. The legacy
 *        scope_size prefix, subject/object_item_cnt tags and a separate item_size
 *        tag are not emitted anymore: every subject/object entity carries exactly
 *        one filter rule, so the entity_cnt field equals the number of filter-rule
 *        blocks that follow, and the item TLV's length header carries the item
 *        payload size. Each *_cnt field is a loop-expansion point: the following
 *        fields repeat the count value times.
 */
enum DEC_POLICY_TLV_TAG : uint32_t {
    DEC_POLICY_TLV_SCOPE = 1,
    DEC_POLICY_TLV_POLICY_CNT = 2,
    DEC_POLICY_TLV_OPERATION_SIZE = 3,
    DEC_POLICY_TLV_OPERATION_TYPE = 4,
    DEC_POLICY_TLV_DEFAULT_ACTION = 5,
    DEC_POLICY_TLV_ASK_TIMEOUT_DEFAULT_ACTION = 6,
    DEC_POLICY_TLV_RULESLIST_CNT = 7,
    DEC_POLICY_TLV_RULE_ACTION = 8,
    DEC_POLICY_TLV_RULE_EVENT_TYPE = 9,
    DEC_POLICY_TLV_FILTER_RULE_SUBJECT_CNT = 10,
    DEC_POLICY_TLV_FILTER_RULE_CMP_TYPE = 11,
    DEC_POLICY_TLV_FILTER_RULE_ITEM_TYPE = 12,
    DEC_POLICY_TLV_FILTER_RULE_ITEM = 13,
    DEC_POLICY_TLV_FILTER_RULE_OBJECT_CNT = 14,
};

/**
 * @brief Rule / default actions. Mirrors kernel enum dec_action (kernel_struct.h):
 *        read from TLV [5]DEFAULT_ACTION and [8]RULE_ACTION. _NONE means the
 *        DefaultAction was not configured.
 */
enum DEC_POLICY_ACTION : uint32_t {
    DEC_POLICY_ACTION_ALLOW = 0,
    DEC_POLICY_ACTION_DENY,
    DEC_POLICY_ACTION_ASK,
    DEC_POLICY_ACTION_NONE,  // default action not configured (missing DefaultAction)
};

/**
 * @brief Scope types. Mirrors kernel enum dec_scope_type (kernel_struct.h), value
 *        range 0..6.
 */
enum DEC_POLICY_SCOPE_TYPE : int {
    DEC_POLICY_SCOPE_TYPE_GLOBAL = 0,
    DEC_POLICY_SCOPE_TYPE_SPECIFIC_USER = 1,
    DEC_POLICY_SCOPE_TYPE_SPECIFIC_APP = 2,
    DEC_POLICY_SCOPE_TYPE_SELF_APP = 3,
    DEC_POLICY_SCOPE_TYPE_SPECIFIC_TASK = 4,
    DEC_POLICY_SCOPE_TYPE_SELF_TASK = 5,
    DEC_POLICY_SCOPE_TYPE_SELF_SESSION = 6,
};

/**
 * @brief Operation types, carried by TLV [4]OPERATION_TYPE and by the ioctl
 *        SandboxPolicyArg.module_id. Mirrors kernel enum dec_op_type
 *        (kernel_struct.h); _NR is the kernel's count sentinel.
 */
enum DEC_POLICY_OP_TYPE : uint32_t {
    DEC_POLICY_OP_TYPE_NETWORK = 0,
    DEC_POLICY_OP_TYPE_FILE,
    DEC_POLICY_OP_TYPE_PROCESS,
    DEC_POLICY_OP_TYPE_NR,
};

/**
 * @brief Filter rule item tags, carried by TLV [12]FILTER_RULE_ITEM_TYPE per item.
 *        Mirrors kernel enum dec_filter_tag (kernel_struct.h): an item is either
 *        FD (numeric fd value) or PATH/CMD (string value); userspace splits fd and
 *        path into separate flat entities. _NR is the kernel's count sentinel.
 */
enum DEC_POLICY_ITEM_TYPE : uint32_t {
    DEC_POLICY_ITEM_TYPE_NULL = 0,
    DEC_POLICY_ITEM_TYPE_PATH,
    DEC_POLICY_ITEM_TYPE_CMD,
    DEC_POLICY_ITEM_TYPE_FD,
    DEC_POLICY_ITEM_TYPE_NR,
};

/**
 * @brief Filter rule comparison operators, carried by TLV [11]FILTER_RULE_CMP_TYPE.
 *        Mirrors kernel enum dec_filter_rule_type (kernel_struct.h). The legacy
 *        STR_/UINT_ value-type variants are gone: the value type is derived by the
 *        kernel from the item tag. Only EQ is supported this version:
 *        AppendFilterRuleBlock rejects any other cmpType (incl. the _NR sentinel).
 */
enum DEC_POLICY_CMP_TYPE : uint32_t {
    DEC_POLICY_CMP_EQ = 0,
    DEC_POLICY_CMP_NE,
    DEC_POLICY_CMP_PREFIX,
    DEC_POLICY_CMP_SUFFIX,
    DEC_POLICY_CMP_NR, /* count sentinel */
};

/**
 * @brief File event bit flags for a file policy, carried OR-combined by TLV
 *        [9]RULE_EVENT_TYPE. Mirrors kernel enum dec_file_event_type
 *        (kernel_struct.h). The former EVENT_TYPE_MAX sentinel is dropped.
 */
enum DEC_POLICY_FILE_EVENT : uint32_t {
    DEC_POLICY_FILE_EVENT_OPEN_READ = 0x1,
    DEC_POLICY_FILE_EVENT_OPEN_WRITE = 0x2,
    DEC_POLICY_FILE_EVENT_STAT = 0x4,
    DEC_POLICY_FILE_EVENT_CREATE = 0x8,
    DEC_POLICY_FILE_EVENT_LINK = 0x10,
    DEC_POLICY_FILE_EVENT_RENAME = 0x20,
    DEC_POLICY_FILE_EVENT_MKDIR = 0x40,
    DEC_POLICY_FILE_EVENT_UNLINK = 0x80,
    DEC_POLICY_FILE_EVENT_RMDIR = 0x100,
};

/**
 * @brief Process event bit flags, carried by TLV [9]RULE_EVENT_TYPE. Mirrors
 *        kernel enum dec_process_event_type (kernel_struct.h): a Process exec cmd
 *        rule carries this event.
 */
enum DEC_POLICY_PROCESS_EVENT : uint32_t {
    DEC_POLICY_PROCESS_EVENT_EXEC = 0x1,
};

/* ============================================================================
 * [2] JSON config model (parse-time)
 *     Mirror of the AddOperationControlRuleGroups[] JSON array: per-action
 *     string vectors plus presence flags. CmdParser fills these while parsing
 *     --config; ConvertOperationControlToTlv() then flattens them into the
 *     SandboxPolicyTlv model in [3].
 * ============================================================================
 */

/**
 * @brief Scope of a rule group (AddOperationControlRuleGroups[].Scope).
 *        This version recognizes only Type and requires "self_session"; the
 *        per-group ids (priority/appId/taskId) are not parsed yet.
 */
struct SandboxPolicyScope {
    // The parser always overwrites this from the config; the default keeps a
    // default-constructed (non-config) scope on the only value accepted this
    // version so a caller never reads an uninitialized type.
    DEC_POLICY_SCOPE_TYPE type = DEC_POLICY_SCOPE_TYPE_SELF_SESSION;
};

/**
 * @brief Network operation control rules (AddOperationControlRuleGroups[].Network).
 */
struct SandboxPolicyNetworkConfig {
    // DefaultAction is REQUIRED when a Network object is configured; the parser admits
    // only "deny"/"allow". NONE remains the model default for direct construction only.
    DEC_POLICY_ACTION defaultAction = DEC_POLICY_ACTION_NONE;
};

/**
 * @brief File operation control rules (AddOperationControlRuleGroups[].File).
 *        This version only supports Delete (rmdir/unlink) rules.
 */
struct SandboxPolicyFileConfig {
    // Optional DefaultAction (NONE when not configured). Default action applied
    // when no rule matches; explicit per-rule actions always win.
    DEC_POLICY_ACTION defaultAction = DEC_POLICY_ACTION_NONE;
    std::vector<std::string> denyDelete;
    std::vector<std::string> allowDelete;
    std::vector<std::string> askDelete;
};

/**
 * @brief Process operation control rules (AddOperationControlRuleGroups[].Process).
 */
struct SandboxPolicyProcessConfig {
    // Optional DefaultAction (NONE when not configured).
    DEC_POLICY_ACTION defaultAction = DEC_POLICY_ACTION_NONE;
    std::vector<std::string> denyExecCmd;
    std::vector<std::string> allowExecCmd;
    std::vector<std::string> askExecCmd;
};

/**
 * @brief A single rule group in the AddOperationControlRuleGroups array.
 */
struct SandboxPolicyRuleGroup {
    struct SandboxPolicyScope scope;
    bool hasNetwork = false;
    struct SandboxPolicyNetworkConfig networkRules;
    bool hasFile = false;
    struct SandboxPolicyFileConfig fileRules;
    bool hasProcess = false;
    struct SandboxPolicyProcessConfig processRules;
};

/* ============================================================================
 * [3] TLV model + serializer
 *     Kernel-facing policy shape. SandboxPolicyScopeBody is the body packed
 *     behind TLV tag [1]scope; SandboxPolicyTlv::Serialize() turns the class
 *     into the TLV bytes that SandboxPolicyArg.data[] carries (see [4]).
 * ============================================================================
 */

/**
 * @brief Scope body carried by TLV [1]scope. Field order/types mirror the kernel
 *        dec_scope_t body behind `type` (scope_id + scope_userid + u64 appidentifier
 *        + u64 taskid, i.e. DEC_SCOPE_BODY_SIZE=24 compact bytes, no padding).
 *        Serialized little-endian in exactly that order.
 *        The scope type is NOT part of this body: the kernel scope type is fixed
 *        and userspace delivers it via DEC_CMD_POLICY_CONFIG_SET
 *        (SandboxPolicySetArg.scope, wired from the parsed config's scope type).
 *        The four id fields below are not parsed this version and stay 0. Keep
 *        this stub byte-identical on the wire.
 */
struct SandboxPolicyScopeBody {
    uint32_t scope_id;
    uint32_t scope_userid;
    uint64_t scope_appidentifier;
    uint64_t scope_taskid;
};

/**
 * @brief Structured carrier for File/Process/Network dynamic policy, serializable
 *        to the TLV array stored in SandboxPolicyArg.data. Nested Policy/Rule/
 *        FilterRule correspond to kernel dec_policy/dec_rules_list_item/dec_filter_rule
 *        (kernel_struct.h).
 */
class SandboxPolicyTlv {
public:
    /**
     * @brief Single filter rule. On the wire a PATH rule is expanded into two
     *        single-rule entities: an FD entity (item = the open fd) followed by
     *        a PATH entity (item = path_str). A CMD rule stays a single entity
     *        (item = cmd_str). The subject/object_item_cnt tags are not emitted;
     *        entity_cnt equals the number of filter-rule blocks that follow.
     */
    struct FilterRule {
        uint32_t cmpType = DEC_POLICY_CMP_NR;
        uint32_t itemType = DEC_POLICY_ITEM_TYPE_NR;
        int fd = -1;  // open() fd of a PATH rule, kept valid through the delivery ioctl
        std::string path;  // PATH item value
        std::string cmd;   // CMD item value
    };

    /**
     * @brief One agent policy rule.
     * subjectRules/objectRules are "entity groups -> filter rules". The
     * subject/object_item_cnt tags are not emitted, so every filter rule is
     * serialized as its own single-rule subject/object entity under entity_cnt;
     * producers today put exactly one filter rule per inner vector.
     */
    struct Rule {
        uint32_t action = DEC_POLICY_ACTION_ALLOW;
        uint32_t eventType = 0;   // OR-combined DEC_POLICY_FILE_EVENT bits
        std::vector<std::vector<FilterRule>> subjectRules;
        std::vector<std::vector<FilterRule>> objectRules;
    };

    /**
     * @brief One agent policy (per operation).
     */
    struct Policy {
        uint32_t operationType = DEC_POLICY_OP_TYPE_FILE;
        uint32_t defaultAction = DEC_POLICY_ACTION_NONE;    // NONE when DefaultAction not configured
        uint32_t askTimeoutDefaultAction = DEC_POLICY_ACTION_DENY; // ask timeout fallback action
        std::vector<Rule> rules;
    };

    uint32_t version = 1;

    // TLV tag [1]scope body, packed little-endian. The scope type is delivered to
    // the kernel via DEC_CMD_POLICY_CONFIG_SET (SandboxPolicySetArg.scope), not
    // through this body; the four id fields are not parsed this version and stay 0.
    // Keeping the body as a class member lets Serialize() emit the complete TLV
    // (scope included) from class state.
    SandboxPolicyScopeBody scope = {0, 0, 0, 0};

    std::vector<Policy> policies;

    /**
     * @brief Serialize the class into a TLV byte array.
     * @param out Output TLV bytes (appended)
     * @return SANDBOX_SUCCESS on success, error code on failure
     */
    int Serialize(std::vector<uint8_t> &out) const;

    /**
     * @brief Open the path of every PATH filter rule so the kernel can identify
     *        the file by fd during the delivery ioctl. Every PATH rule opens
     *        with O_PATH|O_NOFOLLOW, so a symlink is opened as the symlink
     *        itself (a legal rule target) -- no O_RDONLY-to-O_PATH retry. A
     *        genuine open failure (missing file, permissions, ...) is fatal and
     *        reported as an error rather than falling back to the path string,
     *        but every rule is still attempted so the caller hears about all of
     *        them. No-op for CMD rules. Pair with CloseFileFds() after the
     *        ioctl; also call it on error to release the fds that did open.
     * @param errors Optional: every path that failed, with its errno text, is
     *        appended here, so a caller that answers someone else can name all
     *        of them at once.
     * @return SANDBOX_SUCCESS on success, SANDBOX_ERR_PATH_INVALID on open failure
     */
    int OpenFileFds(std::vector<PolicyError> *errors = nullptr);

    /**
     * @brief Close every fd opened by OpenFileFds(). Fds never opened (still
     *        holding the -1 "not open" sentinel) are skipped. Each closed fd is
     *        re-marked to the -1 "not open" sentinel, so calling CloseFileFds()
     *        again is a safe no-op.
     */
    void CloseFileFds();
};

/* ============================================================================
 * [4] ioctl ABI structs (kernel-facing carriers)
 *     Byte layouts mirror the kernel struct copies in kernel_struct.h; their
 *     sizeof drives the _IOWR ioctl numbers. SandboxPolicyArg.data[] holds the
 *     serialized TLV bytes produced by [3].
 * ============================================================================
 */

/**
 * @brief Kernel-facing policy carrier. Byte-for-byte mirrors kernel struct
 *        dec_add_policy_arg (kernel_struct.h): version/size/module_id +
 *        reserved[20] fixed header, then a data[] TLV array. Keep in sync with the
 *        kernel copy; never include kernel_struct.h in the same translation unit.
 *        module_id targets the module: DEC_POLICY_OP_TYPE_NETWORK/FILE/PROCESS.
 */
struct SandboxPolicyArg {
    uint32_t version;        // [IN] default 1
    uint32_t size;           // [IN] size of data[] TLV bytes
    uint32_t module_id;      // [IN] target module: DEC_POLICY_OP_TYPE_*
    uint8_t reserved[20];
    uint8_t data[];          // TLV structure
};

/**
 * @brief DEC_CMD_POLICY_CONFIG_SET fixed header. Mirrors kernel struct
 *        dec_policy_config_set_arg (kernel_struct.h): config_id selects the
 *        sub-command, config_args[] carries the sub-command payload (a
 *        SandboxPolicySetArg). Shared between the fs-side ioctl ABI and the
 *        verify-kernel dispatch.
 */
struct SandboxPolicyConfigSetArg {
    uint32_t config_id;       // [IN] enum dec_config_id (0 = set/set-get payload)
    uint32_t config_args_size;
    uint8_t config_args[];    // SandboxPolicySetArg
};

/**
 * @brief DEC_CMD_POLICY_CONFIG_SET payload behind the fixed SandboxPolicyConfigSetArg
 *        header. Mirrors kernel struct dec_policy_set_set_arg (kernel_struct.h);
 *        fixed size, the config set business only consumes one such set-arg.
 */
struct SandboxPolicySetArg {
    uint32_t scope; // [IN]
    uint8_t reserved[28];
};

/**
 * @brief DEC client init argument, used as the _IOWR size placeholder of
 *        DEC_CMD_AGENTLOCK_CURR_EXECUTER_INIT (issued with a NULL argument, so
 *        only sizeof matters). Mirrors kernel struct dec_client_init_arg
 *        (kernel_struct.h): size == 0 means config.value is a direct value,
 *        size != 0 means config.data is a pointer. Keep 16-byte sizeof in sync
 *        with the kernel copy.
 */
struct DecClientInitArg {
    union {
        void *data;
        uint64_t value;
    };
    size_t size;
};

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS

#endif // CLAW_SANDBOX_SANDBOX_OP_CONTROL_POLICY_H
