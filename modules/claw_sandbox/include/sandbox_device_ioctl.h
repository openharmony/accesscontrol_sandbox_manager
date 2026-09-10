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

#ifndef CLAW_SANDBOX_DEVICE_IOCTL_H
#define CLAW_SANDBOX_DEVICE_IOCTL_H

/*
 * Every device node this process talks to, and the ioctl vocabulary of each.
 *
 * All of it is kernel ABI: the numbers here have to match the kernel side
 * exactly, and _IOWR encodes sizeof(the payload type), so the structs are part
 * of the contract too and live here with the commands that carry them.
 *
 * Collected into one header because they were not: DEC's base and policy-add id
 * had grown a second, identical definition in sandbox_policy.cpp, and nothing
 * would have caught the two drifting apart - both sides compile and link, and
 * the mismatch only shows up as one delivery path quietly failing at run time.
 */

#include <cstddef>
#include <cstdint>
#include <sys/ioctl.h>

#include "sandbox_cmd_parser.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

/*
 * ---------------------------------------------------------------------------
 * /dev/dec - DEC policy device
 *
 * Aligned with startup_appspawn/modules/sandbox/sandbox_dec.h. The parent's
 * pre-fork open (OpenDecDeviceBeforeFork) and the child's reopen
 * (DeliverExecuterInit) use the same path.
 * ---------------------------------------------------------------------------
 */
constexpr const char *DEC_DEVICE_PATH = "/dev/dec";
constexpr int HM_DEC_IOCTL_BASE = 's';

/*
 * The op-control half of the device: everything below measures a struct from
 * sandbox_op_control_policy.h, which only a shell-sandbox build carries. The
 * path and the ioctl base above stay out of the guard - the deny-path and
 * path-mark commands further down use the same device without the model.
 */
#ifdef CONFIG_SHELL_SANDBOX
constexpr int HM_CONFIG_SET_ID = 101;
constexpr int HM_EVENT_SUB_ID = 102;
constexpr int HM_POLICY_ADD_ID = 104;
constexpr int HM_AGENTLOCK_CURRENT_EXECUTER_INIT_ID = 112;
constexpr int HM_AGENTLOCK_CURRENT_DAEMON_INIT_ID = 113;

// config_id carried by DEC_CMD_POLICY_CONFIG_SET. The kernel's policy config
// interface is sub-command driven (see sandbox_dec.h); POLICY_SET_SET is its
// single value today. Must match the kernel enum dec_config_id.
constexpr uint32_t POLICY_SET_SET = 0;

// AgentLock daemon context (DEC_CMD_AGENTLOCK_CURRENT_DAEMON_INIT): identifies
// the current daemon when registering it with the kernel.
struct AgentLockCurrentDaemonContext {
    uint32_t userid;
    uint64_t taskid;  // must not be 0
    uint64_t appIdentifier;
};

// Event subscribe argument
struct dec_event_sub_arg {
    uint32_t eventType;
};

enum DEC_ACTION : uint32_t {
    DEC_ACTION_AGENTLOCK_ASK = 0
};

// Event classes reported back through the device read side.
enum DEC_EVENT_CLASS : uint32_t {
    DEC_EVENT_CLASS_ASK = 0,
};

// The payload structs of the two policy commands below (SandboxPolicyArg,
// SandboxPolicyConfigSetArg, SandboxPolicySetArg, DecClientInitArg) are the
// kernel-facing halves of the op-control model and live with it in
// sandbox_op_control_policy.h.
constexpr unsigned long DEC_CMD_POLICY_ADD =
    _IOWR(HM_DEC_IOCTL_BASE, HM_POLICY_ADD_ID, struct SandboxPolicyArg);
constexpr unsigned long DEC_CMD_AGENTLOCK_CURR_EXECUTER_INIT =
    _IOWR(HM_DEC_IOCTL_BASE, HM_AGENTLOCK_CURRENT_EXECUTER_INIT_ID, struct DecClientInitArg);
constexpr unsigned long DEC_CMD_AGENTLOCK_CURRENT_DAEMON_INIT =
    _IOWR(HM_DEC_IOCTL_BASE, HM_AGENTLOCK_CURRENT_DAEMON_INIT_ID,
        struct AgentLockCurrentDaemonContext);
constexpr unsigned long DEC_CMD_POLICY_CONFIG_SET =
    _IOWR(HM_DEC_IOCTL_BASE, HM_CONFIG_SET_ID, struct SandboxPolicyConfigSetArg);
constexpr unsigned long EVENT_SUB =
    _IOWR(HM_DEC_IOCTL_BASE, HM_EVENT_SUB_ID, struct dec_event_sub_arg);
#endif // CONFIG_SHELL_SANDBOX

#ifdef CONFIG_SHELL_SANDBOX
constexpr uint32_t DEC_KERNEL_BATCH_SIZE = 8;
constexpr uint32_t DEC_POLICY_HEADER_RESERVED = 64;

struct DecPathInfo {
    const char *path;
    uint32_t pathLen;
    uint32_t mode;
    bool flag;
};

struct DecPolicyInfo {
    uint64_t tokenId;
    uint64_t timestamp;
    DecPathInfo path[DEC_KERNEL_BATCH_SIZE];
    uint32_t pathNum;
    int32_t userId;
    uint64_t reserved[DEC_POLICY_HEADER_RESERVED];
    bool flag;
};

constexpr int HM_SET_POLICY_ID = 1;
constexpr size_t DEC_MAX_POLICY_NUM = 64;
constexpr uint32_t DEC_SANDBOX_MODE_READ = 0x00000001;
constexpr uint32_t DEC_SANDBOX_MODE_WRITE = (DEC_SANDBOX_MODE_READ << 1);
constexpr uint32_t DEC_MODE_DENY_INHERIT = (1 << 9);
constexpr uint64_t SEC_TO_NSEC = 1000000000ULL;

constexpr unsigned long SET_DEC_POLICY_CMD =
    _IOWR(HM_DEC_IOCTL_BASE, HM_SET_POLICY_ID, DecPolicyInfo);

// Path mark constants (matching appspawn appspawn_isolate.c)
constexpr int HM_ADD_PATH_MARK = 11;
constexpr uint32_t SEC_UGC_PATH_TYPE = (1 << 0);
constexpr uint32_t SEC_SANDBOX_PATH_TYPE = (1 << 3);
constexpr uint32_t MARK_ENABLE_RECURSIVE = 1;

struct MarkPathInfo {
    const char *path;
    uint32_t flags;
    uint32_t recursive;
    uint32_t reserved[7];
};

constexpr unsigned long ADD_PATH_MARK_CMD =
    _IOWR(HM_DEC_IOCTL_BASE, HM_ADD_PATH_MARK, MarkPathInfo);
#endif // CONFIG_SHELL_SANDBOX

// ---------------------------------------------------------------------------
// /dev/encaps - process capability flags (matching appspawn appspawn_encaps.c)
// ---------------------------------------------------------------------------
#ifdef CONFIG_SHELL_SANDBOX
constexpr const char *ENCAPS_DEVICE_PATH = "/dev/encaps";
constexpr int OH_ENCAPS_MAGIC = 'E';
constexpr int HM_ENCAPS_PROC_FLAG_BASE = 0x1F;
constexpr uint32_t CUSTOM_SANDBOX_PROCESS_TYPE = (1U << 0);

constexpr unsigned long SET_ENCAPS_PROC_FLAG_CMD =
    _IOW(OH_ENCAPS_MAGIC, HM_ENCAPS_PROC_FLAG_BASE, uint32_t);
#endif // CONFIG_SHELL_SANDBOX

// ---------------------------------------------------------------------------
// /dev/xpm - executable region ownership
// ---------------------------------------------------------------------------
constexpr const char *DEV_XPM_PATH = "/dev/xpm";
constexpr int HM_XPM_REGION_IOCTL_BASE = 'x';
constexpr int HM_SET_XPM_OWNERID_ID = 2;
constexpr uint32_t MAX_OWNERID_LEN = 64;
constexpr uint32_t PROCESS_OWNERID_APP = 2;

struct XpmRegionInfo {
    unsigned long addrBase;
    unsigned long length;

    uint32_t idType;
    char ownerid[MAX_OWNERID_LEN];
    uint32_t apiVersion;
};

constexpr unsigned long SET_XPM_OWNERID_CMD =
    _IOW(HM_XPM_REGION_IOCTL_BASE, HM_SET_XPM_OWNERID_ID, struct XpmRegionInfo);

// ---------------------------------------------------------------------------
// /dev/access_token_id - hap parent token
// ---------------------------------------------------------------------------
#ifdef CONFIG_SHELL_SANDBOX
constexpr const char *DEV_ACCESS_TOKEN_PATH = "/dev/access_token_id";
constexpr int HM_ACCESS_TOKENID_IOCTL_BASE = 'A';
constexpr int HM_SET_HAP_PTOKENID = 0x1A;

constexpr unsigned long ACCESS_TOKENID_SET_HAP_PTOKENID =
    _IOW(HM_ACCESS_TOKENID_IOCTL_BASE, HM_SET_HAP_PTOKENID, uint64_t);
#endif // CONFIG_SHELL_SANDBOX

/*
 * ---------------------------------------------------------------------------
 * /dev/hkids - AIDS labelling and blacklist
 *
 * The only family still spelled with macros upstream; kept as constexpr here
 * like the rest, which also forces the payload struct to be declared before the
 * commands that measure it rather than after.
 * ---------------------------------------------------------------------------
 */
constexpr const char *HKIDS_DEVICE_PATH = "/dev/hkids";
constexpr int HM_HKIDS_IOCTL_BASE = 'h';
constexpr int HM_HKIDS_CMD_SEC_EXEC_CMD_ID = 0x04;
constexpr int HM_HKIDS_CMD_SEC_INIT_AIDS_ID = 0x11;

// Fixed by the wire layout of hkids_blacklist_cmd_arg below.
constexpr size_t HKIDS_CMD_MAX_SIZE = 64;

enum blacklist_cmd {
    AGENTID_CMD_SET_AINFO,
    BLACKLIST_CMD_ADD,
    BLACKLIST_CMD_REMOVE,
    BLACKLIST_CMD_CLEAR,
};

struct hkids_ioctl_arg {
    unsigned int module_id;
    unsigned int cmd_id;
    void *cmd_args;
    unsigned int cmd_args_size;
};

struct aids_set_ainfo_arg {
    uint32_t userid;
    uint64_t appIdentifier;
};

struct hkids_blacklist_cmd_arg {
    char command[HKIDS_CMD_MAX_SIZE];
    char subcommand[HKIDS_CMD_MAX_SIZE];
    uint32_t appid;
};

constexpr unsigned long HM_HKIDS_CMD_SEC_EXEC_CMD =
    _IOW(HM_HKIDS_IOCTL_BASE, HM_HKIDS_CMD_SEC_EXEC_CMD_ID, struct hkids_ioctl_arg);
constexpr unsigned long HM_HKIDS_CMD_SEC_INIT_AIDS =
    _IOW(HM_HKIDS_IOCTL_BASE, HM_HKIDS_CMD_SEC_INIT_AIDS_ID, struct hkids_ioctl_arg);

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS

#endif // CLAW_SANDBOX_DEVICE_IOCTL_H
