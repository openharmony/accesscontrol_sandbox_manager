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

// Op-control DEC ioctl delivery, split out of sandbox_manager.cpp: serialize config_
// into SandboxPolicyTlv and push it to /dev/dec (DeliverDaemonSidePolicies /
// DeliverExecuterInit). TLV rebuild lives in op_control_parser.cpp.

#include "sandbox_manager.h"
#include "sandbox_policy.h"
#include "sandbox_log.h"
#include "sandbox_error.h"
#include "securec.h"
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <map>

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {
// The DEC ioctl vocabulary (command numbers, payload structs, POLICY_SET_SET)
// lives in sandbox_device_ioctl.h, reached through sandbox_manager.h.

static int ExecuterInit(int fd)
{
    SANDBOX_LOGD("ExecuterInit: pid=%{public}d DEC_CMD_AGENTLOCK_CURR_EXECUTER_INIT ioctl on fd=%{public}d "
                 "(runs in child)", getpid(), fd);
    int ret = ioctl(fd, DEC_CMD_AGENTLOCK_CURR_EXECUTER_INIT, nullptr);
    if (ret < 0) {
        std::cerr << "Error: ioctl DEC_CMD_AGENTLOCK_CURR_EXECUTER_INIT failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("ioctl DEC_CMD_AGENTLOCK_CURR_EXECUTER_INIT failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_SET_POLICY_FAILED;
    }
    SANDBOX_LOGD("ExecuterInit: pid=%{public}d executer init succeeded on fd=%{public}d", getpid(), fd);
    return SANDBOX_SUCCESS;
}

// Register the current AgentLock daemon: taskid=pid, userid=uid/UID_BASE,
// appIdentifier=config_.appIdentifierU64.
static int DaemonInit(int fd, uint32_t userid, uint64_t appIdentifier)
{
    struct AgentLockCurrentDaemonContext daemonCtx = {};
    daemonCtx.userid = userid;
    daemonCtx.taskid = static_cast<uint64_t>(getpid()); // must not be 0
    daemonCtx.appIdentifier = appIdentifier;

    SANDBOX_LOGD("DaemonInit: pid=%{public}d DEC_CMD_AGENTLOCK_CURRENT_DAEMON_INIT ioctl on "
                 "fd=%{public}d, userid=0x%{public}x taskid=%{public}llu appIdentifier=0x%{public}llx",
                 getpid(), fd, daemonCtx.userid,
                 static_cast<unsigned long long>(daemonCtx.taskid),
                 static_cast<unsigned long long>(daemonCtx.appIdentifier));
    int ret = ioctl(fd, DEC_CMD_AGENTLOCK_CURRENT_DAEMON_INIT, &daemonCtx);
    if (ret < 0) {
        std::cerr << "Error: ioctl DEC_CMD_AGENTLOCK_CURRENT_DAEMON_INIT failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("ioctl DEC_CMD_AGENTLOCK_CURRENT_DAEMON_INIT failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_SET_POLICY_FAILED;
    }

    // Same fd, immediately after: without the subscription the kernel never
    // reports an ASK event, so the monitor would wait on an fd that stays quiet.
    struct dec_event_sub_arg eventSubArg = {
        .eventType = DEC_ACTION_AGENTLOCK_ASK
    };
    ret = ioctl(fd, EVENT_SUB, &eventSubArg);
    if (ret < 0) {
        std::cerr << "Error: ioctl EVENT_SUB failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("ioctl EVENT_SUB failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_SET_POLICY_FAILED;
    }

    SANDBOX_LOGD("DaemonInit: pid=%{public}d daemon init succeeded on fd=%{public}d", getpid(), fd);
    return SANDBOX_SUCCESS;
}

// Open the framework: DEC_CMD_POLICY_CONFIG_SET (config_id=POLICY_SET_SET) carrying the
// operation-control scope type parsed from the config.
static int PolicyConfigSet(int fd, uint32_t scopeType)
{
    struct SandboxPolicySetArg setGetArg = {};
    setGetArg.scope = scopeType;
    // reserved[] is zero-initialized

    size_t totalSize = sizeof(struct SandboxPolicyConfigSetArg) + sizeof(struct SandboxPolicySetArg);
    struct SandboxPolicyConfigSetArg *configSetArg =
        static_cast<struct SandboxPolicyConfigSetArg *>(calloc(1, totalSize));
    if (configSetArg == nullptr) {
        SANDBOX_LOGE("PolicyConfigSet: calloc for SandboxPolicyConfigSetArg failed");
        return SANDBOX_ERR_SET_POLICY_FAILED;
    }
    configSetArg->config_id = POLICY_SET_SET;
    configSetArg->config_args_size = sizeof(struct SandboxPolicySetArg);
    if (memcpy_s(configSetArg->config_args, totalSize - sizeof(struct SandboxPolicyConfigSetArg),
        &setGetArg, sizeof(setGetArg)) != 0) {
        SANDBOX_LOGE("PolicyConfigSet: memcpy_s failed");
        std::free(configSetArg);
        return SANDBOX_ERR_SET_POLICY_FAILED;
    }

    SANDBOX_LOGD("PolicyConfigSet: pid=%{public}d DEC_CMD_POLICY_CONFIG_SET ioctl on fd=%{public}d, "
                 "config_id=%{public}u config_args_size=%{public}u scope=0x%{public}x",
                 getpid(), fd, configSetArg->config_id, configSetArg->config_args_size,
                 setGetArg.scope);
    int ret = ioctl(fd, DEC_CMD_POLICY_CONFIG_SET, configSetArg);
    std::free(configSetArg);
    if (ret < 0) {
        std::cerr << "Error: ioctl DEC_CMD_POLICY_CONFIG_SET failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("ioctl DEC_CMD_POLICY_CONFIG_SET failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_SET_POLICY_FAILED;
    }
    SANDBOX_LOGD("PolicyConfigSet: pid=%{public}d policy config set succeeded on fd=%{public}d", getpid(), fd);
    return SANDBOX_SUCCESS;
}

// Deliver one DEC_CMD_POLICY_ADD per configured module of one group, in
// STARTUP_DELIVERY_MODULES order, through the shared pipeline. okIoctls counts the
// ADD ioctls that returned success, so a group whose later module fails still
// reports what went through. Refusal reasons accumulate in errors.
static int DeliverOneGroupModules(int fd, const SandboxPolicyRuleGroup &group,
    size_t &okIoctls, std::vector<PolicyError> &errors)
{
    SANDBOX_LOGD("DeliverOneGroupModules: pid=%{public}d enter, fd=%{public}d scope type=%{public}s",
        getpid(), fd, PolicyScopeName(group.scope.type));
    for (DEC_POLICY_OP_TYPE module : STARTUP_DELIVERY_MODULES) {
        /*
         * No guarded inode here, unlike the dynamic path. The socket protection
         * rule goes out last (AddSocketProtectionPolicy), so "newest rule per
         * object" already puts it above anything the config said. A dynamic
         * policy arrives after that rule and cannot outrank it, which is why
         * that path has to check instead. The difference is timing, not intent.
         */
        ModuleOutcome outcome;
        int ret = DeliverModuleToDevice(fd, group, module, GuardedInode {}, outcome);
        errors.insert(errors.end(), outcome.errors.begin(), outcome.errors.end());
        if (ret != SANDBOX_SUCCESS) {
            return ret;  // already logged by DeliverModuleToDevice
        }
        if (outcome.configured) {
            okIoctls++;  // one ADD ioctl went through for this (group, module)
        }
    }
    return SANDBOX_SUCCESS;
}

/** Open /dev/dec (O_CLOEXEC) in the parent pre-fork; the fd (decFd_) crosses the fork, is
 *  closed on parent exit, and the child reopens its own in DeliverExecuterInit. O_CLOEXEC
 *  keeps it out of the exec'd program. @return the fd, or -1 if unavailable (caller errors). */
int SandboxManager::OpenDecDeviceBeforeFork()
{
    int fd = open(DEC_DEVICE_PATH, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        SANDBOX_LOGW("DeliverDaemonSidePolicies: parent pid=%{public}d open %{public}s (O_CLOEXEC) failed, "
                     "errno=%{public}d", getpid(), DEC_DEVICE_PATH, errno);
        return -1;
    }
    SANDBOX_LOGD("DeliverDaemonSidePolicies: parent pid=%{public}d opened %{public}s fd=%{public}d (O_CLOEXEC)",
                 getpid(), DEC_DEVICE_PATH, fd);
    // Claimed before the fork, which is what lets both sides close their own copy
    // of it: the manager in its fork-failure paths, the monitor through the
    // deviceFd_ it is handed. The monitor re-claims it on construction.
    SANDBOX_FDSAN_MARK(fd, SANDBOX_FDSAN_SITE_DEC_PREFORK);
    return fd;
}

// Every rejection reason in full to the log; stderr only says what kind of
// problem it was, since which rule it was is what the log is for.
static void ReportPolicyErrors(const std::vector<PolicyError> &errors)
{
    std::map<std::string, size_t> byReason;
    for (const PolicyError &error : errors) {
        std::string actions;
        for (const std::string &action : error.actions) {
            actions += actions.empty() ? action : ", " + action;
        }
        SANDBOX_LOGE("Policy rejected: reason=%{public}s operation=%{public}s "
            "object=%{public}s detail=%{public}s actions=%{public}s",
            error.reason.c_str(), error.operation.c_str(), error.object.c_str(),
            error.detail.c_str(), actions.c_str());
        byReason[error.reason]++;
    }
    if (byReason.empty()) {
        return;
    }

    // Counted by reason rather than listed: the reasons are the wire vocabulary
    // the response body uses, and an unknown one still comes out readable.
    std::cerr << "  policy rejected:";
    for (const auto &[reason, count] : byReason) {
        std::cerr << " " << reason << " x" << count;
    }
    std::cerr << " (see the log for the rules)" << std::endl;
}

// One rule group that reached the ADD stage.
struct GroupTally {
    size_t index;   // config 1-based index of the group
    size_t ioctls;  // that group's ADD ioctls that succeeded
    bool complete;  // whether the whole group went through
};

// Rolling tallies for the daemon-side loop: groups records each group that reached
// the ADD stage; deliveredGroups / deliveredIoctls aggregate them.
struct GroupDeliveryTally {
    size_t deliveredGroups = 0;  // rule groups whose whole module set went through
    size_t deliveredIoctls = 0;  // DEC_CMD_POLICY_ADD ioctls that returned success
    std::vector<GroupTally> groups;
    std::vector<PolicyError> errors;  // every rule the conversion or the device refused
};

// Report to stderr, on an abort, the per-rule-group tally: one line per delivered
// group (the aborted one ends ", then FAILED") plus the overall groups/ioctls, then
// the refused rules. Only DEC_CMD_POLICY_ADD successes are counted; the scope-setup
// config set is not a per-group delivery.
static void ReportDeliveryAbort(const GroupDeliveryTally &tally)
{
    std::cerr << "Error: DEC policy delivery did not complete; per-rule-group ioctls:" << std::endl;
    for (const GroupTally &group : tally.groups) {
        std::cerr << "  rule group " << group.index << ": " << group.ioctls <<
                     " ioctl(s) delivered" << (group.complete ? "" : ", then FAILED") << std::endl;
    }
    std::cerr << "  total: " << tally.deliveredGroups << " group(s) and " <<
                 tally.deliveredIoctls << " ioctl(s) delivered before the failure" << std::endl;
    ReportPolicyErrors(tally.errors);
}

// Open the DEC framework up front (DEC_CMD_POLICY_CONFIG_SET): the operation-control scope is
// configured even when no rule group follows -- rules are optional, the framework open is not.
// The parser admits only one distinct Scope.Type (self_session today) and rejects repeats, so
// exactly one config set is issued, before any add-policy ioctl: the first group's scope, or
// self_session when there is no group.
static int DeliverScopeConfigSet(int fd, const std::vector<SandboxPolicyRuleGroup> &ruleGroups)
{
    const DEC_POLICY_SCOPE_TYPE scopeType = ruleGroups.empty()
        ? DEC_POLICY_SCOPE_TYPE_SELF_SESSION
        : ruleGroups[0].scope.type;
    SANDBOX_LOGD("DeliverDaemonSidePolicies: pid=%{public}d DEC_CMD_POLICY_CONFIG_SET scope "
                 "type=%{public}s (fd=%{public}d)", getpid(), PolicyScopeName(scopeType), fd);
    return PolicyConfigSet(fd, static_cast<uint32_t>(scopeType));
}

// One module-bearing group as an ADD-only daemon-side step: skip a module-less group, then deliver
// its modules (one DEC_CMD_POLICY_ADD each) and record the group's tally. The single scope config
// set already ran up front (DeliverScopeConfigSet). Errors abort; *skipped marks a module-less
// (non-tallied) group.
static int DeliverOneGroupStep(int fd, const SandboxPolicyRuleGroup &group, size_t groupIndex,
    GroupDeliveryTally &tally, bool *skipped)
{
    *skipped = false;
    if (!group.hasFile && !group.hasProcess && !group.hasNetwork) {
        SANDBOX_LOGD("DeliverDaemonSidePolicies: pid=%{public}d rule group %{public}zu "
                     "(scope type=%{public}s) carries no module, skip",
                     getpid(), groupIndex, PolicyScopeName(group.scope.type));
        *skipped = true;
        return SANDBOX_SUCCESS;
    }
    SANDBOX_LOGD("DeliverDaemonSidePolicies: pid=%{public}d DEC_CMD_POLICY_ADD for rule "
                 "group scope type=%{public}s (fd=%{public}d)",
                 getpid(), PolicyScopeName(group.scope.type), fd);
    size_t groupIoctls = 0;
    int ret = DeliverOneGroupModules(fd, group, groupIoctls, tally.errors);
    tally.deliveredIoctls += groupIoctls;  // this group's ADD ioctls that succeeded so far
    tally.groups.push_back(GroupTally {
        .index = groupIndex,
        .ioctls = groupIoctls,
        .complete = ret == SANDBOX_SUCCESS,
    });
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    tally.deliveredGroups++;  // the whole group (all its modules) went through
    return SANDBOX_SUCCESS;
}

// Get the framework ready to take policy: register the daemon, then open the scope.
// Runs even when there is no rule group, since the scope has to be set either way.
static int RunDaemonHandshake(int fd, uint32_t userid, uint64_t appIdentifier,
    const std::vector<SandboxPolicyRuleGroup> &ruleGroups)
{
    int ret = DaemonInit(fd, userid, appIdentifier);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    // Exactly one config set opens the framework scope; it runs even with nothing to add.
    return DeliverScopeConfigSet(fd, ruleGroups);
}

// Group-major ADD loop: each module-bearing group delivers independently via
// DeliverOneGroupStep. Module-less groups are skipped; a failure reports every group's
// tally to stderr and aborts, leaving whatever already landed in the kernel.
static int DeliverPolicyGroups(int fd, const std::vector<SandboxPolicyRuleGroup> &ruleGroups,
    GroupDeliveryTally &tally)
{
    if (ruleGroups.empty()) {
        SANDBOX_LOGD("DeliverDaemonSidePolicies: pid=%{public}d no operation control rule groups: "
                     "daemon init + scope config set done, nothing to ADD", getpid());
        return SANDBOX_SUCCESS;
    }

    for (size_t gi = 0; gi < ruleGroups.size(); ++gi) {
        bool skipped = false;
        int ret = DeliverOneGroupStep(fd, ruleGroups[gi], gi + 1, tally, &skipped);
        if (skipped) {
            continue;  // group carried no module; nothing to deliver or tally
        }
        if (ret != SANDBOX_SUCCESS) {
            ReportDeliveryAbort(tally);
            SANDBOX_LOGE("DeliverDaemonSidePolicies: delivery aborted after "
                "%{public}zu group(s) and %{public}zu ioctl(s) delivered successfully",
                tally.deliveredGroups, tally.deliveredIoctls);
            return ret;
        }
    }
    return SANDBOX_SUCCESS;
}

// Parent-side daemon delivery, right before ForkAfterUnshare (after pivot_root): open
// /dev/dec, hand the framework the daemon and the scope, then issue the per-(group, module)
// add-policy ioctls, and last of all protect the monitor socket. Rules are optional: a
// config with no rule group still runs the handshake. The fd is held in decFd_ and crosses
// the fork.
int SandboxManager::DeliverDaemonSidePolicies()
{
    if (config_.type != "shell") {
        return SANDBOX_SUCCESS;
    }

    const std::vector<SandboxPolicyRuleGroup> &ruleGroups = config_.policy.addOperationControlRuleGroups;

    decFd_ = OpenDecDeviceBeforeFork();
    if (decFd_ < 0) {
        return SANDBOX_ERR_SET_POLICY_FAILED;
    }

    GroupDeliveryTally tally;
    int ret = RunDaemonHandshake(decFd_, config_.uid / UID_BASE, config_.appIdentifierU64, ruleGroups);
    if (ret == SANDBOX_SUCCESS) {
        ret = DeliverPolicyGroups(decFd_, ruleGroups, tally);
    }
    if (ret != SANDBOX_SUCCESS) {
        // The one place the device is given back: every failure above leaves it to us.
        SANDBOX_FDSAN_CLOSE(decFd_, SANDBOX_FDSAN_SITE_DEC_PREFORK);
        decFd_ = -1;
        return ret;
    }

    // Last, so it wins over any config rule on the same path, and never gated on
    // rule groups: TryReconnect resolves socketPath_ by name, so a child that can
    // unlink the socket can be reconnected to.
    ret = AddSocketProtectionPolicy(decFd_, monitorSocketPath_);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("DeliverDaemonSidePolicies: failed to protect the monitor socket, "
            "ret=%{public}d", ret);
    }
    // Keep decFd_ open: it crosses the fork. Ownership passes to SandboxMonitor
    // in the parent; the child closes its inherited copy in ForkAfterUnshare and
    // reopens its own for executer init.
    SANDBOX_LOGD("DeliverDaemonSidePolicies: pid=%{public}d daemon-side policy delivered: "
                 "%{public}zu group(s), %{public}zu ioctl(s); holding fd=%{public}d (O_CLOEXEC) "
                 "across fork", getpid(), tally.deliveredGroups, tally.deliveredIoctls, decFd_);
    return SANDBOX_SUCCESS;
}

int SandboxManager::DeliverExecuterInit()
{
    if (config_.type != "shell") {
        return SANDBOX_SUCCESS;
    }

    // Child side, after ForkAfterUnshare: reopen /dev/dec (O_CLOEXEC) and issue only the executer-
    // init ioctl. Daemon init / scope config set ran unconditionally in the parent
    // (DeliverDaemonSidePolicies), so executer init runs even when no rule groups exist.
    SANDBOX_LOGD("DeliverExecuterInit: pid=%{public}d child reopening %{public}s with O_CLOEXEC (executer init)",
                 getpid(), DEC_DEVICE_PATH);
    int fd = open(DEC_DEVICE_PATH, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        std::cerr << "Error: open " << DEC_DEVICE_PATH << " failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("DeliverExecuterInit: pid=%{public}d open %{public}s (O_CLOEXEC) failed: %{public}s",
                     getpid(), DEC_DEVICE_PATH, strerror(errno));
        return SANDBOX_ERR_SET_POLICY_FAILED;
    }
    SANDBOX_FDSAN_MARK(fd, SANDBOX_FDSAN_SITE_DEC_LOCAL);
    SANDBOX_LOGD("DeliverExecuterInit: pid=%{public}d opened %{public}s fd=%{public}d (O_CLOEXEC)",
                 getpid(), DEC_DEVICE_PATH, fd);

    // Child-side tail: executer init only (DEC_CMD_AGENTLOCK_CURR_EXECUTER_INIT).
    int ret = ExecuterInit(fd);
    SANDBOX_LOGD("DeliverExecuterInit: pid=%{public}d executer init ioctl returned %{public}d",
                 getpid(), ret);
    SANDBOX_LOGD("DeliverExecuterInit: pid=%{public}d closing fd=%{public}d", getpid(), fd);
    SANDBOX_FDSAN_CLOSE(fd, SANDBOX_FDSAN_SITE_DEC_LOCAL);
    return ret;
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
