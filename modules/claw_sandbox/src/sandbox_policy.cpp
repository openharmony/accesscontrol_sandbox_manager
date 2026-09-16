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

#include "sandbox_policy.h"

#include <sys/stat.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string>
#include <utility>

#include "sandbox_device_ioctl.h"
#include "sandbox_error.h"
#include "sandbox_log.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

/*
 * O_PATH, not O_RDONLY: the rule only needs the fd as a handle on the inode,
 * and a socket file cannot be opened for reading at all (ENXIO). O_PATH also
 * needs no read permission on the target, only search permission on the
 * directories above it.
 */
#ifndef O_PATH
#define O_PATH 010000000
#endif

const char *PolicyScopeName(DEC_POLICY_SCOPE_TYPE scope)
{
    switch (scope) {
        case DEC_POLICY_SCOPE_TYPE_GLOBAL: return "global";
        case DEC_POLICY_SCOPE_TYPE_SPECIFIC_USER: return "specific_user";
        case DEC_POLICY_SCOPE_TYPE_SPECIFIC_APP: return "specific_app";
        case DEC_POLICY_SCOPE_TYPE_SELF_APP: return "self_app";
        case DEC_POLICY_SCOPE_TYPE_SPECIFIC_TASK: return "specific_task";
        case DEC_POLICY_SCOPE_TYPE_SELF_TASK: return "self_task";
        case DEC_POLICY_SCOPE_TYPE_SELF_SESSION: return "self_session";
        default: return "unknown";
    }
}

const char *PolicyModuleName(DEC_POLICY_OP_TYPE module)
{
    switch (module) {
        case DEC_POLICY_OP_TYPE_FILE: return "file";
        case DEC_POLICY_OP_TYPE_PROCESS: return "process";
        case DEC_POLICY_OP_TYPE_NETWORK: return "network";
        default: return "unknown";
    }
}

GuardedInode ResolveGuardedInode(const std::string &protectedPath)
{
    GuardedInode guarded;
    if (protectedPath.empty()) {
        return guarded;
    }

    // lstat, not stat: this has to name the same object AddSocketProtectionPolicy
    // bound its rule to, and that open is O_NOFOLLOW. Following a final symlink
    // here would compare rules against a different inode than the one protected.
    struct stat st = {};
    if (lstat(protectedPath.c_str(), &st) != 0) {
        // Unreachable here means no rule can reach it either.
        SANDBOX_LOGI("Monitor socket is not visible from here; no rule can name it");
        return guarded;
    }
    guarded.valid = true;
    guarded.dev = st.st_dev;
    guarded.ino = st.st_ino;
    return guarded;
}

// Only file rules carry paths; a process rule's item is a bare command name.
static const char *OperationLabel(DEC_POLICY_OP_TYPE module)
{
    return module == DEC_POLICY_OP_TYPE_PROCESS ? "ProcessExecCmd" : "FileDelete";
}

// One entity list, mirroring how OpenPathRules splits off OpenFileFds. Returns
// whether any PATH rule in it turned out to be the guarded object.
static bool RefuseGuardedInEntities(
    std::vector<std::vector<SandboxPolicyTlv::FilterRule>> &entities,
    DEC_POLICY_OP_TYPE module, const GuardedInode &guarded,
    std::vector<PolicyError> &errors)
{
    bool found = false;
    for (auto &entity : entities) {
        for (SandboxPolicyTlv::FilterRule &fr : entity) {
            if (fr.itemType != DEC_POLICY_ITEM_TYPE_PATH || fr.fd < 0) {
                continue;
            }
            // fstat cannot fail on an fd open() just returned.
            struct stat st = {};
            const bool isGuarded = fstat(fr.fd, &st) == 0 &&
                st.st_dev == guarded.dev && st.st_ino == guarded.ino;
            if (!isGuarded) {
                continue;
            }
            SANDBOX_LOGE("Refusing a policy that names the monitor socket");
            errors.push_back(PolicyError::ProtectedObject(OperationLabel(module), fr.path));
            found = true;
        }
    }
    return found;
}

/*
 * Refuse any rule whose fd is the monitor socket.
 *
 * Runs after OpenFileFds, so every PATH rule already holds the fd the kernel
 * would bind to - which is what makes this immune to the spelling, to a symlink
 * anywhere along the path, and to the path changing after the check.
 */
static bool RefuseGuardedInode(SandboxPolicyTlv &tlv, DEC_POLICY_OP_TYPE module,
    const GuardedInode &guarded, std::vector<PolicyError> &errors)
{
    if (!guarded.valid) {
        return false;
    }

    bool found = false;
    for (SandboxPolicyTlv::Policy &policy : tlv.policies) {
        for (SandboxPolicyTlv::Rule &rule : policy.rules) {
            found |= RefuseGuardedInEntities(rule.subjectRules, module, guarded, errors);
            found |= RefuseGuardedInEntities(rule.objectRules, module, guarded, errors);
        }
    }
    return found;
}

/*
 * Everything that needs the rule fds open: refuse anything naming guarded, then
 * serialize and hand over - the kernel resolves the fds during the ioctl.
 * Closing them is the caller's business, which keeps CloseFileFds to one site.
 */
static int CheckAndSendModule(int deviceFd, SandboxPolicyTlv &tlv,
    DEC_POLICY_OP_TYPE module, const GuardedInode &guarded, ModuleOutcome &outcome)
{
    if (RefuseGuardedInode(tlv, module, guarded, outcome.errors)) {
        outcome.result = SANDBOX_ERR_CONFIG_INVALID;
        outcome.detail = "a rule names the monitor socket";
        return outcome.result;
    }

    struct SandboxPolicyArg *context = nullptr;
    int ret = CmdParser::BuildAlPolicyContext(tlv, context);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Build policy context failed for module %{public}s: %{public}d",
            PolicyModuleName(module), ret);
        outcome.result = ret;
        outcome.detail = "failed to build the policy payload";
        return ret;
    }

    context->module_id = static_cast<uint32_t>(module);
    SANDBOX_LOGD("Delivering module %{public}s: module_id=%{public}u version=%{public}u "
        "tlvSize=%{public}u", PolicyModuleName(module), context->module_id,
        context->version, context->size);
    ret = ioctl(deviceFd, DEC_CMD_POLICY_ADD, context);
    const int ioctlError = ret < 0 ? errno : 0;
    std::free(context);

    if (ret < 0) {
        SANDBOX_LOGE("DEC_CMD_POLICY_ADD failed for module %{public}s: %{public}s",
            PolicyModuleName(module), strerror(ioctlError));
        outcome.result = SANDBOX_ERR_SET_POLICY_FAILED;
        outcome.detail = strerror(ioctlError);
        return outcome.result;
    }
    return SANDBOX_SUCCESS;
}

// Convert one module's rules, and say whether the group carried it at all.
static int ConvertModuleTlv(const SandboxPolicyRuleGroup &group, DEC_POLICY_OP_TYPE module,
    SandboxPolicyTlv &tlv, ModuleOutcome &outcome)
{
    // ConvertOperationControlToTlv takes the group array; this group is delivered
    // on its own, so hand it a single-element view.
    const std::vector<SandboxPolicyRuleGroup> groupSet = {group};

    /*
     * Conflicts are per module: the object map lives in one conversion call and
     * its keys never cross modules, so a contradiction among the file rules says
     * nothing about the process ones. Only a file rule can name a path, so a rule
     * naming guarded is the same story.
     */
    int ret = CmdParser::ConvertOperationControlToTlv(groupSet, module, tlv, &outcome.errors);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Refusing module %{public}s before delivery: %{public}d",
            PolicyModuleName(module), ret);
        outcome.configured = true;
        outcome.result = ret;
        outcome.detail = "refused before delivery, see errors";
        return ret;
    }
    outcome.configured = !tlv.policies.empty();
    return SANDBOX_SUCCESS;
}

int DeliverModuleToDevice(int deviceFd, const SandboxPolicyRuleGroup &group,
    DEC_POLICY_OP_TYPE module, const GuardedInode &guarded, ModuleOutcome &outcome)
{
    SandboxPolicyTlv tlv;
    int ret = ConvertModuleTlv(group, module, tlv, outcome);
    if (ret != SANDBOX_SUCCESS || !outcome.configured) {
        return ret;  // refused, or the group does not carry this module
    }

    /*
     * Every PATH item carries an fd ahead of its path string, and the kernel
     * resolves it during the ioctl, so the files have to stay open across it.
     *
     * A path that will not open costs the whole module. The kernel binds a rule
     * to an fd and has no fallback to the path string, so the rules after the
     * failure would go out carrying the "not open" marker and match nothing -
     * silently, which for a deny rule is the worst way to fail.
     */
    ret = tlv.OpenFileFds(&outcome.errors);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Opening the rule paths of module %{public}s failed: %{public}d",
            PolicyModuleName(module), ret);
        outcome.result = ret;
        outcome.detail = "a rule path could not be opened";
    } else {
        ret = CheckAndSendModule(deviceFd, tlv, module, guarded, outcome);
    }

    tlv.CloseFileFds();
    return ret;
}

/*
 * Deny unlink and rmdir on one path, addressed by fd so the kernel binds the
 * rule to the inode rather than re-resolving the name.
 */
static void BuildSocketProtectionTlv(int fd, const std::string &socketPath,
    SandboxPolicyTlv &tlv)
{
    SandboxPolicyTlv::FilterRule objectRule;
    objectRule.cmpType = DEC_POLICY_CMP_EQ;
    objectRule.itemType = DEC_POLICY_ITEM_TYPE_PATH;
    objectRule.fd = fd;
    objectRule.path = socketPath;

    SandboxPolicyTlv::Rule rule;
    rule.action = DEC_POLICY_ACTION_DENY;
    rule.eventType = static_cast<uint32_t>(DEC_POLICY_FILE_EVENT_RMDIR | DEC_POLICY_FILE_EVENT_UNLINK);
    rule.objectRules.push_back(std::vector<SandboxPolicyTlv::FilterRule>{objectRule});

    SandboxPolicyTlv::Policy policy;
    policy.operationType = DEC_POLICY_OP_TYPE_FILE;
    // Left at NONE on purpose: this delivery must not disturb whatever default
    // action the caller's own file policy established.
    policy.defaultAction = DEC_POLICY_ACTION_NONE;
    policy.rules.push_back(rule);

    tlv.policies.push_back(std::move(policy));
}

/*
 * Serialize and hand over. The caller keeps the fd open across this - the kernel
 * resolves it during the ioctl - so closing it is not this function's business.
 */
static int DeliverSocketProtectionTlv(int deviceFd, const SandboxPolicyTlv &tlv)
{
    struct SandboxPolicyArg *context = nullptr;
    int ret = CmdParser::BuildAlPolicyContext(tlv, context);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Failed to build the monitor socket protection policy: %{public}d", ret);
        return ret;
    }

    context->module_id = static_cast<uint32_t>(DEC_POLICY_OP_TYPE_FILE);
    ret = ioctl(deviceFd, DEC_CMD_POLICY_ADD, context);
    int ioctlError = ret < 0 ? errno : 0;
    std::free(context);

    if (ret < 0) {
        SANDBOX_LOGE("DEC_CMD_POLICY_ADD failed for the monitor socket protection: %{public}s",
            strerror(ioctlError));
        return SANDBOX_ERR_SET_POLICY_FAILED;
    }

    return SANDBOX_SUCCESS;
}

int AddSocketProtectionPolicy(int deviceFd, const std::string &socketPath)
{
    if (deviceFd < 0 || socketPath.empty()) {
        return SANDBOX_SUCCESS;
    }

    // O_NOFOLLOW, same as the rule fds in OpenPathRules: the rule must bind to
    // this path itself. Without it a symlink sitting where the socket belongs
    // would have us protect whatever it points at instead, and leave the socket
    // itself unprotected. ELOOP then means exactly that, and is a failure.
    int fd = open(socketPath.c_str(), O_PATH | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ENOENT) {
            // Not part of the sandbox's view of the filesystem, so the child
            // cannot touch it either. Nothing to protect.
            SANDBOX_LOGI("Monitor socket is not visible inside the sandbox; no protection rule needed");
            return SANDBOX_SUCCESS;
        }
        SANDBOX_LOGE("Failed to open the monitor socket for protection: %{public}s", strerror(errno));
        return SANDBOX_ERR_SET_POLICY_FAILED;
    }

    SANDBOX_FDSAN_MARK(fd, SANDBOX_FDSAN_SITE_SOCKET_PATH);

    SandboxPolicyTlv tlv;
    BuildSocketProtectionTlv(fd, socketPath, tlv);
    int ret = DeliverSocketProtectionTlv(deviceFd, tlv);
    SANDBOX_FDSAN_CLOSE(fd, SANDBOX_FDSAN_SITE_SOCKET_PATH);

    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    SANDBOX_LOGI("Monitor socket is protected against deletion");
    return SANDBOX_SUCCESS;
}

/*
 * Deliver one policy: every rule group, and within each one every module the
 * group carries.
 *
 * Keep going after a failure. Rules accumulate in the kernel keyed by their
 * object, so a module that lands adds or replaces its own rules and cannot
 * corrupt another module's.
 *
 * Every configured module is recorded, successes included: delivered is the
 * caller's only account of what is live, since DEC cannot be queried.
 */
int AddOperationControlPolicies(int deviceFd,
    const std::vector<SandboxPolicyRuleGroup> &ruleGroups,
    const std::string &protectedPath,
    std::vector<PolicyScopeResult> *results)
{
    if (deviceFd < 0) {
        SANDBOX_LOGE("Invalid DEC fd for adding operation control policies");
        return SANDBOX_ERR_DEVICE_IO;
    }

    const GuardedInode guarded = ResolveGuardedInode(protectedPath);

    int verdict = SANDBOX_SUCCESS;
    for (const SandboxPolicyRuleGroup &group : ruleGroups) {
        PolicyScopeResult result;
        result.scope = group.scope.type;
        size_t degraded = 0;

        for (DEC_POLICY_OP_TYPE module : DYNAMIC_DELIVERY_MODULES) {
            ModuleOutcome outcome;
            DeliverModuleToDevice(deviceFd, group, module, guarded, outcome);
            result.errors.insert(result.errors.end(),
                outcome.errors.begin(), outcome.errors.end());
            if (!outcome.configured) {
                continue;
            }
            if (outcome.result != SANDBOX_SUCCESS) {
                ++degraded;
            }
            result.delivered.push_back(PolicyModuleResult {
                .module = module,
                .result = outcome.result,
                .detail = std::move(outcome.detail),
            });
        }

        // A group that configured no module has nothing to report, and reporting
        // it would tell the caller a group failed when none did.
        if (result.delivered.empty()) {
            continue;
        }
        /*
         * Partial covers every outcome short of "all of it landed", the
         * all-failed case included: the caller needs delivered either way, and
         * only a partial result carries a body to put it in.
         */
        if (degraded > 0) {
            verdict = SANDBOX_ERR_SET_POLICY_PARTIAL;
        }
        if (results != nullptr) {
            results->push_back(std::move(result));
        }
    }

    return verdict;
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
