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

#ifndef CLAW_SANDBOX_POLICY_H
#define CLAW_SANDBOX_POLICY_H

#include <sys/types.h>

#include <vector>

#include <string>

#include "sandbox_cmd_parser.h"
#include "sandbox_error.h"
// Directly, not through sandbox_cmd_parser.h, which only pulls it in under
// CONFIG_SHELL_SANDBOX: everything below names SandboxPolicyRuleGroup and the
// DEC_POLICY_OP_TYPE enumerators outright, so this header has to carry them
// itself rather than depend on the including TU having the define set.
#include "sandbox_op_control_policy.h"
#include "sandbox_policy_result.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

// The names a module and a scope go by outside this process (logs, response
// bodies). The scope spelling matches Scope.Type in the request.
const char *PolicyModuleName(DEC_POLICY_OP_TYPE module);
const char *PolicyScopeName(DEC_POLICY_SCOPE_TYPE scope);

/*
 * The modules each delivery path may carry. Startup takes all three; a dynamic
 * policy has no Network, because EnforcePhaseRules (sandbox_op_control_parser.cpp)
 * refuses one - the network default is fixed when the sandbox starts.
 *
 * Adjacent so the difference is one glance. The order is load-bearing: it fixes
 * the order of the startup ADD ioctls, and of the delivered array a dynamic
 * request reports back.
 */
inline constexpr DEC_POLICY_OP_TYPE STARTUP_DELIVERY_MODULES[] = {
    DEC_POLICY_OP_TYPE_NETWORK,
    DEC_POLICY_OP_TYPE_FILE,
    DEC_POLICY_OP_TYPE_PROCESS,
};
inline constexpr DEC_POLICY_OP_TYPE DYNAMIC_DELIVERY_MODULES[] = {
    DEC_POLICY_OP_TYPE_FILE,
    DEC_POLICY_OP_TYPE_PROCESS,
};

/*
 * An object no rule may name, held as an inode because that is the kernel's own
 * key - "/a/x" and "/a/./x" are one object, and the kernel keeps the newest rule
 * per object, so a rule that spells it differently would override ours.
 *
 * A default-constructed one means nothing is off limits.
 */
struct GuardedInode {
    bool valid = false;
    dev_t dev = 0;
    ino_t ino = 0;
};

GuardedInode ResolveGuardedInode(const std::string &protectedPath);

/*
 * What became of one (group, module).
 *
 * configured is false when the group did not carry the module at all - absent
 * and refused must never read the same. detail is the human readable half of
 * result, and is empty when the module went through.
 */
struct ModuleOutcome {
    bool configured = false;
    int result = SANDBOX_SUCCESS;
    std::string detail;
    std::vector<PolicyError> errors;
};

/*
 * One (group, module) all the way to the kernel: convert to TLV, open the rule
 * paths, refuse anything naming guarded, serialize, one DEC_CMD_POLICY_ADD.
 *
 * The single place that knows the order of those steps, and that the rule fds
 * have to stay open across the ioctl because the kernel resolves them there.
 * Both delivery paths go through it and differ only in what they do with the
 * outcome: the startup path stops at the first failure, a dynamic request
 * carries on and reports every module.
 *
 * Returns what happened to this module, which is also outcome.result.
 */
int DeliverModuleToDevice(int deviceFd, const SandboxPolicyRuleGroup &group,
    DEC_POLICY_OP_TYPE module, const GuardedInode &guarded, ModuleOutcome &outcome);

/*
 * Deny deleting the monitor socket, so the sandboxed program cannot unlink it
 * and put its own in its place.
 *
 * Delivered as its own ioctl rather than merged into the caller's policy: a
 * kernel that refuses this one must not take the caller's rules down with it.
 * Delivering it last also means it wins over anything the config said about the
 * same path, since the kernel keeps the newest rule for an object.
 *
 * Must run after pivot_root, in the sandbox's own mount namespace. The path
 * resolution that builds the rule is then the same one the child would do, so
 * a socket that is not visible inside the sandbox reports ENOENT - and that is
 * success, not failure: what the child cannot reach needs no rule.
 */
int AddSocketProtectionPolicy(int deviceFd, const std::string &socketPath);

/*
 * Deliver one policy, rule group by rule group and within each one module by
 * module: File and Process, the two a dynamic policy may carry.
 *
 * Groups and modules are both independent: one the monitor refuses, or one the
 * kernel rejects, does not hold back the others. Every module a group
 * configured gets an entry in that group's delivered, successes included, so
 * the caller can report what is live in the kernel without asking it.
 *
 * protectedPath, when set, is a path no rule may name - the monitor's own
 * socket. A rule that names it rejects that group's file module and nothing
 * else.
 *
 * Returns SANDBOX_SUCCESS only when everything the policy asked for landed;
 * SANDBOX_ERR_SET_POLICY_PARTIAL otherwise, with one entry in results per group
 * that configured anything.
 */
int AddOperationControlPolicies(int deviceFd,
    const std::vector<SandboxPolicyRuleGroup> &ruleGroups,
    const std::string &protectedPath = "",
    std::vector<PolicyScopeResult> *results = nullptr);

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS

#endif // CLAW_SANDBOX_POLICY_H
