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

#ifndef CLAW_SANDBOX_POLICY_RESULT_H
#define CLAW_SANDBOX_POLICY_RESULT_H

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

// Declared, not included: sandbox_op_control_policy.h defines this enum and
// needs PolicyError from here, so including it back would close a cycle. The
// fixed underlying type makes this declaration a complete type on its own.
enum DEC_POLICY_OP_TYPE : uint32_t;
enum DEC_POLICY_SCOPE_TYPE : int;

/*
 * One reason a policy was rejected, as reported to whoever asked for it - the
 * app over the socket, or stderr on the command line.
 *
 * Which fields apply depends on reason, so build these through the factories
 * below rather than by aggregate initialisation: each one fixes a shape in its
 * signature, and there is no way to fill the wrong subset. The rendering side
 * omits empty fields, so a hand-built error with the wrong fields would not
 * fail - it would quietly go out in a shape the app does not expect.
 *
 * Adding a reason means adding a factory here. That keeps "which reasons exist"
 * a question with exactly one place to look.
 */
struct PolicyError {
    std::string reason;                // machine readable, e.g. "action_conflict"
    std::string operation;             // "FileRead", "ProcessExecCmd", ...
    std::string object;                // the offending path or command
    std::string detail;                // free text, e.g. the errno of a failed open
    std::vector<std::string> actions;  // the actions that clash, in encounter order

    // The same object appears under two actions of one operation. Both actions
    // are reported, in the order they were encountered.
    static PolicyError ActionConflict(std::string operation, std::string object,
        std::string firstAction, std::string secondAction)
    {
        return PolicyError {
            .reason = "action_conflict",
            .operation = std::move(operation),
            .object = std::move(object),
            .detail = "",
            .actions = {std::move(firstAction), std::move(secondAction)}
        };
    }

    // A path that will not open: no fd means no inode to bind the rule to.
    // detail carries the errno text - "missing" and "not permitted" call for
    // very different fixes.
    static PolicyError OpenFailed(std::string object, std::string detail)
    {
        return PolicyError {
            .reason = "open_failed",
            .operation = "",
            .object = std::move(object),
            .detail = std::move(detail)
        };
    }

    // A rule naming the monitor's own socket. The wording is fixed here rather
    // than at the call site: it is part of the wire contract, not a log line.
    static PolicyError ProtectedObject(std::string operation, std::string object)
    {
        return PolicyError {
            .reason = "protected_object",
            .operation = std::move(operation),
            .object = std::move(object),
            .detail = "the monitor socket is protected by the sandbox"
        };
    }
};

// What happened to one module. result is an internal error code; the socket
// layer translates it before it reaches the app. detail is the human readable
// half - strerror text for a failed ioctl, or why the monitor refused it -
// and is empty when the module went through.
struct PolicyModuleResult {
    DEC_POLICY_OP_TYPE module;
    int result;
    std::string detail;
};

/*
 * One rule group's outcome. Both halves are scope-bound: the conflict check
 * keys on one group's objects, and delivery issues one ioctl per (group,
 * module) - so an error or a verdict on its own does not say which group it
 * belongs to.
 */
struct PolicyScopeResult {
    DEC_POLICY_SCOPE_TYPE scope;
    std::vector<PolicyError> errors;
    std::vector<PolicyModuleResult> delivered;
};

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS

#endif // CLAW_SANDBOX_POLICY_RESULT_H
