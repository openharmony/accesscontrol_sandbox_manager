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

#ifndef SANDBOX_MOCK_STATE_H
#define SANDBOX_MOCK_STATE_H

#include <cerrno>
#include <cstdint>
#include <string>
#include <sys/types.h>

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

/*
 * Mock state control for open/ioctl stubs in ioctl_mock_stub.cpp.
 * Tests manipulate this global to control stub behavior for DEC/AgentLock
 * delivery functions that open /dev/dec and issue ioctl commands.
 *
 * DEC delivery is split across the fork boundary (Option 1: separation of duties):
 *   Parent side, DeliverDaemonSidePolicies (before ForkAfterUnshare):
 *     call index 0 = DEC_CMD_AGENTLOCK_CURRENT_DAEMON_INIT  (DaemonInit)
 *     call index 1 = ASK event subscription                (DaemonInit, issued
 *                     immediately after the daemon init on the same fd)
 *     call index 2 = DEC_CMD_POLICY_CONFIG_SET             (PolicyConfigSet, once per
 *                     distinct scope type; exactly one today -- every group is
 *                     locked to "self_session" by the parser)
 *     call index 3.. = DEC_CMD_POLICY_ADD                  (one ioctl per (rule group,
 *                     module); each carries a single policy with policy_cnt=1,
 *                     operation_type/module_id identify the module)
 *   Child side, DeliverExecuterInit (after the fork, in ExecuteLateSteps):
 *     call index 0 = DEC_CMD_AGENTLOCK_CURR_EXECUTER_INIT  (ExecuterInit)
 *
 * failOnCallIndex is resolved per function call: a test calls exactly one
 * delivery function, so index 0/1/2/.. counts ioctls within that function only.
 *
 * Note: the mock open() intercepts "/dev/dec" regardless of flag bits, so the
 * O_CLOEXEC opens (the parent's pre-fork open via OpenDecDeviceBeforeFork and
 * the child's reopen in DeliverExecuterInit) all return mockFd when mockEnabled.
 * The parent-side open is NOT exercised by the DeliverExecuterInit tests (those call
 * DeliverExecuterInit directly and never reach DeliverDaemonSidePolicies);
 * the mount tests cover it via OpenDecDeviceBeforeFork.
 */
struct IoctlMockState {
    bool mockEnabled = false;      // When true, intercept /dev/dec open and ioctl on mockFd
    bool openFail = true;          // Whether mock open returns failure
    int32_t openErrno = ENOENT;        // errno value when open fails
    int32_t mockFd = 100;              // fd value returned by successful mock open
    int32_t failOnCallIndex = -1;      // ioctl call index that should fail (-1 = all succeed)
    int32_t ioctlErrno = EINVAL;       // errno value when ioctl fails
    int32_t ioctlCallCount = 0;        // incremented on each ioctl call to mockFd (reset per test)
};

extern IoctlMockState g_ioctlMockState;

// Mock state for the SELinux APIs used by SandboxManager::SetSelinuxMCS.
// The linker wrappers forward to libselinux unless mockEnabled is true.
struct SelinuxMockState {
    bool mockEnabled = false;
    int32_t selinuxEnabled = 1;
    int32_t getconRet = 0;
    int32_t getpidconRet = 0;
    int32_t securityCheckRet = 0;
    int32_t setconRet = 0;
    int32_t errorNumber = EACCES;
    std::string currentContext = "u:r:claw_sandbox:s0:x1,x2";
    std::string targetContext = "u:r:normal_hap:s0:x58,x334,x512,x868,x1024";
    pid_t capturedPid = -1;
    std::string checkedContext;
    std::string setconContext;
    int32_t getconCallCount = 0;
    int32_t getpidconCallCount = 0;
    int32_t securityCheckCallCount = 0;
    int32_t setconCallCount = 0;
};

extern SelinuxMockState g_selinuxMockState;

// Mock state for permission checks. When true, AccessTokenKit::VerifyAccessToken
// returns PERMISSION_GRANTED for "ohos.permission.CUSTOM_SANDBOX".
extern bool g_customSandboxGranted;

/*
 * Mock state for realpath, wired up through -Drealpath=WrapRealpath in the test
 * target's cflags_cc. The monitor socket whitelist is anchored at
 * /data/storage/el1/base, which only exists inside an application sandbox, so
 * without a redirect IsMonitorSocketPathAllowed() is false for every input and
 * every assertion about it passes without testing anything.
 *
 * While mockEnabled is set, redirectFrom and paths below it resolve as if under
 * redirectTo; everything else goes to the real realpath. Both sides of an
 * IsPathUnder() comparison are rewritten, so containment is preserved. Keep it
 * off by default and reset it in a guard - this is process-wide state.
 */
struct PathMockState {
    bool mockEnabled = false;
    std::string redirectFrom;
    std::string redirectTo;
};

extern PathMockState g_pathMockState;

/*
 * What the exec mocks saw. fexecve must always fail - letting it through would
 * replace the test process - so its return value cannot tell "the executable
 * was refused before exec" apart from "exec was reached and failed". The count
 * is what separates those two, which is the whole point of ExecuteCommand's
 * error path. Reset it in a guard; this is process-wide state.
 */
struct ExecMockState {
    int fexecveCalls = 0;
    int lastFexecveFd = -1;
};

extern ExecMockState g_execMockState;

}  // namespace SANDBOX
}  // namespace AccessControl
}  // namespace OHOS

#endif  // SANDBOX_MOCK_STATE_H
