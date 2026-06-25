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

#include <cstdint>
#include <string>

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

// Mock state control for SpmGetEntry/SpmDataNew stubs in sandbox_manager_mock_stub.cpp.
// Tests manipulate this global to control stub behavior.
struct SpmMockState {
    bool failDataNew = false;    // SpmDataNew returns nullptr
    bool failGetEntry = true;    // SpmGetEntry returns error (default: fail)
    uint32_t uid = 20020026;     // uid written into SpmData by SpmGetEntry
    uint64_t ownerid = 0;        // ownerid written into SpmData
    std::string name;            // name written into SpmData
};

extern SpmMockState g_spmMockState;

// Mock state control for open/ioctl stubs in ioctl_mock_stub.cpp.
// Tests manipulate this global to control stub behavior for DeliverPolicy
// and other functions that open /dev/dec and issue ioctl commands.
//
// By default mockEnabled is false, so all open/ioctl calls are forwarded
// to the real syscalls. Set mockEnabled to true and configure failOnCallIndex
// to simulate failures at specific ioctl stages:
//   call index 0 = DEC_CMD_AGENTLOCK_CURR_EXECUTER_INIT (DeliverPolicyInit)
//   call index 1 = DEC_CMD_POLICY_ADD              (DeliverNetPolicy)
struct IoctlMockState {
    bool mockEnabled = false;      // When true, intercept /dev/dec open and ioctl on mockFd
    bool openFail = true;          // Whether mock open returns failure
    int openErrno = ENOENT;        // errno value when open fails
    int mockFd = 100;              // fd value returned by successful mock open
    int failOnCallIndex = -1;      // ioctl call index that should fail (-1 = all succeed)
    int ioctlErrno = EINVAL;       // errno value when ioctl fails
    int ioctlCallCount = 0;        // incremented on each ioctl call to mockFd (reset per test)
};

extern IoctlMockState g_ioctlMockState;

}  // namespace SANDBOX
}  // namespace AccessControl
}  // namespace OHOS

#endif  // SANDBOX_MOCK_STATE_H
