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

}  // namespace SANDBOX
}  // namespace AccessControl
}  // namespace OHOS

#endif  // SANDBOX_MOCK_STATE_H
