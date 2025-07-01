/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef SANDBOX_MEMORY_MANAGER_H
#define SANDBOX_MEMORY_MANAGER_H

#include <mutex>
#include <sys/types.h>
#include <unistd.h>

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class SandboxMemoryManager {
public:
    SandboxMemoryManager() {};
    virtual ~SandboxMemoryManager() {};

    static SandboxMemoryManager& GetInstance();
    void AddFunctionRuningNum();
    void DecreaseFunctionRuningNum();
    bool IsAllowedUnloadService();
    void SetIsDelayedToUnload(bool isUnload);
    bool IsDelayedToUnload();

private:
    bool isDelayedToUnload_ = false;
    int32_t callFuncRunningNum_ = 0;
    std::mutex callNumberMutex_;
    std::mutex isDelayedMutex_;
};
}  // namespace SandboxManager
}  // namespace Security
}  // namespace OHOS
#endif  // SANDBOX_MEMORY_MANAGER_H
