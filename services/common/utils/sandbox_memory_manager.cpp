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
#include "sandbox_memory_manager.h"

#include "sandbox_manager_log.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
using namespace OHOS::HiviewDFX;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerMemmgr"
};
constexpr int32_t MAX_RUNNING_NUM = 256;
std::recursive_mutex g_instanceMutex;
}

SandboxMemoryManager& SandboxMemoryManager::GetInstance()
{
    static SandboxMemoryManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            SandboxMemoryManager* tmp = new (std::nothrow) SandboxMemoryManager();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

void SandboxMemoryManager::AddFunctionRuningNum()
{
    std::lock_guard<std::mutex> lock(callNumberMutex_);
    callFuncRunningNum_++;
    if (callFuncRunningNum_ > MAX_RUNNING_NUM) {
        SANDBOXMANAGER_LOG_WARN(LABEL,
            "The num of working function (%{public}d) over %{public}d.", callFuncRunningNum_, MAX_RUNNING_NUM);
    }
}

void SandboxMemoryManager::DecreaseFunctionRuningNum()
{
    std::lock_guard<std::mutex> lock(callNumberMutex_);
    callFuncRunningNum_--;
}

bool SandboxMemoryManager::IsAllowedUnloadService()
{
    std::lock_guard<std::mutex> lock(callNumberMutex_);
    if (callFuncRunningNum_ == 0) {
        return true;
    }
    SANDBOXMANAGER_LOG_WARN(LABEL,
        "Not allowed to unload service, callFuncRunningNum_ is %{public}d.", callFuncRunningNum_);
    return false;
}

void SandboxMemoryManager::SetIsDelayedToUnload(bool isUnload)
{
    std::lock_guard<std::mutex> lock(isDelayedMutex_);
    isDelayedToUnload_ = isUnload;
}

bool SandboxMemoryManager::IsDelayedToUnload()
{
    std::lock_guard<std::mutex> lock(isDelayedMutex_);
    return isDelayedToUnload_;
}

}  // namespace SandboxManager
}  // namespace AccessControl
}  // namespace OHOS
