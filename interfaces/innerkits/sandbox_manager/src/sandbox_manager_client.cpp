/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "sandbox_manager_client.h"

#include <cstdint>
#include <thread>
#include "i_sandbox_manager.h"
#include "iservice_registry.h"
#include "refbase.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"
#include "sys_binder.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerClient"
};
static const int32_t SANDBOX_MANAGER_LOAD_SA_TIMEOUT_SEC = 4;
static const int32_t SANDBOX_MANAGER_LOAD_SA_TRY_TIMES = 2;
static const int32_t SA_REQUEST_RETRY_TIMES = 1;

static const int32_t SENDREQ_FAIL_ERR = 32;
static const std::vector<int32_t> RETRY_CODE_LIST = {
    BR_DEAD_REPLY, BR_FAILED_REPLY, SENDREQ_FAIL_ERR };
}

SandboxManagerClient& SandboxManagerClient::GetInstance()
{
    static SandboxManagerClient instance;
    return instance;
}

SandboxManagerClient::SandboxManagerClient()
{}

SandboxManagerClient::~SandboxManagerClient()
{}

int32_t SandboxManagerClient::CleanPersistPolicyByPath(const std::vector<std::string>& filePathList)
{
    std::function<int32_t(sptr<ISandboxManager> &)> func =
        [&](sptr<ISandboxManager> &proxy) { return proxy->CleanPersistPolicyByPath(filePathList); };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t SandboxManagerClient::PersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    std::function<int32_t(sptr<ISandboxManager> &)> func =
        [&](sptr<ISandboxManager> &proxy) { return proxy->PersistPolicy(policy, result); };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t SandboxManagerClient::UnPersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    std::function<int32_t(sptr<ISandboxManager> &)> func =
        [&](sptr<ISandboxManager> &proxy) { return proxy->UnPersistPolicy(policy, result); };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t SandboxManagerClient::PersistPolicyByTokenId(
    uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    std::function<int32_t(sptr<ISandboxManager> &)> func =
        [&](sptr<ISandboxManager> &proxy) { return proxy->PersistPolicyByTokenId(tokenId, policy, result); };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t SandboxManagerClient::UnPersistPolicyByTokenId(
    uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    std::function<int32_t(sptr<ISandboxManager> &)> func =
        [&](sptr<ISandboxManager> &proxy) { return proxy->UnPersistPolicyByTokenId(tokenId, policy, result); };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t SandboxManagerClient::SetPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                        uint64_t policyFlag, std::vector<uint32_t> &result)
{
    std::function<int32_t(sptr<ISandboxManager> &)> func =
        [&](sptr<ISandboxManager> &proxy) { return proxy->SetPolicy(tokenId, policy, policyFlag, result); };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t SandboxManagerClient::UnSetPolicy(uint32_t tokenId, const PolicyInfo &policy)
{
    std::function<int32_t(sptr<ISandboxManager> &)> func =
        [&](sptr<ISandboxManager> &proxy) { return proxy->UnSetPolicy(tokenId, policy); };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t SandboxManagerClient::SetPolicyAsync(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                             uint64_t policyFlag)
{
    std::function<int32_t(sptr<ISandboxManager> &)> func =
        [&](sptr<ISandboxManager> &proxy) { return proxy->SetPolicyAsync(tokenId, policy, policyFlag); };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t SandboxManagerClient::UnSetPolicyAsync(uint32_t tokenId, const PolicyInfo &policy)
{
    std::function<int32_t(sptr<ISandboxManager> &)> func =
        [&](sptr<ISandboxManager> &proxy) { return proxy->UnSetPolicyAsync(tokenId, policy); };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t SandboxManagerClient::CheckPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                          std::vector<bool> &result)
{
    std::function<int32_t(sptr<ISandboxManager> &)> func =
        [&](sptr<ISandboxManager> &proxy) { return proxy->CheckPolicy(tokenId, policy, result); };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t SandboxManagerClient::StartAccessingPolicy(
    const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    std::function<int32_t(sptr<ISandboxManager> &)> func =
        [&](sptr<ISandboxManager> &proxy) { return proxy->StartAccessingPolicy(policy, result); };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t SandboxManagerClient::StopAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    std::function<int32_t(sptr<ISandboxManager> &)> func =
        [&](sptr<ISandboxManager> &proxy) { return proxy->StopAccessingPolicy(policy, result); };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t SandboxManagerClient::CheckPersistPolicy(
    uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result)
{
    std::function<int32_t(sptr<ISandboxManager> &)> func =
        [&](sptr<ISandboxManager> &proxy) { return proxy->CheckPersistPolicy(tokenId, policy, result); };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t SandboxManagerClient::StartAccessingByTokenId(uint32_t tokenId)
{
    std::function<int32_t(sptr<ISandboxManager> &)> func =
        [&](sptr<ISandboxManager> &proxy) { return proxy->StartAccessingByTokenId(tokenId); };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t SandboxManagerClient::UnSetAllPolicyByToken(uint32_t tokenId)
{
    std::function<int32_t(sptr<ISandboxManager> &)> func =
        [&](sptr<ISandboxManager> &proxy) { return proxy->UnSetAllPolicyByToken(tokenId); };
    return CallProxyWithRetry(func, __FUNCTION__);
}

sptr<ISandboxManager> SandboxManagerClient::GetProxy()
{
    std::unique_lock<std::mutex> lock(proxyMutex_);
    auto samgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "GetSystemAbilityManager return null");
        return nullptr;
    }
    // If sa is loaded, CheckSystemAbility return not null.
    auto remoteObject = samgr->CheckSystemAbility(ISandboxManager::SA_ID_SANDBOX_MANAGER_SERVICE);
    if (remoteObject != nullptr) {
        auto proxy = iface_cast<ISandboxManager>(remoteObject);
        if (proxy != nullptr) {
            return proxy;
        }
    }
    // Try to load sa for SANDBOX_MANAGER_LOAD_SA_TRY_TIMES times.
    for (int32_t i = 0; i < SANDBOX_MANAGER_LOAD_SA_TRY_TIMES; i++) {
        remoteObject = samgr->LoadSystemAbility(ISandboxManager::SA_ID_SANDBOX_MANAGER_SERVICE,
            SANDBOX_MANAGER_LOAD_SA_TIMEOUT_SEC);
        if (remoteObject != nullptr) {
            auto proxy = iface_cast<ISandboxManager>(remoteObject);
            if (proxy != nullptr) {
                return proxy;
            }
            SANDBOXMANAGER_LOG_WARN(LABEL, "Get iface_cast return NULL.");
        }
        SANDBOXMANAGER_LOG_WARN(LABEL, "Try to load SandboxManager Sa failed, times %{public}d / %{public}d",
            i, SANDBOX_MANAGER_LOAD_SA_TRY_TIMES);
    }
    SANDBOXMANAGER_LOG_ERROR(LABEL, "Get proxy retry failed %{public}d times.",
        SANDBOX_MANAGER_LOAD_SA_TRY_TIMES);
    return nullptr;
}

int32_t SandboxManagerClient::CallProxyWithRetry(
    const std::function<int32_t(sptr<ISandboxManager> &)> &func, const char *funcName)
{
    auto proxy = GetProxy();
    if (proxy != nullptr) {
        int32_t ret = func(proxy);
        if (!IsRequestNeedRetry(ret)) {
            return ret;
        } else {
            SANDBOXMANAGER_LOG_WARN(LABEL, "First try call %{public}s failed, " \
                "err = %{public}d. Begin retry.", funcName, ret);
        }
    } else {
        SANDBOXMANAGER_LOG_WARN(LABEL, "First try call %{public}s failed, proxy is NULL. Begin retry.", funcName);
    }
    // begin retry
    for (int32_t i = 0; i < SA_REQUEST_RETRY_TIMES; i++) {
        proxy = GetProxy();
        if (proxy == nullptr) {
            SANDBOXMANAGER_LOG_WARN(LABEL, "Get proxy %{public}s failed, retry time = %{public}d.", funcName, i);
            continue;
        }
        int32_t ret = func(proxy);
        if (!IsRequestNeedRetry(ret)) {
            return ret;
        }
        SANDBOXMANAGER_LOG_WARN(LABEL, "Call %{public}s failed, retry time = %{public}d, " \
            "result = %{public}d.", funcName, i, ret);
    }
    SANDBOXMANAGER_LOG_ERROR(LABEL, "Retry call service %{public}s error, tried %{public}d times.",
        funcName, SA_REQUEST_RETRY_TIMES);
    return SANDBOX_MANAGER_SERVICE_REMOTE_ERR;
}

bool SandboxManagerClient::IsRequestNeedRetry(int32_t ret)
{
    auto it = std::find(RETRY_CODE_LIST.begin(), RETRY_CODE_LIST.end(), ret);
    return it != RETRY_CODE_LIST.end();
}
} // SandboxManager
} // AccessControl
} // OHOS