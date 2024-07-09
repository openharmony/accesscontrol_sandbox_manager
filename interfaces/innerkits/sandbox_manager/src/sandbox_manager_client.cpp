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
#include "iservice_registry.h"
#include "i_sandbox_manager.h"
#include "refbase.h"
#include "sandbox_manager_death_recipient.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_load_callback.h"
#include "sandbox_manager_log.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerClient"
};
static const int32_t SANDBOX_MANAGER_LOAD_SA_TIMEOUT_MS = 4000;

SandboxManagerClient& SandboxManagerClient::GetInstance()
{
    static SandboxManagerClient instance;
    return instance;
}

SandboxManagerClient::SandboxManagerClient()
{}

SandboxManagerClient::~SandboxManagerClient()
{}


int32_t SandboxManagerClient::PersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "proxy is null");
        return SANDBOX_MANAGER_SERVICE_NOT_EXIST;
    }
    return proxy->PersistPolicy(policy, result);
}

int32_t SandboxManagerClient::UnPersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "proxy is null");
        return SANDBOX_MANAGER_SERVICE_NOT_EXIST;
    }
    return proxy->UnPersistPolicy(policy, result);
}

int32_t SandboxManagerClient::PersistPolicyByTokenId(
    uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "proxy is null");
        return SANDBOX_MANAGER_SERVICE_NOT_EXIST;
    }
    return proxy->PersistPolicyByTokenId(tokenId, policy, result);
}

int32_t SandboxManagerClient::UnPersistPolicyByTokenId(
    uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "proxy is null");
        return SANDBOX_MANAGER_SERVICE_NOT_EXIST;
    }
    return proxy->UnPersistPolicyByTokenId(tokenId, policy, result);
}

int32_t SandboxManagerClient::SetPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                        uint64_t policyFlag, std::vector<uint32_t> &result)
{
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Proxy is null.");
        return SANDBOX_MANAGER_SERVICE_NOT_EXIST;
    }
    return proxy->SetPolicy(tokenId, policy, policyFlag, result);
}

int32_t SandboxManagerClient::UnSetPolicy(uint32_t tokenId, const PolicyInfo &policy)
{
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Proxy is null.");
        return SANDBOX_MANAGER_SERVICE_NOT_EXIST;
    }
    return proxy->UnSetPolicy(tokenId, policy);
}

int32_t SandboxManagerClient::SetPolicyAsync(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                             uint64_t policyFlag)
{
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Proxy is null.");
        return SANDBOX_MANAGER_SERVICE_NOT_EXIST;
    }
    return proxy->SetPolicyAsync(tokenId, policy, policyFlag);
}

int32_t SandboxManagerClient::UnSetPolicyAsync(uint32_t tokenId, const PolicyInfo &policy)
{
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Proxy is null.");
        return SANDBOX_MANAGER_SERVICE_NOT_EXIST;
    }
    return proxy->UnSetPolicyAsync(tokenId, policy);
}

int32_t SandboxManagerClient::CheckPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                          std::vector<bool> &result)
{
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Proxy is null.");
        return SANDBOX_MANAGER_SERVICE_NOT_EXIST;
    }
    return proxy->CheckPolicy(tokenId, policy, result);
}

int32_t SandboxManagerClient::StartAccessingPolicy(
    const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "proxy is null");
        return SANDBOX_MANAGER_SERVICE_NOT_EXIST;
    }
    return proxy->StartAccessingPolicy(policy, result);
}

int32_t SandboxManagerClient::StopAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "proxy is null");
        return SANDBOX_MANAGER_SERVICE_NOT_EXIST;
    }
    return proxy->StopAccessingPolicy(policy, result);
}

int32_t SandboxManagerClient::CheckPersistPolicy(
    uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result)
{
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "proxy is null");
        return SANDBOX_MANAGER_SERVICE_NOT_EXIST;
    }
    return proxy->CheckPersistPolicy(tokenId, policy, result);
}

int32_t SandboxManagerClient::StartAccessingByTokenId(uint32_t tokenId)
{
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Proxy is null");
        return SANDBOX_MANAGER_SERVICE_NOT_EXIST;
    }
    return proxy->StartAccessingByTokenId(tokenId);
}

int32_t SandboxManagerClient::UnSetAllPolicyByToken(uint32_t tokenId)
{
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Proxy is null");
        return SANDBOX_MANAGER_SERVICE_NOT_EXIST;
    }
    return proxy->UnSetAllPolicyByToken(tokenId);
}

bool SandboxManagerClient::StartLoadSandboxManagerSa()
{
    {
        std::unique_lock<std::mutex> lock(cvLock_);
        readyFlag_ = false;
    }
    auto sam = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "GetSystemAbilityManager is null");
        return false;
    }
    sptr<SandboxManagerLoadCallback> ptrSandboxManagerLoadCallback = new (std::nothrow) SandboxManagerLoadCallback();
    if (ptrSandboxManagerLoadCallback == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "New ptrSandboxManagerLoadCallback fail.");
        return false;
    }

    int32_t result = sam->LoadSystemAbility(ISandboxManager::SA_ID_SANDBOX_MANAGER_SERVICE,
        ptrSandboxManagerLoadCallback);
    if (result != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "LoadSystemAbility %{public}d failed",
            ISandboxManager::SA_ID_SANDBOX_MANAGER_SERVICE);
        return false;
    }
    SANDBOXMANAGER_LOG_INFO(LABEL, "Notify samgr load sa %{public}d success",
        ISandboxManager::SA_ID_SANDBOX_MANAGER_SERVICE);
    return true;
}

void SandboxManagerClient::WaitForSandboxManagerSa()
{
    // wait_for release lock and block until time out(1s) or match the condition with notice
    std::unique_lock<std::mutex> lock(cvLock_);
    auto waitStatus = sandboxManagerCon_.wait_for(
        lock, std::chrono::milliseconds(SANDBOX_MANAGER_LOAD_SA_TIMEOUT_MS), [this]() { return readyFlag_; });
    if (!waitStatus) {
        // time out or loadcallback fail
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Sandbox manager load sa timeout");
        return;
    }
}

void SandboxManagerClient::GetSandboxManagerSa()
{
    auto sam = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "GetSystemAbilityManager return null");
        return;
    }

    auto sa = sam->GetSystemAbility(ISandboxManager::SA_ID_SANDBOX_MANAGER_SERVICE);
    if (sa == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "GetSystemAbility %{public}d is null",
            ISandboxManager::SA_ID_SANDBOX_MANAGER_SERVICE);
        return;
    }

    GetProxyFromRemoteObject(sa);
}

void SandboxManagerClient::LoadSandboxManagerSa()
{
    if (!StartLoadSandboxManagerSa()) {
        return;
    }
    WaitForSandboxManagerSa();
}

void SandboxManagerClient::OnRemoteDiedHandle()
{
    SANDBOXMANAGER_LOG_ERROR(LABEL, "Remote service died");
    std::unique_lock<std::mutex> lock(proxyMutex_);
    proxy_ = nullptr;
    serviceDeathObserver_ = nullptr;
    {
        std::unique_lock<std::mutex> lock1(cvLock_);
        readyFlag_ = false;
    }
}

void SandboxManagerClient::FinishStartSASuccess(const sptr<IRemoteObject> &remoteObject)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "Get sandbox_manager sa success.");

    GetProxyFromRemoteObject(remoteObject);

    // get lock which wait_for release and send a notice so that wait_for can out of block
    std::unique_lock<std::mutex> lock(cvLock_);
    readyFlag_ = true;
    sandboxManagerCon_.notify_one();
}

void SandboxManagerClient::FinishStartSAFail()
{
    SANDBOXMANAGER_LOG_ERROR(LABEL, "get sandbox_manager sa failed.");

    // get lock which wait_for release and send a notice
    std::unique_lock<std::mutex> lock(cvLock_);
    readyFlag_ = true;
    sandboxManagerCon_.notify_one();
}

void SandboxManagerClient::GetProxyFromRemoteObject(const sptr<IRemoteObject> &remoteObject)
{
    if (remoteObject == nullptr) {
        return;
    }

    sptr<SandboxManagerDeathRecipient> serviceDeathObserver = new (std::nothrow) SandboxManagerDeathRecipient();
    if (serviceDeathObserver == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Alloc service death observer fail");
        return;
    }

    if (!remoteObject->AddDeathRecipient(serviceDeathObserver)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Add service death observer fail");
        return;
    }

    auto proxy = iface_cast<ISandboxManager>(remoteObject);
    if (proxy == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "iface_cast get null");
        return;
    }
    std::unique_lock<std::mutex> lock(proxyMutex_);
    proxy_ = proxy;
    serviceDeathObserver_ = serviceDeathObserver;
    SANDBOXMANAGER_LOG_INFO(LABEL, "GetSystemAbility %{public}d success",
        ISandboxManager::SA_ID_SANDBOX_MANAGER_SERVICE);
    return;
}

sptr<ISandboxManager> SandboxManagerClient::GetProxy(bool doLoadSa)
{
    {
        std::unique_lock<std::mutex> lock(proxyMutex_);
        if (proxy_ != nullptr) {
            return proxy_;
        }
    }
    if (doLoadSa) {
        LoadSandboxManagerSa();
    } else {
        GetSandboxManagerSa();
    }
    std::unique_lock<std::mutex> lock(proxyMutex_);
    return proxy_;
}
} // SandboxManager
} // AccessControl
} // OHOS