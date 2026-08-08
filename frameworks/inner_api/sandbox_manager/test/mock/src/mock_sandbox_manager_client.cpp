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
#include "iservice_registry.h"
#include "refbase.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"
#include "sys_binder.h"
#include "system_ability_definition.h"
#include "if_system_ability_manager.h"
#include "isystem_ability_load_callback.h"
#include "system_ability_load_callback_stub.h"
#include "token_setproc.h"
#include "ipc_skeleton.h"

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

class UnSetAllPolicyAsyncCallback : public SystemAbilityLoadCallbackStub {
public:
    explicit UnSetAllPolicyAsyncCallback(uint32_t tokenId, uint32_t callingTokenId, uint64_t timestamp)
        : tokenId_(tokenId), callingTokenId_(callingTokenId), timestamp_(timestamp) {}
    ~UnSetAllPolicyAsyncCallback() override = default;

    void OnLoadSystemAbilitySuccess(int32_t systemAbilityId, const sptr<IRemoteObject>& remoteObject) override
    {
        uint32_t selfTokenId = GetSelfTokenID();
        if (selfTokenId != callingTokenId_) {
            SANDBOXMANAGER_LOG_INFO(LABEL, "pthread token need check self=%{public}u, calling=%{public}u",
                selfTokenId, callingTokenId_);
            int32_t uid = getuid();
            setuid(0);
            (void)SetSelfTokenID(callingTokenId_);
            if (uid != 0) {
                setuid(uid);
            }
        }
        if (remoteObject == nullptr) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "OnLoadSystemAbilitySuccess remoteObject is null");
            return;
        }
        auto proxy = iface_cast<ISandboxManager>(remoteObject);
        if (proxy == nullptr) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "OnLoadSystemAbilitySuccess iface_cast failed");
            return;
        }
        int32_t ret = proxy->UnSetAllPolicyByToken(tokenId_, timestamp_);
        if (ret != SANDBOX_MANAGER_OK) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "UnSetAllPolicyByTokenAsync call failed, ret=%{public}d", ret);
            return;
        }
        SANDBOXMANAGER_LOG_INFO(LABEL, "UnSetAllPolicyByTokenAsync success, tokenId=%{public}u", tokenId_);
    }

    void OnLoadSystemAbilityFail(int32_t systemAbilityId) override
    {
        LOGE_WITH_REPORT(LABEL, "OnLoadSystemAbilityFail, systemAbilityId=%{public}d, tokenId=%{public}u",
            systemAbilityId, tokenId_);
    }

private:
    uint32_t tokenId_;
    uint32_t callingTokenId_;
    uint64_t timestamp_;
};

SandboxManagerClient& SandboxManagerClient::GetInstance()
{
    static SandboxManagerClient instance;
    return instance;
}

// ===== Real implementations (used by tests) =====
int32_t SandboxManagerClient::SetPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                        uint64_t policyFlag, std::vector<uint32_t> &result, const SetInfo &setInfo)
{
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policy);

    result.clear();
    Uint32VecRawData resultRawData;

    SetInfoParcel setInfoParcel;
    setInfoParcel.setInfo = setInfo;

    std::function<int32_t(sptr<ISandboxManager> &)> func = [&](sptr<ISandboxManager> &proxy) {
        return proxy->SetPolicy(tokenId, policyRawData, policyFlag, resultRawData, setInfoParcel);
    };
    int32_t ret = CallProxyWithRetry(func, __FUNCTION__);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    resultRawData.Unmarshalling(result);
    return ret;
}

int32_t SandboxManagerClient::CheckPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                          std::vector<bool> &result)
{
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policy);

    result.clear();
    BoolVecRawData resultRawData;
    std::function<int32_t(sptr<ISandboxManager> &)> func = [&](sptr<ISandboxManager> &proxy) {
        return proxy->CheckPolicy(tokenId, policyRawData, resultRawData);
    };
    int32_t ret = CallProxyWithRetry(func, __FUNCTION__);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    resultRawData.Unmarshalling(result);
    return ret;
}

int32_t SandboxManagerClient::UnSetAllPolicyByTokenAsync(uint32_t tokenId, uint64_t timestamp)
{
    auto samgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "GetSystemAbilityManager return null");
        return SANDBOX_MANAGER_SERVICE_REMOTE_ERR;
    }
    uint32_t selfTokenId = GetSelfTokenID();
    sptr<UnSetAllPolicyAsyncCallback> callback = new UnSetAllPolicyAsyncCallback(tokenId, selfTokenId, timestamp);
    int32_t ret = samgr->LoadSystemAbility(SANDBOX_MANAGER_SERVICE_ID, callback);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "LoadSystemAbility failed, ret=%{public}d", ret);
        return SANDBOX_MANAGER_SERVICE_REMOTE_ERR;
    }
    SANDBOXMANAGER_LOG_INFO(LABEL, "LoadSystemAbility async initiated, tokenId=%{public}u", tokenId);
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::UnSetAllPolicyByToken(uint32_t tokenId, uint64_t timestamp)
{
    std::function<int32_t(sptr<ISandboxManager> &)> func =
        [&](sptr<ISandboxManager> &proxy) { return proxy->UnSetAllPolicyByToken(tokenId, timestamp); };
    return CallProxyWithRetry(func, __FUNCTION__);
}

// ===== Infrastructure (real) =====

sptr<ISandboxManager> SandboxManagerClient::GetProxy()
{
    std::unique_lock<std::mutex> lock(proxyMutex_);
    auto samgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "GetSystemAbilityManager return null");
        return nullptr;
    }
    // If sa is loaded, CheckSystemAbility return not null.
    auto remoteObject = samgr->CheckSystemAbility(SANDBOX_MANAGER_SERVICE_ID);
    if (remoteObject != nullptr) {
        auto proxy = iface_cast<ISandboxManager>(remoteObject);
        if (proxy != nullptr) {
            return proxy;
        }
    }
    // Try to load sa for SANDBOX_MANAGER_LOAD_SA_TRY_TIMES times.
    for (int32_t i = 0; i < SANDBOX_MANAGER_LOAD_SA_TRY_TIMES; i++) {
        remoteObject = samgr->LoadSystemAbility(SANDBOX_MANAGER_SERVICE_ID,
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

// ===== Stub implementations (not used by tests) =====

int32_t SandboxManagerClient::CleanPersistPolicyByPath(const std::vector<std::string> &filePathList)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::SetPolicyByBundleName(const std::string &bundleName, int32_t appCloneIndex,
    const std::vector<PolicyInfo> &policy, uint64_t policyFlag, std::vector<uint32_t> &result)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::CleanPolicyByUserId(uint32_t userId, const std::vector<std::string> &filePathList)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::PersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::UnPersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::UnPersistPolicy(uint32_t tokenId)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::PersistPolicyByTokenId(
    uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::UnPersistPolicyByTokenId(
    uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::UnSetPolicy(uint32_t tokenId, const PolicyInfo &policy)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::SetDenyPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                            std::vector<uint32_t> &result)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::UnSetDenyPolicy(uint32_t tokenId, const PolicyInfo &policy)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::SetPolicyAsync(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
    uint64_t policyFlag, uint64_t timestamp)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::UnSetPolicyAsync(uint32_t tokenId, const PolicyInfo &policy)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::StartAccessingPolicy(const std::vector<PolicyInfo> &policy,
    std::vector<uint32_t> &result, bool useCallerToken, uint32_t tokenId, uint64_t timestamp)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::StopAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::CheckPersistPolicy(
    uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::StartAccessingByTokenId(uint32_t tokenId, uint64_t timestamp)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::GetPersistPolicy(uint32_t tokenId, std::vector<PolicyInfo> &policy)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::SetShareFileInfo(const std::string &cfginfo, const std::string &bundleName,
    uint32_t userId, uint32_t tokenId)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::UpdateShareFileInfo(const std::string &cfginfo, const std::string &bundleName,
    uint32_t userId, uint32_t tokenId)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::UnsetShareFileInfo(uint32_t tokenId, const std::string &bundleName, uint32_t userId)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::GetSharedDirectoryInfo(std::vector<SharedDirectoryInfo> &result)
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::GrantSharedDirectoryPermission()
{
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerClient::RevokeSharedDirectoryPermission()
{
    return SANDBOX_MANAGER_OK;
}

} // SandboxManager
} // AccessControl
} // OHOS
