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

#include "sandbox_manager_service.h"

#include <cctype>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include "accesstoken_kit.h"
#include "common_event_support.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "policy_info.h"
#include "policy_info_manager.h"
#include "sandbox_manager_const.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_event_subscriber.h"
#include "sandbox_manager_log.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
using namespace OHOS::AppExecFwk;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerService"
};
}

REGISTER_SYSTEM_ABILITY_BY_ID(SandboxManagerService,
    SandboxManagerService::SA_ID_SANDBOX_MANAGER_SERVICE, true);


SandboxManagerService::SandboxManagerService(int saId, bool runOnCreate)
    : SystemAbility(saId, runOnCreate), state_(ServiceRunningState::STATE_NOT_START)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "SandboxManagerService()");
}

SandboxManagerService::SandboxManagerService()
    : SystemAbility(SA_ID_SANDBOX_MANAGER_SERVICE, true), state_(ServiceRunningState::STATE_NOT_START)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "SandboxManagerService()");
}

SandboxManagerService::~SandboxManagerService()
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "~SandboxManagerService()");
}

void SandboxManagerService::OnStart()
{
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        if (state_ == ServiceRunningState::STATE_RUNNING) {
            SANDBOXMANAGER_LOG_INFO(LABEL, "SandboxManagerService has already started.");
            return;
        }
        if (!Initialize()) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Initialize failed.");
            return;
        }
        state_ = ServiceRunningState::STATE_RUNNING;
        SANDBOXMANAGER_LOG_INFO(LABEL, "SandboxManagerService is starting.");
    }
    bool ret = Publish(DelayedSingleton<SandboxManagerService>::GetInstance().get());
    if (!ret) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to publish service! ");
        return;
    }
#ifdef NOT_RESIDENT
    DelayUnloadService();
#endif
    SANDBOXMANAGER_LOG_INFO(LABEL, "SandboxManagerService start successful.");
}

void SandboxManagerService::OnStop()
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "Stop sandbox manager service.");
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        if (state_ == ServiceRunningState::STATE_NOT_START) {
            SANDBOXMANAGER_LOG_INFO(LABEL, "Sandbox manager service has stopped.");
            return;
        }
        state_ = ServiceRunningState::STATE_NOT_START;
        SandboxManagerCommonEventSubscriber::UnRegisterEvent();
    }
}

void SandboxManagerService::OnStart(const SystemAbilityOnDemandReason& startReason)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "SandboxManagerService started by event.");
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        if (state_ == ServiceRunningState::STATE_RUNNING) {
            // Concurrent startup, if sa is running, do event action
            SANDBOXMANAGER_LOG_INFO(LABEL, "SandboxManagerService has already started.");
            StartByEventAction(startReason);
            return;
        }
        if (!Initialize()) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to initialize ");
            return;
        }
        state_ = ServiceRunningState::STATE_RUNNING;
        SANDBOXMANAGER_LOG_INFO(LABEL, "SandboxManagerService is starting.");
        // If service is running, event action is completed by CommonEventSubscriber
        // Process event action
        StartByEventAction(startReason);
    }
    bool ret = Publish(DelayedSingleton<SandboxManagerService>::GetInstance().get());
    if (!ret) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to publish service.");
        return;
    }
#ifdef NOT_RESIDENT
    DelayUnloadService();
#endif
    SANDBOXMANAGER_LOG_INFO(LABEL, "SandboxManagerService start successful.");
}

int32_t SandboxManagerService::CleanPersistPolicyByPath(const std::vector<std::string>& filePathList)
{
    size_t filePathSize = filePathList.size();
    if (filePathSize == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "FilePath vector size error, size = %{public}zu.", filePathSize);
        return INVALID_PARAMTER;
    }
    return PolicyInfoManager::GetInstance().CleanPersistPolicyByPath(filePathList);
}

int32_t SandboxManagerService::PersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    size_t policySize = policy.size();
    if (policySize == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Policy vector size error, size = %{public}zu.", policy.size());
        return INVALID_PARAMTER;
    }

    uint32_t flag = 0;
    if (IPCSkeleton::GetCallingUid() == FOUNDATION_UID) {
        flag = 1;
    }
    return PolicyInfoManager::GetInstance().AddPolicy(callingTokenId, policy, result, flag);
}

int32_t SandboxManagerService::UnPersistPolicy(
    const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    size_t policySize = policy.size();
    if (policySize == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Policy vector size error, size =  %{public}zu.", policy.size());
        return INVALID_PARAMTER;
    }

    return PolicyInfoManager::GetInstance().RemovePolicy(callingTokenId, policy, result);
}

int32_t SandboxManagerService::PersistPolicyByTokenId(
    uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    size_t policySize = policy.size();
    if ((policySize == 0) || (tokenId == 0)) {
        SANDBOXMANAGER_LOG_ERROR(
            LABEL, "Policy vector size error or invalid tokenid, size = %{public}zu, tokenid = %{public}d.",
            policy.size(), tokenId);
        return INVALID_PARAMTER;
    }

    uint32_t flag = 0;
    if (IPCSkeleton::GetCallingUid() == FOUNDATION_UID) {
        flag = 1;
    }
    return PolicyInfoManager::GetInstance().AddPolicy(tokenId, policy, result, flag);
}

int32_t SandboxManagerService::UnPersistPolicyByTokenId(
    uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    size_t policySize = policy.size();
    if ((policySize == 0) || (tokenId == 0)) {
        SANDBOXMANAGER_LOG_ERROR(
            LABEL, "Policy vector size error or invalid tokenid, size = %{public}zu, tokenid = %{public}d.",
            policy.size(), tokenId);
        return INVALID_PARAMTER;
    }

    return PolicyInfoManager::GetInstance().RemovePolicy(tokenId, policy, result);
}

int32_t SandboxManagerService::SetPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                         uint64_t policyFlag, std::vector<uint32_t> &result, uint64_t timestamp)
{
    size_t policySize = policy.size();
    if (policySize == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check policy size failed, size = %{public}zu.", policySize);
        return INVALID_PARAMTER;
    }
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check tokenId failed.");
        return INVALID_PARAMTER;
    }
    if ((policyFlag != 0) && (policyFlag != 1)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check policyFlag failed, policyFlag = %{public}" PRIu64 ".", policyFlag);
        return INVALID_PARAMTER;
    }

    return PolicyInfoManager::GetInstance().SetPolicy(tokenId, policy, policyFlag, result, timestamp);
}

int32_t SandboxManagerService::UnSetPolicy(uint32_t tokenId, const PolicyInfo &policy)
{
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check tokenId failed.");
        return INVALID_PARAMTER;
    }
    uint32_t length = policy.path.length();
    if (length == 0 || length > POLICY_PATH_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Policy path size check failed, path=%{private}s", policy.path.c_str());
        return INVALID_PARAMTER;
    }

    return PolicyInfoManager::GetInstance().UnSetPolicy(tokenId, policy);
}

int32_t SandboxManagerService::SetPolicyAsync(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                              uint64_t policyFlag, uint64_t timestamp)
{
    std::vector<uint32_t> result;
    return SetPolicy(tokenId, policy, policyFlag, result, timestamp);
}

int32_t SandboxManagerService::UnSetPolicyAsync(uint32_t tokenId, const PolicyInfo &policy)
{
    return UnSetPolicy(tokenId, policy);
}

int32_t SandboxManagerService::CheckPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                           std::vector<bool> &result)
{
    size_t policySize = policy.size();
    if (policySize == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check policy size failed, size = %{public}zu.", policySize);
        return INVALID_PARAMTER;
    }
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check tokenId failed.");
        return INVALID_PARAMTER;
    }

    return PolicyInfoManager::GetInstance().CheckPolicy(tokenId, policy, result);
}

int32_t SandboxManagerService::StartAccessingPolicy(const std::vector<PolicyInfo> &policy,
    std::vector<uint32_t> &result, bool useCallerToken, uint32_t tokenId, uint64_t timestamp)
{
    uint32_t callingTokenId = 0;
    if (useCallerToken) {
        callingTokenId = IPCSkeleton::GetCallingTokenID();
    } else {
        callingTokenId = tokenId;
    }
    size_t policySize = policy.size();
    if (policySize == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Policy vector size error, size = %{public}zu", policy.size());
        return INVALID_PARAMTER;
    }

    return PolicyInfoManager::GetInstance().StartAccessingPolicy(callingTokenId, policy, result, timestamp);
}

int32_t SandboxManagerService::StopAccessingPolicy(
    const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    size_t policySize = policy.size();
    if (policySize == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Policy vector size error, size = %{public}zu", policy.size());
        return INVALID_PARAMTER;
    }

    return PolicyInfoManager::GetInstance().StopAccessingPolicy(callingTokenId, policy, result);
}

int32_t SandboxManagerService::CheckPersistPolicy(
    uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result)
{
    size_t policySize = policy.size();
    if (policySize == 0 || tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Policy vector size error, size = %{public}zu, tokenid = %{public}d.",
            policy.size(), tokenId);
        return INVALID_PARAMTER;
    }

    std::vector<uint32_t> matchResult(policySize);

    int32_t ret = PolicyInfoManager::GetInstance().MatchPolicy(tokenId, policy, matchResult);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    result.resize(policySize);
    for (size_t i = 0; i < policy.size(); i++) {
        result[i] = (matchResult[i] == OPERATE_SUCCESSFULLY);
    }
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerService::StartAccessingByTokenId(uint32_t tokenId, uint64_t timestamp)
{
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Invalid Tokenid.");
        return INVALID_PARAMTER;
    }
    return PolicyInfoManager::GetInstance().StartAccessingByTokenId(tokenId, timestamp);
}

int32_t SandboxManagerService::UnSetAllPolicyByToken(uint32_t tokenId, uint64_t timestamp)
{
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Invalid Tokenid.");
        return INVALID_PARAMTER;
    }
    return PolicyInfoManager::GetInstance().UnSetAllPolicyByToken(tokenId, timestamp);
}

bool SandboxManagerService::Initialize()
{
    PolicyInfoManager::GetInstance().Init();
    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
    return true;
}

void SandboxManagerService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    if (systemAbilityId == COMMON_EVENT_SERVICE_ID) {
        SandboxManagerCommonEventSubscriber::RegisterEvent();
    }
}

std::mutex SandboxManagerService::unloadMutex_;
std::shared_ptr<EventHandler> SandboxManagerService::unloadHandler_ = nullptr;
std::shared_ptr<EventRunner> SandboxManagerService::unloadRunner_ = nullptr;

bool SandboxManagerService::InitDelayUnloadHandler()
{
    if ((unloadRunner_ != nullptr) && (unloadHandler_ != nullptr)) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "UnloadRunner_ and UnloadHandler_ already init.");
        return true;
    }
    unloadRunner_ = EventRunner::Create(SA_ID_SANDBOX_MANAGER_SERVICE, AppExecFwk::ThreadMode::FFRT);
    if (unloadRunner_ == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "UnloadRunner_ init failed.");
        return false;
    }
    unloadHandler_ = std::make_shared<EventHandler>(unloadRunner_);
    if (unloadHandler_ == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "UnloadHandler_ init failed.");
        return false;
    }
    return true;
}

#ifdef NOT_RESIDENT
void SandboxManagerService::DelayUnloadService()
{
    std::lock_guard<std::mutex> lock(unloadMutex_);
    if (!InitDelayUnloadHandler()) {
        return;
    }
    auto task = [this]() {
        auto samgrProxy = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Get samgr failed.");
            return;
        }
        int32_t ret = samgrProxy->UnloadSystemAbility(SA_ID_SANDBOX_MANAGER_SERVICE);
        if (ret != ERR_OK) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Unload system ability failed.");
            return;
        }
    };
    unloadHandler_->RemoveTask("SandboxManagerUnload");
    unloadHandler_->PostTask(task, "SandboxManagerUnload", SA_LIFE_TIME);
    SANDBOXMANAGER_LOG_INFO(LABEL, "Delay unload task updated.");
}
#endif

bool SandboxManagerService::StartByEventAction(const SystemAbilityOnDemandReason& startReason)
{
    std::string reasonName = startReason.GetName();
    SANDBOXMANAGER_LOG_INFO(LABEL, "Start by common event, event = %{public}s.", reasonName.c_str());
    if (reasonName == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED ||
        reasonName == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_FULLY_REMOVED ||
        reasonName == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED) {
        auto wantMap = startReason.GetExtraData().GetWant();
        auto iter = startReason.GetExtraData().GetWant().find("accessTokenId");
        if (iter == startReason.GetExtraData().GetWant().end()) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Extradata search tokenid failed.");
            return false;
        }
        std::string strTokenID = iter->second;
        // strTokenID[0] must be digit, otherwise stoull would crash
        if (strTokenID.empty()) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Error empty token received.");
            return false;
        }
        if (std::isdigit(strTokenID[0]) == 0) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Invalid digit token string received.");
            return false;
        }
        size_t idx = 0;
        uint32_t tokenId = std::stoul(strTokenID, &idx);
        if (idx != strTokenID.length()) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Convert failed, tokenId = %{public}s.", strTokenID.c_str());
            return false;
        }
        if (tokenId == 0) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Receive invalid tokenId.");
            return false;
        }
        PolicyInfoManager::GetInstance().RemoveBundlePolicy(tokenId);
        SANDBOXMANAGER_LOG_INFO(LABEL, "RemovebundlePolicy, tokenID = %{public}u.", tokenId);
    }
    return true;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS