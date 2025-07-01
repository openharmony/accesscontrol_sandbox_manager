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
#include "os_account_manager.h"
#include "policy_info.h"
#include "policy_info_manager.h"
#include "sandbox_manager_const.h"
#include "sandbox_manager_dfx_helper.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_event_subscriber.h"
#include "sandbox_manager_log.h"
#ifdef MEMORY_MANAGER_ENABLE
#include "sandbox_memory_manager.h"
#endif
#include "system_ability_definition.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
using namespace OHOS::AppExecFwk;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerService"
};
#ifdef MEMORY_MANAGER_ENABLE
static constexpr int32_t SA_READY_TO_UNLOAD = 0;
static constexpr int32_t SA_REFUSE_TO_UNLOAD = -1;
#endif
}

REGISTER_SYSTEM_ABILITY_BY_ID(SandboxManagerService,
    SANDBOX_MANAGER_SERVICE_ID, true);


SandboxManagerService::SandboxManagerService(int saId, bool runOnCreate)
    : SystemAbility(saId, runOnCreate), state_(ServiceRunningState::STATE_NOT_START)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "SandboxManagerService()");
}

SandboxManagerService::SandboxManagerService()
    : SystemAbility(SANDBOX_MANAGER_SERVICE_ID, true), state_(ServiceRunningState::STATE_NOT_START)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "SandboxManagerService()");
}

SandboxManagerService::~SandboxManagerService()
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "~SandboxManagerService()");
}

// CallbackEnter, if "option_stub_hooks on", is called per IPC call at entrance of OnRemoteRequest
int32_t SandboxManagerService::CallbackEnter(uint32_t code)
{
#ifdef MEMORY_MANAGER_ENABLE
    SandboxMemoryManager::GetInstance().AddFunctionRuningNum();
#endif
    return ERR_OK;
}

// CallbackExit, if "option_stub_hooks on", is called per IPC call at exit of OnRemoteRequest
int32_t SandboxManagerService::CallbackExit(uint32_t code, int32_t result)
{
#ifdef MEMORY_MANAGER_ENABLE
    SandboxMemoryManager::GetInstance().DecreaseFunctionRuningNum();
#endif
    return ERR_OK;
}

#ifdef MEMORY_MANAGER_ENABLE
int32_t SandboxManagerService::OnIdle(const SystemAbilityOnDemandReason &idleReason)
{
    if (SandboxMemoryManager::GetInstance().IsDelayedToUnload() ||
        SandboxMemoryManager::GetInstance().IsAllowedUnloadService()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "IdleReason name=%{public}s, value=%{public}s.",
            idleReason.GetName().c_str(), idleReason.GetValue().c_str());
        return SA_READY_TO_UNLOAD;
    }

    return SA_REFUSE_TO_UNLOAD;
}
#endif

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
#ifdef MEMORY_MANAGER_ENABLE
        SandboxMemoryManager::GetInstance().SetIsDelayedToUnload(false);
#endif
        SANDBOXMANAGER_LOG_INFO(LABEL, "SandboxManagerService is starting.");
    }
    bool ret = Publish(DelayedSingleton<SandboxManagerService>::GetInstance().get());
    if (!ret) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to publish service! ");
        return;
    }
    DelayUnloadService();
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
    DelayUnloadService();
    SANDBOXMANAGER_LOG_INFO(LABEL, "SandboxManagerService start successful.");
}

int32_t SandboxManagerService::CleanPersistPolicyByPath(const std::vector<std::string> &filePathList)
{
    DelayUnloadService();
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!IsFileManagerCalling(callingTokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Permission denied(tokenID=%{public}d)", callingTokenId);
        return PERMISSION_DENIED;
    }
    size_t filePathSize = filePathList.size();
    if (filePathSize == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "FilePath vector size error, size = %{public}zu.", filePathSize);
        return INVALID_PARAMTER;
    }
    return PolicyInfoManager::GetInstance().CleanPersistPolicyByPath(filePathList);
}

int32_t SandboxManagerService::CleanPolicyByUserId(uint32_t userId, const std::vector<std::string> &filePathList)
{
    DelayUnloadService();
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!IsFileManagerCalling(callingTokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Permission denied(tokenID=%{public}d)", callingTokenId);
        return PERMISSION_DENIED;
    }

    if (filePathList.empty()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "FilePath vector empty");
        return INVALID_PARAMTER;
    }
    return PolicyInfoManager::GetInstance().CleanPolicyByUserId(userId, filePathList);
}


int32_t SandboxManagerService::SetPolicyByBundleName(const std::string &bundleName, int32_t appCloneIndex,
    const PolicyVecRawData &policyRawData, uint64_t policyFlag, Uint32VecRawData &resultRawData)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "set policy by bundle:%{public}s", bundleName.c_str());
    DelayUnloadService();
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, FILE_ACCESS_PERMISSION_NAME)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check tokenId failed.");
        return PERMISSION_DENIED;
    }
    std::vector<PolicyInfo> policy;
    policyRawData.Unmarshalling(policy);
    size_t policySize = policy.size();
    if (policySize == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check policy size failed, size = %{public}zu.", policySize);
        return INVALID_PARAMTER;
    }
    int32_t userId = 0;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "grantPermission failed, get user id failed error=%{public}d", ret);
        return INVALID_PARAMTER;
    }

    uint32_t tokenId = Security::AccessToken::AccessTokenKit::GetHapTokenID(userId, bundleName, appCloneIndex);
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "grantPermission failed, get token id failed");
        return INVALID_PARAMTER;
    }

    SANDBOXMANAGER_LOG_INFO(LABEL, "set policy targetId:%{public}u", tokenId);

    if ((policyFlag != 0) && (policyFlag != 1)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check policyFlag failed, policyFlag = %{public}" PRIu64 ".", policyFlag);
        return INVALID_PARAMTER;
    }
    std::vector<uint32_t> result;
    ret = PolicyInfoManager::GetInstance().SetPolicy(tokenId, policy, policyFlag, result);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    resultRawData.Marshalling(result);
    return SANDBOX_MANAGER_OK;
}
int32_t SandboxManagerService::PersistPolicy(const PolicyVecRawData &policyRawData, Uint32VecRawData &resultRawData)
{
    DelayUnloadService();
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, ACCESS_PERSIST_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }
    std::vector<PolicyInfo> policy;
    policyRawData.Unmarshalling(policy);
    size_t policySize = policy.size();
    if (policySize == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Policy vector size error, size = %{public}zu.", policy.size());
        return INVALID_PARAMTER;
    }

    uint32_t flag = 0;
    if (IPCSkeleton::GetCallingUid() == FOUNDATION_UID) {
        flag = 1;
    }

    std::vector<uint32_t> result;
    int32_t ret = PolicyInfoManager::GetInstance().AddPolicy(callingTokenId, policy, result, flag);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    resultRawData.Marshalling(result);
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerService::UnPersistPolicy(
    const PolicyVecRawData &policyRawData, Uint32VecRawData &resultRawData)
{
    DelayUnloadService();
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, ACCESS_PERSIST_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }
    std::vector<PolicyInfo> policy;
    policyRawData.Unmarshalling(policy);
    size_t policySize = policy.size();
    if (policySize == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Policy vector size error, size =  %{public}zu.", policy.size());
        return INVALID_PARAMTER;
    }

    std::vector<uint32_t> result;
    int32_t ret = PolicyInfoManager::GetInstance().RemovePolicy(callingTokenId, policy, result);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    resultRawData.Marshalling(result);
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerService::PersistPolicyByTokenId(
    uint32_t tokenId, const PolicyVecRawData &policyRawData, Uint32VecRawData &resultRawData)
{
    DelayUnloadService();
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, ACCESS_PERSIST_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }
    std::vector<PolicyInfo> policy;
    policyRawData.Unmarshalling(policy);
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

    std::vector<uint32_t> result;
    int32_t ret = PolicyInfoManager::GetInstance().AddPolicy(tokenId, policy, result, flag);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    resultRawData.Marshalling(result);
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerService::UnPersistPolicyByTokenId(
    uint32_t tokenId, const PolicyVecRawData &policyRawData, Uint32VecRawData &resultRawData)
{
    DelayUnloadService();
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, ACCESS_PERSIST_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }
    std::vector<PolicyInfo> policy;
    policyRawData.Unmarshalling(policy);
    size_t policySize = policy.size();
    if ((policySize == 0) || (tokenId == 0)) {
        SANDBOXMANAGER_LOG_ERROR(
            LABEL, "Policy vector size error or invalid tokenid, size = %{public}zu, tokenid = %{public}d.",
            policy.size(), tokenId);
        return INVALID_PARAMTER;
    }

    std::vector<uint32_t> result;
    int32_t ret = PolicyInfoManager::GetInstance().RemovePolicy(tokenId, policy, result);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    resultRawData.Marshalling(result);
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerService::SetPolicy(uint32_t tokenId, const PolicyVecRawData &policyRawData,
                                         uint64_t policyFlag, Uint32VecRawData &resultRawData, uint64_t timestamp)
{
    DelayUnloadService();
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, SET_POLICY_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }
    std::vector<PolicyInfo> policy;
    policyRawData.Unmarshalling(policy);
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
    std::vector<uint32_t> result;
    int32_t ret = PolicyInfoManager::GetInstance().SetPolicy(tokenId, policy, policyFlag, result, timestamp);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    resultRawData.Marshalling(result);
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerService::UnSetPolicy(uint32_t tokenId, const PolicyInfoParcel &policyParcel)
{
    DelayUnloadService();
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, SET_POLICY_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check tokenId failed.");
        return INVALID_PARAMTER;
    }
    uint32_t length = policyParcel.policyInfo.path.length();
    if (length == 0 || length > POLICY_PATH_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Policy path size check failed, path=%{private}s",
            policyParcel.policyInfo.path.c_str());
        return INVALID_PARAMTER;
    }

    return PolicyInfoManager::GetInstance().UnSetPolicy(tokenId, policyParcel.policyInfo);
}

int32_t SandboxManagerService::SetPolicyAsync(uint32_t tokenId, const PolicyVecRawData &policyRawData,
                                              uint64_t policyFlag, uint64_t timestamp)
{
    Uint32VecRawData resultRawData;
    return SetPolicy(tokenId, policyRawData, policyFlag, resultRawData, timestamp);
}

int32_t SandboxManagerService::UnSetPolicyAsync(uint32_t tokenId, const PolicyInfoParcel &policyParcel)
{
    return UnSetPolicy(tokenId, policyParcel);
}

int32_t SandboxManagerService::CheckPolicy(uint32_t tokenId, const PolicyVecRawData &policyRawData,
    BoolVecRawData &resultRawData)
{
    DelayUnloadService();
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if ((tokenId != callingTokenId) &&
        !CheckPermission(callingTokenId, CHECK_POLICY_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }
    std::vector<PolicyInfo> policy;
    policyRawData.Unmarshalling(policy);
    size_t policySize = policy.size();
    if (policySize == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check policy size failed, size = %{public}zu.", policySize);
        return INVALID_PARAMTER;
    }
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check tokenId failed.");
        return INVALID_PARAMTER;
    }
    std::vector<bool> result;
    int32_t ret = PolicyInfoManager::GetInstance().CheckPolicy(tokenId, policy, result);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    resultRawData.Marshalling(result);
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerService::StartAccessingPolicy(const PolicyVecRawData &policyRawData,
    Uint32VecRawData &resultRawData, bool useCallerToken, uint32_t tokenId, uint64_t timestamp)
{
    DelayUnloadService();
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, ACCESS_PERSIST_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }
    std::vector<PolicyInfo> policy;
    policyRawData.Unmarshalling(policy);
    if (!useCallerToken) {
        callingTokenId = tokenId;
    }
    size_t policySize = policy.size();
    if (policySize == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Policy vector size error, size = %{public}zu", policy.size());
        return INVALID_PARAMTER;
    }

    std::vector<uint32_t> result;
    int32_t ret = PolicyInfoManager::GetInstance().StartAccessingPolicy(callingTokenId, policy, result, timestamp);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    resultRawData.Marshalling(result);
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerService::StopAccessingPolicy(
    const PolicyVecRawData &policyRawData, Uint32VecRawData &resultRawData)
{
    DelayUnloadService();
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, ACCESS_PERSIST_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }
    std::vector<PolicyInfo> policy;
    policyRawData.Unmarshalling(policy);
    size_t policySize = policy.size();
    if (policySize == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Policy vector size error, size = %{public}zu", policy.size());
        return INVALID_PARAMTER;
    }

    std::vector<uint32_t> result;
    int32_t ret = PolicyInfoManager::GetInstance().StopAccessingPolicy(callingTokenId, policy, result);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    resultRawData.Marshalling(result);
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerService::CheckPersistPolicy(
    uint32_t tokenId, const PolicyVecRawData &policyRawData, BoolVecRawData &resultRawData)
{
    DelayUnloadService();
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if ((tokenId != callingTokenId) &&
        !CheckPermission(callingTokenId, CHECK_POLICY_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }
    std::vector<PolicyInfo> policy;
    policyRawData.Unmarshalling(policy);
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
    std::vector<bool> result(policySize);
    for (size_t i = 0; i < policy.size(); i++) {
        result[i] = (matchResult[i] == OPERATE_SUCCESSFULLY);
    }
    resultRawData.Marshalling(result);
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerService::StartAccessingByTokenId(uint32_t tokenId, uint64_t timestamp)
{
    DelayUnloadService();
    if (IPCSkeleton::GetCallingUid() != FOUNDATION_UID) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Not foundation userid, permision denied.");
        return PERMISSION_DENIED;
    }
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Invalid Tokenid.");
        return INVALID_PARAMTER;
    }
    return PolicyInfoManager::GetInstance().StartAccessingByTokenId(tokenId, timestamp);
}

int32_t SandboxManagerService::UnSetAllPolicyByToken(uint32_t tokenId, uint64_t timestamp)
{
    DelayUnloadService();
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, SET_POLICY_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }
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
    unloadRunner_ = EventRunner::Create(SANDBOX_MANAGER_SERVICE_ID, AppExecFwk::ThreadMode::FFRT);
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

void SandboxManagerService::DelayUnloadService()
{
#ifdef NOT_RESIDENT
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
#ifdef MEMORY_MANAGER_ENABLE
        SandboxMemoryManager::GetInstance().SetIsDelayedToUnload(true);
#endif
        int32_t ret = samgrProxy->UnloadSystemAbility(SANDBOX_MANAGER_SERVICE_ID);
        if (ret != ERR_OK) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Unload system ability failed.");
            return;
        }
    };
    unloadHandler_->RemoveTask("SandboxManagerUnload");
    unloadHandler_->PostTask(task, "SandboxManagerUnload", SA_LIFE_TIME);
    SANDBOXMANAGER_LOG_INFO(LABEL, "Delay unload task updated.");
#endif
}

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

bool SandboxManagerService::CheckPermission(const uint32_t tokenId, const std::string &permission)
{
    int32_t ret = Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, permission);
    if (ret == Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Check permission token:%{public}d pass", tokenId);
        return true;
    }
    SandboxManagerDfxHelper::WritePermissionCheckFailEvent(permission, tokenId);
    SANDBOXMANAGER_LOG_ERROR(LABEL, "Check permission token:%{public}d fail", tokenId);
    return false;
}

bool SandboxManagerService::IsFileManagerCalling(uint32_t tokenCaller)
{
    if (tokenFileManagerId_ == 0) {
        tokenFileManagerId_ = Security::AccessToken::AccessTokenKit::GetNativeTokenId(
            "file_manager_service");
    }
    return tokenCaller == tokenFileManagerId_;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS