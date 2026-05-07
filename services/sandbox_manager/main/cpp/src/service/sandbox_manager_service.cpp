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
#include <chrono>
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
#include "sandbox_stats_reporter.h"
#ifdef MEMORY_MANAGER_ENABLE
#include "sandbox_memory_manager.h"
#endif
#include "system_ability_definition.h"
#include "share_files.h"
#include "persistent_preserve.h"
#include "tokenid_kit.h"
#include "shared_directory_info_vec_raw_data.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security::AccessToken;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerService"
};
#ifdef MEMORY_MANAGER_ENABLE
static constexpr int32_t SA_READY_TO_UNLOAD = 0;
static constexpr int32_t SA_REFUSE_TO_UNLOAD = -1;
#endif
static constexpr int32_t BASE_USER_RANGE = 200000;
static constexpr uint32_t TOKEN_ID_LOWMASK = 0xffffffff;
static constexpr int32_t KILL_PROCESS_FOR_PERMISSION_UPDATE = 5300;
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
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Permission denied(tokenID=%{public}u)", callingTokenId);
        return PERMISSION_DENIED;
    }
    size_t filePathSize = filePathList.size();
    if (filePathSize == 0) {
        LOGE_WITH_REPORT(LABEL, "FilePath vector size error, size = %{public}zu.", filePathSize);
        return INVALID_PARAMTER;
    }
    int32_t userId = 0;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "clean persist failed, get user id failed error=%{public}d", ret);
        return INVALID_PARAMTER;
    }
    return PolicyInfoManager::GetInstance().CleanPolicyByUserId(userId, filePathList);
}

int32_t SandboxManagerService::CleanPolicyByUserId(uint32_t userId, const std::vector<std::string> &filePathList)
{
    DelayUnloadService();
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!IsFileManagerCalling(callingTokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Permission denied(tokenID=%{public}u)", callingTokenId);
        return PERMISSION_DENIED;
    }

    if (filePathList.empty()) {
        LOGE_WITH_REPORT(LABEL, "FilePath vector empty");
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
    if ((policyFlag != 0) && (policyFlag != 1)) {
        LOGE_WITH_REPORT(LABEL, "Check policyFlag failed, policyFlag = %{public}" PRIu64 ".", policyFlag);
        return INVALID_PARAMTER;
    }
    int32_t userId = -1;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        LOGE_WITH_REPORT(LABEL, "grantPermission failed, get user id failed error=%{public}d", ret);
        return INVALID_PARAMTER;
    }

    uint32_t tokenId = Security::AccessToken::AccessTokenKit::GetHapTokenID(userId, bundleName, appCloneIndex);
    if (tokenId == 0) {
        LOGE_WITH_REPORT(LABEL, "grantPermission failed, get token id failed");
        return INVALID_PARAMTER;
    }

    SANDBOXMANAGER_LOG_INFO(LABEL, "set policy targetId:%{public}u", tokenId);

    std::vector<uint32_t> result;
    SetInfo setInfo;
    setInfo.bundleName = bundleName;
    // Use batch-processing version - pass PolicyVecRawData directly without full unmarshalling
    ret = PolicyInfoManager::GetInstance().SetPolicy(tokenId, policyRawData, policyFlag, result, userId, setInfo);
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

    uint32_t flag = 0;
    if (IPCSkeleton::GetCallingUid() == FOUNDATION_UID) {
        flag = 1;
    }

    std::vector<uint32_t> result;
    // Use batch-processing version - pass PolicyVecRawData directly without full unmarshalling
    int32_t ret = PolicyInfoManager::GetInstance().AddPolicy(callingTokenId, policyRawData, result, flag);
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

    std::vector<uint32_t> result;
    // Use batch-processing version - pass PolicyVecRawData directly without full unmarshalling
    int32_t ret = PolicyInfoManager::GetInstance().RemovePolicy(callingTokenId, policyRawData, result);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    resultRawData.Marshalling(result);
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerService::UnPersistPolicy(uint32_t tokenId)
{
    DelayUnloadService();
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    if (!TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Unpersist failed, not system app");
        return SANDBOX_MANAGER_NOT_SYS_APP;
    }

    AccessTokenID callingTokenId = fullTokenId & TOKEN_ID_LOWMASK;
    if (!CheckPermission(callingTokenId, REVOKE_PERSIST_PERMISSION_NAME)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Unpersist failed, check permission failed");
        return PERMISSION_DENIED;
    }
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Invalid tokenid = %{public}u.", tokenId);
        return INVALID_PARAMTER;
    }

    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenType(tokenId);
    if (tokenType == TOKEN_INVALID) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Unpersist failed, tokenId not exist");
        return INVALID_PARAMTER;
    }

    // Remove all policies associated with the token ID
    if (!PolicyInfoManager::GetInstance().RemoveBundlePolicy(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "UnPersistPolicy failed for tokenId=%{public}u", tokenId);
        return SANDBOX_MANAGER_DB_ERR;
    }

    // Also unset all policies by token
    int32_t ret = PolicyInfoManager::GetInstance().UnSetAllPolicyByToken(tokenId);
    if (ret != 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "UnSetAllPolicyByToken failed for tokenId=%{public}u, error=%{public}d",
            tokenId, ret);
        return ret;
    }

    if (tokenType == ATokenTypeEnum::TOKEN_HAP) {
        ret = KillProcessForPermissionUpdate(tokenId);
        if (ret != 0) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Kill process failed for tokenId=%{public}u, error=%{public}d",
                tokenId, ret);
            return SANDBOX_MANAGER_KILL_PROCESS_ERR;
        }
    }

    return ret;
}

int32_t SandboxManagerService::PersistPolicyByTokenId(
    uint32_t tokenId, const PolicyVecRawData &policyRawData, Uint32VecRawData &resultRawData)
{
    DelayUnloadService();
    if (IPCSkeleton::GetCallingUid() != FOUNDATION_UID) {
        LOGE_WITH_REPORT(LABEL, "Not foundation userid, permission denied.");
        return PERMISSION_DENIED;
    }
    if (tokenId == 0) {
        LOGE_WITH_REPORT(LABEL, "Invalid tokenid = %{public}u.", tokenId);
        return INVALID_PARAMTER;
    }

    uint32_t flag = 0;
    if (IPCSkeleton::GetCallingUid() == FOUNDATION_UID) {
        flag = 1;
    }

    std::vector<uint32_t> result;
    // Use batch-processing version - pass PolicyVecRawData directly without full unmarshalling
    int32_t ret = PolicyInfoManager::GetInstance().AddPolicy(tokenId, policyRawData, result, flag);
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

    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    AccessTokenID callingTokenId = fullTokenId & TOKEN_ID_LOWMASK;

    bool isFileManagerService = (Security::AccessToken::AccessTokenKit::GetNativeTokenId("file_manager_service") ==
        callingTokenId);
    ATokenTypeEnum callingTokenType = AccessTokenKit::GetTokenType(callingTokenId);
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenType(tokenId);
    if (isFileManagerService) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "UnPersistPolicyByTokenId by file_manager_service");
    } else if (callingTokenType == ATokenTypeEnum::TOKEN_HAP) {
        if (!TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
            LOGE_WITH_REPORT(LABEL, "UnPersistPolicyByTokenId failed, permission denied - caller is not system app");
            return SANDBOX_MANAGER_NOT_SYS_APP;
        }

        // System HAP apps need to check the specific permission
        if (!CheckPermission(callingTokenId, REVOKE_PERSIST_PERMISSION_NAME)) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "UnPersistPolicyByTokenId failed, required permission: %{public}s",
                REVOKE_PERSIST_PERMISSION_NAME.c_str());
            return PERMISSION_DENIED;
        }

        if (tokenType == TOKEN_INVALID) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Unpersist failed, tokenId not exist");
            return INVALID_PARAMTER;
        }
    } else {
        // Non-HAP tokens (other services) are denied directly
        LOGE_WITH_REPORT(LABEL, "UnPersistPolicyByTokenId failed, permission denied - caller is not system app");
        return PERMISSION_DENIED;
    }

    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Invalid tokenid = %{public}u.", tokenId);
        return INVALID_PARAMTER;
    }

    std::vector<uint32_t> result;
    // Use batch-processing version - pass PolicyVecRawData directly without full unmarshalling
    int32_t ret = PolicyInfoManager::GetInstance().RemovePolicy(tokenId, policyRawData, result);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    resultRawData.Marshalling(result);

    if (tokenType == ATokenTypeEnum::TOKEN_HAP) {
        ret = KillProcessForPermissionUpdate(tokenId);
        if (ret != 0) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Kill process failed for tokenId=%{public}u, error=%{public}d",
                tokenId, ret);
            return SANDBOX_MANAGER_KILL_PROCESS_ERR;
        }
    }

    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerService::SetPolicy(uint32_t tokenId, const PolicyVecRawData &policyRawData,
    uint64_t policyFlag, Uint32VecRawData &resultRawData, const SetInfoParcel &setInfoParcel)
{
    DelayUnloadService();
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, SET_POLICY_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }
    if (tokenId == 0) {
        LOGE_WITH_REPORT(LABEL, "Check tokenId failed.");
        return INVALID_PARAMTER;
    }
    if ((policyFlag != 0) && (policyFlag != 1)) {
        LOGE_WITH_REPORT(LABEL, "Check policyFlag failed, policyFlag = %{public}" PRIu64 ".", policyFlag);
        return INVALID_PARAMTER;
    }
    int32_t userId = 0;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        LOGE_WITH_REPORT(LABEL, "set policy failed, get user id failed error=%{public}d", ret);
        return INVALID_PARAMTER;
    }
    std::vector<uint32_t> result;
    // Use batch-processing version - pass PolicyVecRawData directly without full unmarshalling
    ret = PolicyInfoManager::GetInstance().SetPolicy(tokenId, policyRawData, policyFlag,
        result, userId, setInfoParcel.setInfo);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    resultRawData.Marshalling(result);

    DelayedSingleton<SandboxStatsReporter>::GetInstance()->Report();
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerService::SetDenyPolicy(uint32_t tokenId, const PolicyVecRawData &policyRawData,
    Uint32VecRawData &resultRawData)
{
    DelayUnloadService();
    if (IPCSkeleton::GetCallingUid() != SPACE_MGR_SERVICE_UID) {
        LOGE_WITH_REPORT(LABEL, "Not space_mgr uid, permision denied.");
        return PERMISSION_DENIED;
    }
    if (tokenId == 0) {
        LOGE_WITH_REPORT(LABEL, "Check tokenId failed.");
        return INVALID_PARAMTER;
    }
    int32_t userId = 0;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        LOGE_WITH_REPORT(LABEL, "set deny policy failed, get user id failed error=%{public}d", ret);
        return INVALID_PARAMTER;
    }

    std::vector<uint32_t> result;
    // Use batch-processing version - pass PolicyVecRawData directly without full unmarshalling
    ret = PolicyInfoManager::GetInstance().SetDenyPolicy(tokenId, policyRawData, result, userId);
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
        LOGE_WITH_REPORT(LABEL, "Check tokenId failed.");
        return INVALID_PARAMTER;
    }
    uint32_t length = policyParcel.policyInfo.path.length();
    if (length == 0 || length > POLICY_PATH_LIMIT) {
        LOGE_WITH_REPORT(LABEL, "Policy path size check failed, length= %{public}u", length);
        return INVALID_PARAMTER;
    }

    return PolicyInfoManager::GetInstance().UnSetPolicy(tokenId, policyParcel.policyInfo);
}

int32_t SandboxManagerService::UnSetDenyPolicy(uint32_t tokenId, const PolicyInfoParcel &policyParcel)
{
    DelayUnloadService();
    if (IPCSkeleton::GetCallingUid() != SPACE_MGR_SERVICE_UID) {
        LOGE_WITH_REPORT(LABEL, "Not space_mgr uid, permision denied.");
        return PERMISSION_DENIED;
    }
    if (tokenId == 0) {
        LOGE_WITH_REPORT(LABEL, "Check tokenId failed.");
        return INVALID_PARAMTER;
    }
    uint32_t length = policyParcel.policyInfo.path.length();
    if (length == 0 || length > POLICY_PATH_LIMIT) {
        LOGE_WITH_REPORT(LABEL, "Policy path size check failed, length= %{public}u", length);
        return INVALID_PARAMTER;
    }

    return PolicyInfoManager::GetInstance().UnSetDenyPolicy(tokenId, policyParcel.policyInfo);
}

int32_t SandboxManagerService::SetPolicyAsync(uint32_t tokenId, const PolicyVecRawData &policyRawData,
                                              uint64_t policyFlag, uint64_t timestamp)
{
    Uint32VecRawData resultRawData;
    SetInfoParcel setInfoParcel;
    setInfoParcel.setInfo.timestamp = timestamp;
    return SetPolicy(tokenId, policyRawData, policyFlag, resultRawData, setInfoParcel);
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
    if (tokenId == 0) {
        LOGE_WITH_REPORT(LABEL, "Check tokenId failed.");
        return INVALID_PARAMTER;
    }

    std::vector<bool> result;
    // Use batch-processing version - pass PolicyVecRawData directly without full unmarshalling
    int32_t ret = PolicyInfoManager::GetInstance().CheckPolicy(tokenId, policyRawData, result);
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
    if (!useCallerToken) {
        if (IPCSkeleton::GetCallingUid() != FOUNDATION_UID) {
            LOGE_WITH_REPORT(LABEL, "Not foundation userid, permission denied.");
            return PERMISSION_DENIED;
        }
        callingTokenId = tokenId;
    }
    int32_t userId = 0;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        LOGE_WITH_REPORT(LABEL, "start accessing policy failed, get user id failed error=%{public}d", ret);
        return INVALID_PARAMTER;
    }

    std::vector<uint32_t> result;
    // Use batch-processing version - pass PolicyVecRawData directly without full unmarshalling
    ret = PolicyInfoManager::GetInstance().StartAccessingPolicy(callingTokenId,
        policyRawData, result, userId, timestamp);
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

    std::vector<uint32_t> result;
    // Use batch-processing version - pass PolicyVecRawData directly without full unmarshalling
    int32_t ret = PolicyInfoManager::GetInstance().StopAccessingPolicy(callingTokenId, policyRawData, result);
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
    if (tokenId == 0) {
        LOGE_WITH_REPORT(LABEL, "Invalid tokenid = %{public}u.", tokenId);
        return INVALID_PARAMTER;
    }

    std::vector<uint32_t> matchResult;
    // Use batch-processing version - pass PolicyVecRawData directly without full unmarshalling
    int32_t ret = PolicyInfoManager::GetInstance().MatchPolicy(tokenId, policyRawData, matchResult);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    std::vector<bool> result(matchResult.size());
    for (size_t i = 0; i < matchResult.size(); i++) {
        result[i] = (matchResult[i] == OPERATE_SUCCESSFULLY);
    }
    resultRawData.Marshalling(result);
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerService::StartAccessingByTokenId(uint32_t tokenId, uint64_t timestamp)
{
    DelayUnloadService();
    if (IPCSkeleton::GetCallingUid() != FOUNDATION_UID) {
        LOGE_WITH_REPORT(LABEL, "Not foundation userid, permision denied.");
        return PERMISSION_DENIED;
    }
    if (tokenId == 0) {
        LOGE_WITH_REPORT(LABEL, "Invalid Tokenid.");
        return INVALID_PARAMTER;
    }
    int32_t userId = 0;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        LOGE_WITH_REPORT(LABEL, "start accessing by token failed, get user id failed error=%{public}d", ret);
        return INVALID_PARAMTER;
    }
    return PolicyInfoManager::GetInstance().StartAccessingByTokenId(tokenId, userId, timestamp);
}

int32_t SandboxManagerService::UnSetAllPolicyByToken(uint32_t tokenId, uint64_t timestamp)
{
    DelayUnloadService();
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, SET_POLICY_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }
    if (tokenId == 0) {
        LOGE_WITH_REPORT(LABEL, "Invalid Tokenid.");
        return INVALID_PARAMTER;
    }
    return PolicyInfoManager::GetInstance().UnSetAllPolicyByToken(tokenId, timestamp);
}

int32_t SandboxManagerService::GetPersistPolicy(uint32_t tokenId, PolicyVecRawData &policyRawData)
{
    DelayUnloadService();
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    if (!TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "GetPersistPolicy failed, not system app");
        return SANDBOX_MANAGER_NOT_SYS_APP;
    }

    AccessTokenID callingTokenId = fullTokenId & TOKEN_ID_LOWMASK;
    if (!CheckPermission(callingTokenId, GET_PERSIST_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }

    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Get persist policy failed, invalid tokenid");
        return INVALID_PARAMTER;
    }

    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenType(tokenId);
    if (tokenType == TOKEN_INVALID) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Get persist policy failed, tokenId not exist");
        return INVALID_PARAMTER;
    }

    return PolicyInfoManager::GetInstance().GetPersistPolicy(tokenId, policyRawData);
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
        SANDBOXMANAGER_LOG_DEBUG(LABEL, "UnloadRunner_ and UnloadHandler_ already init.");
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
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "Delay unload task updated.");
#endif
}

template <typename T>
static int32_t GetDemandReasonValue(std::string value, T &data)
{
    if (value.empty()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Error empty value received.");
        return INVALID_PARAMTER;
    }
    if (std::isdigit(value[0]) == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Invalid digit userId string received.");
        return INVALID_PARAMTER;
    }
    size_t idx = 0;
    
    if constexpr (std::is_same_v<T, uint32_t>) {
        data = std::stoul(value, &idx);
    } else {
        data = std::stoi(value, &idx);
    }
    
    if (idx != value.length()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Convert failed, %{public}s.", value.c_str());
        return INVALID_PARAMTER;
    }

    return SANDBOX_MANAGER_OK;
}

static int32_t GetDemandReasonInfo(const SystemAbilityOnDemandReason &startReason,
    std::string &bundleName, int32_t &userId, uint32_t &tokenId)
{
    auto wantMap = startReason.GetExtraData().GetWant();
    for (auto i = wantMap.begin(); i != wantMap.end(); ++i) {
        std::string key = std::string(i->first.data());
        std::string value = std::string(i->second.data());
        if (key == "bundleName") {
            if (value.empty()) {
                SANDBOXMANAGER_LOG_ERROR(LABEL, "Error empty bundleName received.");
                return INVALID_PARAMTER;
            }
            bundleName = value;
        }
        if (key == "userId") {
            if (SANDBOX_MANAGER_OK != GetDemandReasonValue(value, userId)) {
                return INVALID_PARAMTER;
            }
            if (userId <= 0) {
                SANDBOXMANAGER_LOG_ERROR(LABEL, "Error userId received.");
                return INVALID_PARAMTER;
            }
        }
        if (key == "accessTokenId") {
            if (SANDBOX_MANAGER_OK != GetDemandReasonValue(value, tokenId)) {
                return INVALID_PARAMTER;
            }
            if (tokenId == 0) {
                SANDBOXMANAGER_LOG_ERROR(LABEL, "Error tokenId received.");
                return INVALID_PARAMTER;
            }
        }
    }

    if (bundleName.empty()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "GetDemandReasonInfo failed by error input.");
        return INVALID_PARAMTER;
    }
    return SANDBOX_MANAGER_OK;
}

static int32_t GetDemandReasonAppIndex(const SystemAbilityOnDemandReason &startReason, int &appIndex)
{
    auto iter = startReason.GetExtraData().GetWant().find("appIndex");
    if (iter == startReason.GetExtraData().GetWant().end()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Extradata search appIndex failed.");
        return INVALID_PARAMTER;
    }
    std::string appIndexID = iter->second;
    if (SANDBOX_MANAGER_OK != GetDemandReasonValue(appIndexID, appIndex)) {
        return INVALID_PARAMTER;
    }

    return SANDBOX_MANAGER_OK;
}

static int32_t GetDemandPreserveConfig(const SystemAbilityOnDemandReason &startReason, std::string &config)
{
    auto iter = startReason.GetExtraData().GetWant().find("ohos.fileshare.supportPreservePersistentPermission");
    if (iter == startReason.GetExtraData().GetWant().end()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Extradata search Preserve Config failed.");
        return INVALID_PARAMTER;
    }
    std::string value = iter->second;
    if (value.empty()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Error Preserve Config received.");
        return INVALID_PARAMTER;
    }
    config = value;
    return SANDBOX_MANAGER_OK;
}

static int32_t GetDemandAppIdentifier(const SystemAbilityOnDemandReason &startReason, std::string &appIdentifier)
{
    auto iter = startReason.GetExtraData().GetWant().find("appIdentifier");
    if (iter == startReason.GetExtraData().GetWant().end()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Extradata search AppIdentifier failed.");
        return INVALID_PARAMTER;
    }
    std::string value = iter->second;
    if (value.empty()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Error AppIdentifier received.");
        return INVALID_PARAMTER;
    }
    appIdentifier = value;
    return SANDBOX_MANAGER_OK;
}

bool SandboxManagerService::PackageChangedEventAction(const SystemAbilityOnDemandReason &startReason)
{
    uint32_t tokenId = 0;
    std::string bundleName;
    int32_t userId = -1;
    int32_t ret = GetDemandReasonInfo(startReason, bundleName, userId, tokenId);
    if (ret != SANDBOX_MANAGER_OK) {
        return false;
    }
    SANDBOXMANAGER_LOG_INFO(LABEL, "PackageChangedEventAction bundleName = %{public}s.%{public}d.%{public}u",
        bundleName.c_str(), userId, tokenId);
    ret = PolicyInfoManager::GetInstance().CleanPolicyByPackageChanged(bundleName, userId);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "%{public}s clean policy failed", bundleName.c_str());
        return false;
    }

#ifdef NOT_RESIDENT
    SandboxManagerShare::GetInstance().Refresh(bundleName, userId);
#endif

    return true;
}

bool SandboxManagerService::PackageAddEventAction(const SystemAbilityOnDemandReason &startReason)
{
    uint32_t tokenId = 0;
    std::string bundleName;
    std::string appIdentifier;
    int32_t userId = -1;
    int32_t ret = GetDemandReasonInfo(startReason, bundleName, userId, tokenId);
    if (ret != SANDBOX_MANAGER_OK) {
        return false;
    }
    ret = GetDemandAppIdentifier(startReason, appIdentifier);
    if (ret != SANDBOX_MANAGER_OK) {
        return false;
    }
    SANDBOXMANAGER_LOG_INFO(LABEL, "PackageAdd %{public}s, %{public}s, userId=%{public}d, tokenId=%{public}u",
        bundleName.c_str(), appIdentifier.c_str(), userId, tokenId);
    ret = PersistentPreserve::RestoreBundlePersistentPolicies(appIdentifier, userId, tokenId, bundleName);
    if (ret != SANDBOX_MANAGER_OK) {
        return false;
    }
    ret = PersistentPreserve::DeleteBundlePersistentPolicies(appIdentifier, userId);
    if (ret != SANDBOX_MANAGER_OK) {
        return false;
    }
    SANDBOXMANAGER_LOG_INFO(LABEL, "OnReceiveEventAdd for %{public}s", bundleName.c_str());
    return true;
}

bool SandboxManagerService::PackageRemoveEventAction(const SystemAbilityOnDemandReason &startReason)
{
    uint32_t tokenId = 0;
    std::string bundleName;
    std::string appIdentifier;
    int32_t userId = -1;
    int32_t ret = GetDemandReasonInfo(startReason, bundleName, userId, tokenId);
    if (ret != SANDBOX_MANAGER_OK) {
        return false;
    }

    int32_t appIndex;
    ret = GetDemandReasonAppIndex(startReason, appIndex);
    if (ret != SANDBOX_MANAGER_OK) {
        return false;
    }
    SANDBOXMANAGER_LOG_INFO(LABEL, "PackageRemoveEventAction bundleName=%{public}s.%{public}d.%{public}u.%{public}d",
        bundleName.c_str(), userId, tokenId, appIndex);
    if (appIndex == 0) {
        std::string shouldPreserve;
        ret = GetDemandPreserveConfig(startReason, shouldPreserve);
        if (ret != SANDBOX_MANAGER_OK) {
            return false;
        }
        SANDBOXMANAGER_LOG_INFO(LABEL, "main package removed, PreserveConfig=%{public}s", shouldPreserve.c_str());
        if (shouldPreserve == "true") {
            ret = GetDemandAppIdentifier(startReason, appIdentifier);
            if (ret != SANDBOX_MANAGER_OK) {
                return false;
            }
            ret = PersistentPreserve::SaveBundlePersistentPolicies(bundleName, userId, appIdentifier, tokenId);
            if (ret != SANDBOX_MANAGER_OK) {
                LOGE_WITH_REPORT(LABEL, "SaveBundlePersistentPolicies failed for %{public}s", bundleName.c_str());
            }
            //no need remove bundle policy
            SANDBOXMANAGER_LOG_INFO(LABEL, "RemoveBundlePolicy, tokenID = %{public}u.", tokenId);
            return true;
        }
    }

    // Remove bundle policy
    if (PolicyInfoManager::GetInstance().RemoveBundlePolicy(tokenId) == false) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "RemoveBundlePolicy failed, tokenID = %{public}u.", tokenId);
        return false;
    }
    SANDBOXMANAGER_LOG_INFO(LABEL, "RemoveBundlePolicy, tokenID = %{public}u.", tokenId);
    return true;
}

bool SandboxManagerService::StartByEventAction(const SystemAbilityOnDemandReason& startReason)
{
    std::string reasonName = startReason.GetName();
    SANDBOXMANAGER_LOG_INFO(LABEL, "Start by common event, event = %{public}s.", reasonName.c_str());
    if (reasonName == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED ||
        reasonName == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_FULLY_REMOVED ||
        reasonName == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED) {
        return PackageRemoveEventAction(startReason);
    }
    if (reasonName == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED) {
        return PackageChangedEventAction(startReason);
    }
    if (reasonName == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED) {
        return PackageAddEventAction(startReason);
    }
    return true;
}

bool SandboxManagerService::CheckPermission(const uint32_t tokenId, const std::string &permission)
{
    int32_t ret = Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, permission);
    if (ret == Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Check permission token:%{public}u pass", tokenId);
        return true;
    }

    LOGE_WITH_REPORT(LABEL, "Check permission %{public}s token:%{public}u fail", permission.c_str(), tokenId);
    std::string reason = "check permission denied: " + permission;
    (void)SandboxManagerDfxHelper::ReportPolicyViolate(tokenId, reason, SG_REPORT_PERMISSION_DENIED);
    return false;
}

bool SandboxManagerService::IsFileManagerCalling(uint32_t tokenCaller)
{
    if (tokenFileManagerId_ == 0) {
        tokenFileManagerId_ = Security::AccessToken::AccessTokenKit::GetNativeTokenId(
            "file_manager_service");
    }
    if (tokenCaller != tokenFileManagerId_) {
        LOGE_WITH_REPORT(LABEL, "Check permission %{public}s token:%{public}u fail",
            FILE_ACCESS_PERMISSION_NAME.c_str(), tokenCaller);
        return false;
    }

    return true;
}

static int32_t CheckShareFileInfo(uint32_t tokenId, const std::string &bundleName)
{
    if (tokenId == 0) {
        LOGE_WITH_REPORT(LABEL, "Check tokenId failed.");
        return INVALID_PARAMTER;
    }
    if (bundleName.empty()) {
        LOGE_WITH_REPORT(LABEL, "Check bundleName failed.");
        return INVALID_PARAMTER;
    }
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerService::SetShareFileInfo(
    const std::string &cfginfo, const std::string &bundleName, uint32_t userId, uint32_t tokenId)
{
    DelayUnloadService();
    if (IPCSkeleton::GetCallingUid() != FOUNDATION_UID) {
        LOGE_WITH_REPORT(LABEL, "Not foundation userid, permision denied.");
        return PERMISSION_DENIED;
    }
    int32_t ret = CheckShareFileInfo(tokenId, bundleName);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    return SandboxManagerShare::GetInstance().SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
}

int32_t SandboxManagerService::UpdateShareFileInfo(
    const std::string &cfginfo, const std::string &bundleName, uint32_t userId, uint32_t tokenId)
{
    DelayUnloadService();
    if (IPCSkeleton::GetCallingUid() != FOUNDATION_UID) {
        LOGE_WITH_REPORT(LABEL, "Not foundation userid, permision denied.");
        return PERMISSION_DENIED;
    }
    int32_t ret = CheckShareFileInfo(tokenId, bundleName);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    return SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
}

int32_t SandboxManagerService::UnsetShareFileInfo(uint32_t tokenId, const std::string &bundleName, uint32_t userId)
{
    DelayUnloadService();
    if (IPCSkeleton::GetCallingUid() != FOUNDATION_UID) {
        LOGE_WITH_REPORT(LABEL, "Not foundation userid, permision denied.");
        return PERMISSION_DENIED;
    }
    int32_t ret = CheckShareFileInfo(tokenId, bundleName);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    return SandboxManagerShare::GetInstance().UnsetShareFileInfo(tokenId, bundleName, userId);
}

static int32_t GetOsAccountLocalIdFromUid(const int32_t callingUid)
{
    return callingUid / BASE_USER_RANGE;
}

int32_t SandboxManagerService::GetSharedDirectoryInfo(SharedDirectoryInfoVecRawData &resultRawData)
{
    DelayUnloadService();
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    if (!TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "GetSharedDirectoryInfo failed, not system app");
        return SANDBOX_MANAGER_NOT_SYS_APP;
    }
    AccessTokenID callingTokenId = fullTokenId & TOKEN_ID_LOWMASK;
    if (!CheckPermission(callingTokenId, ACCESS_SHARED_FILE_NAME)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Permission denied(tokenID=%{public}u)", callingTokenId);
        return PERMISSION_DENIED;
    }
    int32_t userId = GetOsAccountLocalIdFromUid(IPCSkeleton::GetCallingUid());

    std::vector<SharedDirectoryInfo> result;
    int32_t ret = PolicyInfoManager::GetInstance().GetSharedDirectoryInfo(result, userId);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "GetSharedDirectoryInfo failed, ret=%{public}d", ret);
        return ret;
    }

    resultRawData.Marshalling(result);
    SANDBOXMANAGER_LOG_INFO(LABEL, "GetSharedDirectoryInfo success, count=%{public}zu", result.size());
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerService::GrantSharedDirectoryPermission()
{
    DelayUnloadService();
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    if (!TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "GrantSharedDirectoryPermission failed, not system app");
        return SANDBOX_MANAGER_NOT_SYS_APP;
    }

    AccessTokenID callingTokenId = fullTokenId & TOKEN_ID_LOWMASK;
    if (!CheckPermission(callingTokenId, ACCESS_SHARED_FILE_NAME)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Permission denied(tokenID=%{public}u)", callingTokenId);
        return PERMISSION_DENIED;
    }
    int32_t userId = GetOsAccountLocalIdFromUid(IPCSkeleton::GetCallingUid());

    return PolicyInfoManager::GetInstance().GrantSharedDirectoryPermission(callingTokenId, userId);
}

int32_t SandboxManagerService::RevokeSharedDirectoryPermission()
{
    DelayUnloadService();
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    if (!TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "RevokeSharedDirectoryPermission failed, not system app");
        return SANDBOX_MANAGER_NOT_SYS_APP;
    }

    AccessTokenID callingTokenId = fullTokenId & TOKEN_ID_LOWMASK;
    if (!CheckPermission(callingTokenId, ACCESS_SHARED_FILE_NAME)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Permission denied(tokenID=%{public}u)", callingTokenId);
        return PERMISSION_DENIED;
    }
    int32_t userId = GetOsAccountLocalIdFromUid(IPCSkeleton::GetCallingUid());

    return PolicyInfoManager::GetInstance().RevokeSharedDirectoryPermission(callingTokenId, userId);
}

int32_t SandboxManagerService::KillProcessForPermissionUpdate(uint32_t accessTokenId)
{
    // Get the system ability manager
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to get system ability manager");
        return INVALID_PARAMTER;
    }

    // Get the ability manager service using the lightweight approach
    auto abilityManagerRemote = systemAbilityMgr->GetSystemAbility(ABILITY_MGR_SERVICE_ID);
    if (abilityManagerRemote == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to get ability manager service");
        return INVALID_PARAMTER;
    }

    // Create a proxy to the ability manager service
    sptr<IRemoteObject> proxy = abilityManagerRemote;
    // Prepare the data to send to the ability manager
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(u"ohos.aafwk.AbilityManager")) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write interface token failed");
        return INVALID_PARAMTER;
    }

    if (!data.WriteUint32(accessTokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write accessTokenId failed");
        return INVALID_PARAMTER;
    }

    // Call the ability manager service
    int32_t ret = proxy->SendRequest(static_cast<uint32_t>(KILL_PROCESS_FOR_PERMISSION_UPDATE),
                                     data, reply, option);
    if (ret != NO_ERROR) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "SendRequest failed, error: %{public}d", ret);
        return ret;
    }

    // Read the result
    int32_t result = reply.ReadInt32();
    return result;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
