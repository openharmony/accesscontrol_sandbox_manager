/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "sandbox_manager_stub.h"

#include <cinttypes>
#include <cstdint>
#include <unistd.h>
#include <vector>
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "policy_info.h"
#include "policy_info_vector_parcel.h"
#include "sandbox_manager_const.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"
#include "sandbox_manager_service.h"
#include "string"
#include "string_ex.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerStub"};
}

int32_t SandboxManagerStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "code %{public}u token %{public}u", code, callingTokenID);
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != ISandboxManager::GetDescriptor()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
        return -1;
    }
    DelayUnloadService();
    auto itFunc = requestFuncMap_.find(code);
    if (itFunc != requestFuncMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            (this->*requestFunc)(data, reply);
        } else {
            // when valid code without any function to handle
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    } else {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option); // when code invalid
    }

    return NO_ERROR;
}

void SandboxManagerStub::PersistPolicyInner(MessageParcel &data, MessageParcel &reply)
{
    uint64_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, ACCESS_PERSIST_PERMISSION_NAME)) {
        reply.WriteInt32(PERMISSION_DENIED);
        return;
    }

    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager data parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    
    std::vector<uint32_t> result;
    int32_t ret = this->PersistPolicy(policyInfoVectorParcel->policyVector, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return;
    }

    if (!reply.WriteUInt32Vector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager vector parcel fail");
        return;
    }
    return;
}

void SandboxManagerStub::UnPersistPolicyInner(MessageParcel &data, MessageParcel &reply)
{
    uint64_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, ACCESS_PERSIST_PERMISSION_NAME)) {
        reply.WriteInt32(PERMISSION_DENIED);
        return;
    }

    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "read sandbox manager data parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    
    std::vector<uint32_t> result;
    
    int32_t ret = this->UnPersistPolicy(policyInfoVectorParcel->policyVector, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return;
    }

    if (!reply.WriteUInt32Vector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager vector parcel fail");
        return;
    }
    return;
}

void SandboxManagerStub::PersistPolicyByTokenIdInner(MessageParcel &data, MessageParcel &reply)
{
    uint64_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, ACCESS_PERSIST_PERMISSION_NAME)) {
        reply.WriteInt32(PERMISSION_DENIED);
        return;
    }
    uint64_t tokenId;
    if (!data.ReadUint64(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "read tokenId parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "read sandbox manager data parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    
    std::vector<uint32_t> result;
    int32_t ret = this->PersistPolicyByTokenId(tokenId, policyInfoVectorParcel->policyVector, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return;
    }

    if (!reply.WriteUInt32Vector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager vector parcel fail");
        return;
    }
    return;
}

void SandboxManagerStub::UnPersistPolicyByTokenIdInner(MessageParcel &data, MessageParcel &reply)
{
    uint64_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, ACCESS_PERSIST_PERMISSION_NAME)) {
        reply.WriteUint32(PERMISSION_DENIED);
        return;
    }
    uint64_t tokenId;
    if (!data.ReadUint64(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply tokenId parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager data parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    
    std::vector<uint32_t> result;
    
    int32_t ret = this->UnPersistPolicyByTokenId(tokenId, policyInfoVectorParcel->policyVector, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return;
    }

    if (!reply.WriteUInt32Vector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager vector parcel fail");
        return;
    }
    return;
}

void SandboxManagerStub::SetPolicyInner(MessageParcel &data, MessageParcel &reply)
{
    uint64_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, SET_POLICY_PERMISSION_NAME)) {
        reply.WriteUint32(PERMISSION_DENIED);
        return;
    }

    uint64_t tokenId;
    if (!data.ReadUint64(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply tokenId parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }

    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager data parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }

    uint64_t policyFlag;
    if (!data.ReadUint64(policyFlag)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "read policyFlag parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    
    int32_t ret = this->SetPolicy(tokenId, policyInfoVectorParcel->policyVector, policyFlag);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    return;
}

void SandboxManagerStub::StartAccessingPolicyInner(MessageParcel &data, MessageParcel &reply)
{
    uint64_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, ACCESS_PERSIST_PERMISSION_NAME)) {
        reply.WriteInt32(PERMISSION_DENIED);
        return;
    }

    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager data parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    
    std::vector<uint32_t> result;
    int32_t ret = this->StartAccessingPolicy(policyInfoVectorParcel->policyVector, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return;
    }

    if (!reply.WriteUInt32Vector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write sandbox manager reply parcel fail");
        return;
    }
    return;
}

void SandboxManagerStub::StopAccessingPolicyInner(MessageParcel &data, MessageParcel &reply)
{
    uint64_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, ACCESS_PERSIST_PERMISSION_NAME)) {
        reply.WriteInt32(PERMISSION_DENIED);
        return;
    }

    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager data parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    
    std::vector<uint32_t> result;
    
    int32_t ret = this->StopAccessingPolicy(policyInfoVectorParcel->policyVector, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return;
    }

    if (!reply.WriteUInt32Vector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write sandbox manager reply parcel fail");
        return;
    }
    return;
}

void SandboxManagerStub::CheckPersistPolicyInner(MessageParcel &data, MessageParcel &reply)
{
    uint64_t tokenId;
    if (!data.ReadUint64(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply tokenId parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }

    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager data parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }

    std::vector<bool> result;
    int32_t ret = this->CheckPersistPolicy(tokenId, policyInfoVectorParcel->policyVector, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return;
    }

    if (!reply.WriteBoolVector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write sandbox manager reply parcel fail");
        return;
    }
    return;
}

void SandboxManagerStub::SetPolicyOpFuncInMap()
{
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::PERSIST_PERMISSION)] =
        &SandboxManagerStub::PersistPolicyInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::UNPERSIST_PERMISSION)] =
        &SandboxManagerStub::UnPersistPolicyInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::PERSIST_PERMISSION_BY_TOKENID)] =
        &SandboxManagerStub::PersistPolicyByTokenIdInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::UNPERSIST_PERMISSION_BY_TOKENID)] =
        &SandboxManagerStub::UnPersistPolicyByTokenIdInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::SET_POLICY)] =
        &SandboxManagerStub::SetPolicyInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::START_ACCESSING_URI)] =
        &SandboxManagerStub::StartAccessingPolicyInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::STOP_ACCESSING_URI)] =
        &SandboxManagerStub::StopAccessingPolicyInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::CHECK_PERSIST_PERMISSION)] =
        &SandboxManagerStub::CheckPersistPolicyInner;
}

SandboxManagerStub::SandboxManagerStub()
{
    SetPolicyOpFuncInMap();
}

SandboxManagerStub::~SandboxManagerStub()
{
    requestFuncMap_.clear();
}

bool SandboxManagerStub::CheckPermission(const uint64_t tokenId, const std::string &permission)
{
    uint32_t ret = Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, permission);
    if (ret == Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Check permission token:%{public}" PRIu64" pass", tokenId);
        return true;
    }
    SANDBOXMANAGER_LOG_ERROR(LABEL, "Check permission token:%{public}" PRIu64" fail", tokenId);
    return false;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS