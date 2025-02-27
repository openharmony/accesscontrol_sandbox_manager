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

#include "sandbox_manager_proxy.h"

#include <cstddef>
#include <sstream>
#include <string>
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "message_option.h"
#include "message_parcel.h"
#include "parcel.h"
#include "policy_info_parcel.h"
#include "policy_info_vector_parcel.h"
#include "sandboxmanager_service_ipc_interface_code.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"
#include "string_ex.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE,
    ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerProxy"};
}

SandboxManagerProxy::SandboxManagerProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ISandboxManager>(impl)
{}

SandboxManagerProxy::~SandboxManagerProxy()
{}

static void MarshalPolicy(std::stringstream &ss, const std::vector<PolicyInfo> &policy)
{
    uint32_t policyNum = policy.size();
    ss.write(reinterpret_cast<const char *>(&policyNum), sizeof(policyNum));
    for (uint32_t i = 0; i < policyNum; i++) {
        uint32_t pathLen = policy[i].path.length();
        ss.write(reinterpret_cast<const char *>(&pathLen), sizeof(pathLen));
        ss.write(policy[i].path.c_str(), pathLen);
        ss.write(reinterpret_cast<const char *>(&policy[i].mode), sizeof(policy[i].mode));
    }
}
int32_t SandboxManagerProxy::SendRequest(SandboxManagerInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);
    return SendRequest(code, data, reply, option);
}

int32_t SandboxManagerProxy::SendRequest(SandboxManagerInterfaceCode code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Remote service null.");
        return SANDBOX_MANAGER_SERVICE_REMOTE_ERR;
    }
    int32_t requestResult = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (requestResult != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Request fail, result: %{public}d", requestResult);
    }
    return requestResult;
}

int32_t SandboxManagerProxy::CleanPersistPolicyByPath(const std::vector<std::string>& filePathList)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write descriptor fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (!data.WriteStringVector(filePathList)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write filePathList failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    return SendRequest(SandboxManagerInterfaceCode::CLEAN_PERSIST_POLICY_BY_PATH, data, reply, option);
}

int32_t SandboxManagerProxy::PersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write descriptor fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    std::stringstream ss;
    MarshalPolicy(ss, policy);

    if (!data.WriteUint32(ss.str().length())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write policy len failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (!data.WriteRawData(reinterpret_cast<const void *>(ss.str().data()), ss.str().length())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write raw data failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    MessageParcel reply;
    int32_t requestRet = SendRequest(SandboxManagerInterfaceCode::PERSIST_PERMISSION, data, reply);
    if (requestRet != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Remote fail");
        return requestRet;
    }

    int32_t remoteRet;
    if (!reply.ReadInt32(remoteRet)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read ret fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (remoteRet == SANDBOX_MANAGER_OK && !reply.ReadUInt32Vector(&result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read result fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return remoteRet;
}

int32_t SandboxManagerProxy::UnPersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write descriptor fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    std::stringstream ss;
    MarshalPolicy(ss, policy);

    if (!data.WriteUint32(ss.str().length())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write policy len failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (!data.WriteRawData(reinterpret_cast<const void *>(ss.str().data()), ss.str().length())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write raw data failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    
    MessageParcel reply;
    int32_t requestRet = SendRequest(SandboxManagerInterfaceCode::UNPERSIST_PERMISSION, data, reply);
    if (requestRet != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Remote fail");
        return requestRet;
    }

    int32_t remoteRet;
    if (!reply.ReadInt32(remoteRet)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read ret fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (remoteRet == SANDBOX_MANAGER_OK && !reply.ReadUInt32Vector(&result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read result fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return remoteRet;
}

int32_t SandboxManagerProxy::PersistPolicyByTokenId(
    uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write descriptor fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    if (!data.WriteUint32(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write tokenId fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    std::stringstream ss;
    MarshalPolicy(ss, policy);

    if (!data.WriteUint32(ss.str().length())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write policy len failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (!data.WriteRawData(reinterpret_cast<const void *>(ss.str().data()), ss.str().length())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write raw data failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    
    MessageParcel reply;
    int32_t requestRet = SendRequest(SandboxManagerInterfaceCode::PERSIST_PERMISSION_BY_TOKENID, data, reply);
    if (requestRet != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Remote fail");
        return requestRet;
    }

    int32_t remoteRet;
    if (!reply.ReadInt32(remoteRet)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read ret fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (remoteRet == SANDBOX_MANAGER_OK && !reply.ReadUInt32Vector(&result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read result fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return remoteRet;
}

int32_t SandboxManagerProxy::UnPersistPolicyByTokenId(
    uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write descriptor fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    if (!data.WriteUint32(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write tokenId fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    std::stringstream ss;
    MarshalPolicy(ss, policy);

    if (!data.WriteUint32(ss.str().length())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write policy len failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (!data.WriteRawData(reinterpret_cast<const void *>(ss.str().data()), ss.str().length())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write raw data failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    
    MessageParcel reply;
    int32_t requestRet = SendRequest(SandboxManagerInterfaceCode::UNPERSIST_PERMISSION_BY_TOKENID, data, reply);
    if (requestRet != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Remote fail");
        return requestRet;
    }

    int32_t remoteRet;
    if (!reply.ReadInt32(remoteRet)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read ret fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (remoteRet == SANDBOX_MANAGER_OK && !reply.ReadUInt32Vector(&result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read result fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return remoteRet;
}

static bool WriteSetPolicyParcel(MessageParcel &data, uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                 uint64_t policyFlag, uint64_t timestamp)
{
    if (!data.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write descriptor failed.");
        return false;
    }
    if (!data.WriteUint32(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write tokenId failed.");
        return false;
    }
    if (!data.WriteUint64(timestamp)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write timestamp failed.");
        return false;
    }

    std::stringstream ss;
    MarshalPolicy(ss, policy);

    if (!data.WriteUint32(ss.str().length())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write policy len failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (!data.WriteRawData(reinterpret_cast<const void *>(ss.str().data()), ss.str().length())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write raw data failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (!data.WriteUint64(policyFlag)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write policyFlag failed.");
        return false;
    }
    return true;
}

int32_t SandboxManagerProxy::SetPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                       uint64_t policyFlag, std::vector<uint32_t> &result, uint64_t timestamp)
{
    MessageParcel data;
    if (!WriteSetPolicyParcel(data, tokenId, policy, policyFlag, timestamp)) {
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    MessageParcel reply;
    int32_t requestRet = SendRequest(SandboxManagerInterfaceCode::SET_POLICY, data, reply);
    if (requestRet != SANDBOX_MANAGER_OK) {
        return requestRet;
    }

    int32_t remoteRet;
    if (!reply.ReadInt32(remoteRet)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read ret failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    result.clear();
    if (remoteRet != SANDBOX_MANAGER_OK) {
        return remoteRet;
    }
    if (!reply.ReadUInt32Vector(&result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read result failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return remoteRet;
}

int32_t SandboxManagerProxy::SetPolicyAsync(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                            uint64_t policyFlag, uint64_t timestamp)
{
    MessageParcel data;
    if (!WriteSetPolicyParcel(data, tokenId, policy, policyFlag, timestamp)) {
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    return SendRequest(SandboxManagerInterfaceCode::SET_POLICY_ASYNC, data, reply, option);
}

static bool WriteUnSetPolicyParcel(MessageParcel &data, uint32_t tokenId, const PolicyInfo &policy)
{
    if (!data.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write descriptor failed.");
        return false;
    }
    if (!data.WriteUint32(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write tokenId failed.");
        return false;
    }

    PolicyInfoParcel policyInfoParcel;
    policyInfoParcel.policyInfo = policy;
    if (!data.WriteParcelable(&policyInfoParcel)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write policyInfoParcel failed.");
        return false;
    }
    return true;
}

int32_t SandboxManagerProxy::UnSetPolicy(uint32_t tokenId, const PolicyInfo &policy)
{
    MessageParcel data;
    if (!WriteUnSetPolicyParcel(data, tokenId, policy)) {
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    MessageParcel reply;
    int32_t requestRet = SendRequest(SandboxManagerInterfaceCode::UNSET_POLICY, data, reply);
    if (requestRet != SANDBOX_MANAGER_OK) {
        return requestRet;
    }

    int32_t remoteRet;
    if (!reply.ReadInt32(remoteRet)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read ret failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return remoteRet;
}

int32_t SandboxManagerProxy::UnSetPolicyAsync(uint32_t tokenId, const PolicyInfo &policy)
{
    MessageParcel data;
    if (!WriteUnSetPolicyParcel(data, tokenId, policy)) {
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    return SendRequest(SandboxManagerInterfaceCode::UNSET_POLICY_ASYNC, data, reply, option);
}

int32_t SandboxManagerProxy::CheckPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
    std::vector<bool> &result)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write descriptor failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    if (!data.WriteUint32(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write tokenId failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    std::stringstream ss;
    MarshalPolicy(ss, policy);

    if (!data.WriteUint32(ss.str().length())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write policy len failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (!data.WriteRawData(reinterpret_cast<const void *>(ss.str().data()), ss.str().length())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write raw data failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    MessageParcel reply;
    int32_t requestRet = SendRequest(SandboxManagerInterfaceCode::CHECK_POLICY, data, reply);
    if (requestRet != SANDBOX_MANAGER_OK) {
        return requestRet;
    }

    int32_t remoteRet;
    if (!reply.ReadInt32(remoteRet)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read ret failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    result.clear();
    if (remoteRet != SANDBOX_MANAGER_OK) {
        return remoteRet;
    }
    if (!reply.ReadBoolVector(&result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read result failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return remoteRet;
}

int32_t SandboxManagerProxy::StartAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result,
    bool useCallerToken, uint32_t tokenId, uint64_t timestamp)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write descriptor fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (!data.WriteBool(useCallerToken)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write useCallerToken failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (!data.WriteUint32(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write tokenId failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (!data.WriteUint64(timestamp)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write timestamp failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    std::stringstream ss;
    MarshalPolicy(ss, policy);

    if (!data.WriteUint32(ss.str().length())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write policy len failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (!data.WriteRawData(reinterpret_cast<const void *>(ss.str().data()), ss.str().length())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write raw data failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    
    MessageParcel reply;
    int32_t requestRet = SendRequest(SandboxManagerInterfaceCode::START_ACCESSING_URI, data, reply);
    if (requestRet != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Remote fail");
        return requestRet;
    }

    int32_t remoteRet;
    if (!reply.ReadInt32(remoteRet)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read ret fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (remoteRet == SANDBOX_MANAGER_OK && !reply.ReadUInt32Vector(&result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read result fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return remoteRet;
}

int32_t SandboxManagerProxy::StopAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write descriptor fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    std::stringstream ss;
    MarshalPolicy(ss, policy);

    if (!data.WriteUint32(ss.str().length())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write policy len failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (!data.WriteRawData(reinterpret_cast<const void *>(ss.str().data()), ss.str().length())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write raw data failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    MessageParcel reply;
    int32_t requestRet = SendRequest(SandboxManagerInterfaceCode::STOP_ACCESSING_URI, data, reply);
    if (requestRet != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Remote fail");
        return requestRet;
    }

    int32_t remoteRet;
    if (!reply.ReadInt32(remoteRet)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read ret fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (remoteRet == SANDBOX_MANAGER_OK && !reply.ReadUInt32Vector(&result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read result fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return remoteRet;
}

int32_t SandboxManagerProxy::CheckPersistPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
    std::vector<bool> &result)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write descriptor fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    if (!data.WriteUint32(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write tokenId fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    
    std::stringstream ss;
    MarshalPolicy(ss, policy);

    if (!data.WriteUint32(ss.str().length())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write policy len failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (!data.WriteRawData(reinterpret_cast<const void *>(ss.str().data()), ss.str().length())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write raw data failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    MessageParcel reply;
    int32_t requestRet = SendRequest(SandboxManagerInterfaceCode::CHECK_PERSIST_PERMISSION, data, reply);
    if (requestRet != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Remote fail");
        return requestRet;
    }

    int32_t remoteRet;
    if (!reply.ReadInt32(remoteRet)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read ret fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (remoteRet == SANDBOX_MANAGER_OK && !reply.ReadBoolVector(&result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read result fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return remoteRet;
}

int32_t SandboxManagerProxy::StartAccessingByTokenId(uint32_t tokenId, uint64_t timestamp)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write descriptor fail.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    if (!data.WriteUint32(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write tokenId fail.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (!data.WriteUint64(timestamp)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write timestamp fail.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    int32_t requestRet = SendRequest(SandboxManagerInterfaceCode::START_ACCESSING_BY_TOKEN, data, reply, option);
    if (requestRet != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Remote fail, requestRet = %{public}d.", requestRet);
        return SANDBOX_MANAGER_SERVICE_REMOTE_ERR;
    }
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerProxy::UnSetAllPolicyByToken(uint32_t tokenId, uint64_t timestamp)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write descriptor fail.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    if (!data.WriteUint32(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write tokenId fail.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (!data.WriteUint64(timestamp)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write timestamp failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    int32_t requestRet = SendRequest(SandboxManagerInterfaceCode::UNSET_ALL_POLICY_BY_TOKEN, data, reply, option);
    if (requestRet != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Remote fail, requestRet = %{public}d.", requestRet);
        return SANDBOX_MANAGER_SERVICE_REMOTE_ERR;
    }
    return SANDBOX_MANAGER_OK;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS