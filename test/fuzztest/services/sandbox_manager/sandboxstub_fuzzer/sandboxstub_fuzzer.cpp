/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "sandboxstub_fuzzer.h"

#include <vector>
#include <cstdint>
#include <string>
#include "alloc_token.h"
#include "fuzz_common.h"
#include "isandbox_manager.h"
#include "policy_info_parcel.h"
#define private public
#include "sandbox_manager_service.h"
#undef private
#include "accesstoken_kit.h"
#include "policy_info_vector_parcel.h"
#include "sandbox_manager_kit.h"
#include "token_setproc.h"


using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
namespace {
const int32_t SPACE_MGR_SERVICE_UID = 7013;
const int32_t FOUNDATION_UID = 5523;
};
    bool UnsetPolicyStub(const uint8_t *data, size_t size)
    {
        PolicyInfoRandomGenerator gen(data, size);
        uint32_t tokenid = gen.GetData<uint32_t>();

        PolicyInfo policy;
        gen.GeneratePolicyInfo(policy);

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }
        if (!datas.WriteUint32(tokenid)) {
            return false;
        }
        PolicyInfoParcel policyInfoParcel;
        policyInfoParcel.policyInfo = policy;
        if (!datas.WriteParcelable(&policyInfoParcel)) {
            return false;
        }
            
        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_UN_SET_POLICY);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        return true;
    }

    bool UnsetPolicyStubFuzzTest(const uint8_t *data, size_t size)
    {
        return AllocTokenWithFuzz(data, size, UnsetPolicyStub);
    }

    bool UnsetPolicyAsyncStub(const uint8_t *data, size_t size)
    {
        PolicyInfoRandomGenerator gen(data, size);
        uint32_t tokenid = gen.GetData<uint32_t>();

        PolicyInfo policy;
        gen.GeneratePolicyInfo(policy);

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }
        if (!datas.WriteUint32(tokenid)) {
            return false;
        }
        PolicyInfoParcel policyInfoParcel;
        policyInfoParcel.policyInfo = policy;
        if (!datas.WriteParcelable(&policyInfoParcel)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_UN_SET_POLICY_ASYNC);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        return true;
    }

    bool UnsetPolicyAsyncStubFuzzTest(const uint8_t *data, size_t size)
    {
        return AllocTokenWithFuzz(data, size, UnsetPolicyAsyncStub);
    }

    bool UnsetDenyPolicyStub(const uint8_t *data, size_t size)
    {
        int32_t uid = getuid();
        setuid(SPACE_MGR_SERVICE_UID);
        PolicyInfoRandomGenerator gen(data, size);
        uint32_t tokenid = gen.GetData<uint32_t>();

        PolicyInfo policy;
        gen.GeneratePolicyInfo(policy);

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }
        if (!datas.WriteUint32(tokenid)) {
            return false;
        }
        PolicyInfoParcel policyInfoParcel;
        policyInfoParcel.policyInfo = policy;
        if (!datas.WriteParcelable(&policyInfoParcel)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_UN_SET_DENY_POLICY);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        setuid(uid);
        return true;
    }

    bool UnsetDenyPolicyStubFuzzTest(const uint8_t *data, size_t size)
    {
        return AllocTokenWithFuzz(data, size, UnsetDenyPolicyStub);
    }

    bool UnsetAllPolicyByTokenStub(const uint8_t *data, size_t size)
    {
        PolicyInfoRandomGenerator gen(data, size);
        uint32_t tokenid = gen.GetData<uint32_t>();

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }
        if (!datas.WriteUint32(tokenid)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_UN_SET_ALL_POLICY_BY_TOKEN);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        return true;
    }

    bool UnsetAllPolicyByTokenFuzzTest(const uint8_t *data, size_t size)
    {
        return AllocTokenWithFuzz(data, size, UnsetAllPolicyByTokenStub);
    }

    bool UnPersistPolicyToken(const uint8_t *data, size_t size)
    {
        static uint32_t g_selfToken = 0;
        static uint32_t g_file_manager_token = 0;

        g_file_manager_token = Security::AccessToken::AccessTokenKit::GetNativeTokenId(
            "file_manager_service");
        g_selfToken = GetSelfTokenID();
        SetSelfTokenID(g_file_manager_token);
        std::vector<PolicyInfo> policyVec;
        std::vector<uint32_t> result;
        PolicyInfoRandomGenerator gen(data, size);
        uint32_t tokenId = gen.GetData<uint32_t>();
        gen.GeneratePolicyInfoVec(policyVec);

        PolicyVecRawData policyRawData;
        policyRawData.Marshalling(policyVec);
        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }

        if (!datas.WriteUint32(tokenId)) {
            return false;
        }

        if (!datas.WriteUint32(policyRawData.size)) {
            return false;
        }

        if (!datas.WriteRawData(policyRawData.data, policyRawData.size)) {
            return false;
        }
        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_UN_PERSIST_POLICY_BY_TOKEN_ID);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        SetSelfTokenID(g_selfToken);
        return true;
    }

    bool UnPersistPolicyTokenFuzzTest(const uint8_t *data, size_t size)
    {
        return AllocTokenWithFuzz(data, size, UnPersistPolicyToken);
    }

    bool UnpersistPolicyStub(const uint8_t *data, size_t size)
    {
        std::vector<PolicyInfo> policyVec;
        std::vector<uint32_t> result;
        PolicyInfoRandomGenerator gen(data, size);
        gen.GeneratePolicyInfoVec(policyVec);

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }

        PolicyVecRawData policyRawData;
        policyRawData.Marshalling(policyVec);
        if (!datas.WriteUint32(policyRawData.size)) {
            return false;
        }

        if (!datas.WriteRawData(policyRawData.data, policyRawData.size)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_UN_PERSIST_POLICY);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

        return true;
    }

    bool UnpersistPolicyStubFuzzTest(const uint8_t *data, size_t size)
    {
        return AllocTokenWithFuzz(data, size, UnpersistPolicyStub);
    }

    bool StopAccessingPolicyStub(const uint8_t *data, size_t size)
    {
        std::vector<PolicyInfo> policyVec;
        std::vector<uint32_t> result;
        PolicyInfoRandomGenerator gen(data, size);
        gen.GeneratePolicyInfoVec(policyVec);

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }

        PolicyVecRawData policyRawData;
        policyRawData.Marshalling(policyVec);
        if (!datas.WriteUint32(policyRawData.size)) {
            return false;
        }

        if (!datas.WriteRawData(policyRawData.data, policyRawData.size)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_STOP_ACCESSING_POLICY);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

        return true;
    }

    bool StopAccessingPolicyStubFuzzTest(const uint8_t *data, size_t size)
    {
        return AllocTokenWithFuzz(data, size, StopAccessingPolicyStub);
    }

    bool StartByEventActionFuzzTest(const uint8_t *data, size_t size)
    {
        PolicyInfoRandomGenerator gen(data, size);
        std::string name;
        std::string name1;
        std::string name2;
        gen.GenerateString(name);
        gen.GenerateString(name1);
        gen.GenerateString(name2);

        SystemAbilityOnDemandReason startReason;
        startReason.SetName(name.c_str());
        DelayedSingleton<SandboxManagerService>::GetInstance()->StartByEventAction(startReason);

        std::map<std::string, std::string> want = {{name1.c_str(), name2.c_str()}};
        OnDemandReasonExtraData extraData2(0, "test", want);
        startReason.SetExtraData(extraData2);
        DelayedSingleton<SandboxManagerService>::GetInstance()->StartByEventAction(startReason);
        return true;
    }

    bool StartAccessingPolicyStub(const uint8_t *data, size_t size)
    {
        std::vector<PolicyInfo> policyVec;
        std::vector<uint32_t> result;
        PolicyInfoRandomGenerator gen(data, size);
        gen.GeneratePolicyInfoVec(policyVec);
        uint32_t tokenId = GetSelfTokenID();

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }

        PolicyVecRawData policyRawData;
        policyRawData.Marshalling(policyVec);
        if (!datas.WriteUint32(policyRawData.size)) {
            return false;
        }

        if (!datas.WriteRawData(policyRawData.data, policyRawData.size)) {
            return false;
        }

        uint32_t useCallerToken = gen.GetData<uint32_t>();
        if (!datas.WriteUint32(useCallerToken)) {
            return false;
        }

        if (!datas.WriteUint32(tokenId)) {
            return false;
        }

        uint32_t timestamp = gen.GetData<uint64_t>();
        if (!datas.WriteUint64(timestamp)) {
            return false;
        }
        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_START_ACCESSING_POLICY);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

        return true;
    }

    bool StartAccessingPolicyStubFuzzTest(const uint8_t *data, size_t size)
    {
        return AllocTokenWithFuzz(data, size, StartAccessingPolicyStub);
    }

    bool StartAccessingByTokenidStubFuzzTest(const uint8_t *data, size_t size)
    {
        int32_t uid = getuid();
        setuid(FOUNDATION_UID);
        PolicyInfoRandomGenerator gen(data, size);
        uint32_t tokenid = gen.GetData<uint32_t>();

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }
        if (!datas.WriteUint32(tokenid)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_START_ACCESSING_BY_TOKEN_ID);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        setuid(uid);
        return true;
    }

    bool SetPolicyStub(const uint8_t *data, size_t size)
    {
        std::vector<PolicyInfo> policyVec;
        PolicyInfoRandomGenerator gen(data, size);
        uint32_t tokenId = gen.GetData<uint32_t>();
        uint64_t policyFlag = gen.GetData<uint64_t>() % 2; // 2 is flag max

        gen.GeneratePolicyInfoVec(policyVec);

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }

        if (!datas.WriteUint32(tokenId)) {
            return false;
        }

        PolicyVecRawData policyRawData;
        policyRawData.Marshalling(policyVec);
        if (!datas.WriteUint32(policyRawData.size)) {
            return false;
        }

        if (!datas.WriteRawData(policyRawData.data, policyRawData.size)) {
            return false;
        }

        if (!datas.WriteUint64(policyFlag)) {
            return false;
        }

        SetInfoParcel setInfoParcel;
        SetInfo setInfo;
        setInfoParcel.setInfo = setInfo;
        if (!datas.WriteParcelable(&setInfoParcel)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_SET_POLICY);
        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        return true;
    }

    bool SetPolicyStubFuzzTest(const uint8_t *data, size_t size)
    {
        return AllocTokenWithFuzz(data, size, SetPolicyStub);
    }

    bool SetPolicyByBundleNameStub(const uint8_t *data, size_t size)
    {
        std::vector<PolicyInfo> policyVec;
        std::string name;
        PolicyInfoRandomGenerator gen(data, size);

        uint64_t policyFlag = gen.GetData<uint64_t>() % 2; // 2 is flag max
        int32_t appCloneIndex = gen.GetData<int32_t>();
        gen.GenerateString(name);
        gen.GeneratePolicyInfoVec(policyVec);

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }

        if (!datas.WriteString16(Str8ToStr16(name))) {
            return false;
        }

        if (!datas.WriteInt32(appCloneIndex)) {
            return false;
        }

        PolicyVecRawData policyRawData;
        policyRawData.Marshalling(policyVec);
        if (!datas.WriteUint32(policyRawData.size)) {
            return false;
        }

        if (!datas.WriteRawData(policyRawData.data, policyRawData.size)) {
            return false;
        }

        if (!datas.WriteUint64(policyFlag)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_SET_POLICY_BY_BUNDLE_NAME);
        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        return true;
    }

    bool SetPolicyByBundleNameStubFuzzTest(const uint8_t *data, size_t size)
    {
        return AllocTokenWithFuzz(data, size, SetPolicyByBundleNameStub);
    }

    bool SetPolicyAsyncStub(const uint8_t *data, size_t size)
    {
        std::vector<PolicyInfo> policyVec;
        PolicyInfoRandomGenerator gen(data, size);
        uint32_t tokenId = gen.GetData<uint32_t>();
        uint64_t policyFlag = gen.GetData<uint64_t>() % 2; // 2 is flag max

        gen.GeneratePolicyInfoVec(policyVec);

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }

        if (!datas.WriteUint32(tokenId)) {
            return false;
        }

        PolicyInfoVectorParcel policyInfoParcel;
        policyInfoParcel.policyVector = policyVec;
        if (!datas.WriteParcelable(&policyInfoParcel)) {
            return false;
        }

        if (!datas.WriteUint64(policyFlag)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_SET_POLICY_ASYNC);
        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        return true;
    }

    bool SetPolicyAsyncStubFuzzTest(const uint8_t *data, size_t size)
    {
        return AllocTokenWithFuzz(data, size, SetPolicyAsyncStub);
    }

    bool SetDenyPolicyStub(const uint8_t *data, size_t size)
    {
        int32_t uid = getuid();
        setuid(SPACE_MGR_SERVICE_UID);
        std::vector<PolicyInfo> policyVec;
        PolicyInfoRandomGenerator gen(data, size);
        uint32_t tokenId = gen.GetData<uint32_t>();
        uint64_t policyFlag = gen.GetData<uint64_t>() % 2; // 2 is flag max

        gen.GeneratePolicyInfoVec(policyVec);

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }

        if (!datas.WriteUint32(tokenId)) {
            return false;
        }

        PolicyVecRawData policyRawData;
        policyRawData.Marshalling(policyVec);
        if (!datas.WriteUint32(policyRawData.size)) {
            return false;
        }

        if (!datas.WriteRawData(policyRawData.data, policyRawData.size)) {
            return false;
        }

        if (!datas.WriteUint64(policyFlag)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_SET_DENY_POLICY);
        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        setuid(uid);
        return true;
    }

    bool SetDenyPolicyStubFuzzTest(const uint8_t *data, size_t size)
    {
        return AllocTokenWithFuzz(data, size, SetDenyPolicyStub);
    }

    bool PersistPolicyTokenStub(const uint8_t *data, size_t size)
    {
        int32_t uid = getuid();
        setuid(FOUNDATION_UID);
        std::vector<PolicyInfo> policyVec;
        std::vector<uint32_t> result;
        PolicyInfoRandomGenerator gen(data, size);
        uint32_t tokenId = gen.GetData<uint32_t>();

        gen.GeneratePolicyInfoVec(policyVec);

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }

        if (!datas.WriteUint32(tokenId)) {
            return false;
        }

        PolicyVecRawData policyRawData;
        policyRawData.Marshalling(policyVec);
        if (!datas.WriteUint32(policyRawData.size)) {
            return false;
        }

        if (!datas.WriteRawData(policyRawData.data, policyRawData.size)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_PERSIST_POLICY_BY_TOKEN_ID);
        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        setuid(uid);
        return true;
    }

    bool PersistPolicyTokenStubFuzzTest(const uint8_t *data, size_t size)
    {
        return AllocTokenWithFuzz(data, size, PersistPolicyTokenStub);
    }

    bool PersistPolicyStub(const uint8_t *data, size_t size)
    {
        std::vector<PolicyInfo> policyVec;
        std::vector<uint32_t> result;
        PolicyInfoRandomGenerator gen(data, size);

        gen.GeneratePolicyInfoVec(policyVec);

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }

        PolicyVecRawData policyRawData;
        policyRawData.Marshalling(policyVec);
        if (!datas.WriteUint32(policyRawData.size)) {
            return false;
        }

        if (!datas.WriteRawData(policyRawData.data, policyRawData.size)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_PERSIST_POLICY);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

        return true;
    }

    bool PersistPolicyStubFuzzTest(const uint8_t *data, size_t size)
    {
        return AllocTokenWithFuzz(data, size, PersistPolicyStub);
    }

    bool CleanPolicyByUserIdStubFuzzTest(const uint8_t *data, size_t size)
    {
        static uint32_t SELF_TOKEN = 0;
        static uint32_t FILE_MANAGER_TOKEN = 0;

        FILE_MANAGER_TOKEN = Security::AccessToken::AccessTokenKit::GetNativeTokenId(
            "file_manager_service");
        SELF_TOKEN = GetSelfTokenID();
        SetSelfTokenID(FILE_MANAGER_TOKEN);

        std::vector<std::string> pathList;
        PolicyInfoRandomGenerator gen(data, size);
        uint32_t userId = gen.GetData<uint32_t>();
        gen.GenerateStringVec(pathList);

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }

        if (!datas.WriteUint32(userId)) {
            return false;
        }

        if (!datas.WriteStringVector(pathList)) {
            return false;
        }

        // for test all branch, need write something in rdb
        uint8_t isWriteRdb = gen.GetData<uint8_t>();
        if (isWriteRdb & 1) {
            std::vector<PolicyInfo> policy;
            uint64_t policyFlag = 1;
            std::vector<uint32_t> policyResult;
            PolicyInfo infoParent = {
                .path = "/A/B",
                .mode = OperateMode::READ_MODE
            };
            policy.emplace_back(infoParent);
            SandboxManagerKit::SetPolicy(GetSelfTokenID(), policy, policyFlag, policyResult);
            SandboxManagerKit::PersistPolicy(policy, policyResult);
        }
        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_CLEAN_POLICY_BY_USER_ID);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        SetSelfTokenID(SELF_TOKEN);
        return true;
    }

    bool CleanPersistPolicyByPathStubFuzzTest(const uint8_t *data, size_t size)
    {
        static uint32_t SELF_TOKEN = 0;
        static uint32_t FILE_MANAGER_TOKEN = 0;
        FILE_MANAGER_TOKEN = Security::AccessToken::AccessTokenKit::GetNativeTokenId(
            "file_manager_service");
        SELF_TOKEN = GetSelfTokenID();
        SetSelfTokenID(FILE_MANAGER_TOKEN);

        std::vector<std::string> pathList;
        PolicyInfoRandomGenerator gen(data, size);
        gen.GenerateStringVec(pathList);

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }

        if (!datas.WriteStringVector(pathList)) {
            return false;
        }

        // for test all branch, need write something in rdb
        uint8_t isWriteRdb = gen.GetData<uint8_t>();
        if (isWriteRdb & 1) {
            std::vector<PolicyInfo> policy;
            uint64_t policyFlag = 1;
            std::vector<uint32_t> policyResult;
            PolicyInfo infoParent = {
                .path = "/A/B",
                .mode = OperateMode::READ_MODE
            };
            policy.emplace_back(infoParent);
            SandboxManagerKit::SetPolicy(GetSelfTokenID(), policy, policyFlag, policyResult);
            SandboxManagerKit::PersistPolicy(policy, policyResult);
        }
        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_CLEAN_PERSIST_POLICY_BY_PATH);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        SetSelfTokenID(SELF_TOKEN);
        return true;
    }

    bool CheckPolicyStubFuzzTest(const uint8_t *data, size_t size)
    {
        std::vector<PolicyInfo> policyVec;
        PolicyInfoRandomGenerator gen(data, size);
        uint32_t tokenId = GetSelfTokenID();
        gen.GeneratePolicyInfoVec(policyVec);

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }

        PolicyVecRawData policyRawData;
        policyRawData.Marshalling(policyVec);
        if (!datas.WriteUint32(tokenId)) {
            return false;
        }

        if (!datas.WriteUint32(policyRawData.size)) {
            return false;
        }

        if (!datas.WriteRawData(policyRawData.data, policyRawData.size)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_CHECK_POLICY);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        return true;
    }

    bool CheckPersistPolicyStubFuzzTest(const uint8_t *data, size_t size)
    {
        std::vector<PolicyInfo> policyVec;
        std::vector<bool> result;
        PolicyInfoRandomGenerator gen(data, size);
        uint32_t tokenId = GetSelfTokenID();
        gen.GeneratePolicyInfoVec(policyVec);

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }

        PolicyVecRawData policyRawData;
        policyRawData.Marshalling(policyVec);
        if (!datas.WriteUint32(tokenId)) {
            return false;
        }

        if (!datas.WriteUint32(policyRawData.size)) {
            return false;
        }

        if (!datas.WriteRawData(policyRawData.data, policyRawData.size)) {
            return false;
        }

        // for test all branch, need write something in rdb
        uint8_t isWriteRdb = gen.GetData<uint8_t>();
        if (isWriteRdb & 1) {
            uint64_t policyFlag = 1;
            std::vector<uint32_t> policyResult;
            SandboxManagerKit::SetPolicy(tokenId, policyVec, policyFlag, policyResult);
            SandboxManagerKit::PersistPolicy(policyVec, policyResult);
        }

        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_CHECK_PERSIST_POLICY);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        return true;
    }
}

const uint32_t TEST_FUNS_NUM = 20;
/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    // use first uint8 to switch fun
    const uint8_t *data_new = data + 1;
    size_t size_new = size - 1;
    if ((data_new == nullptr) || (size_new == 0)) {
        return false;
    }

    uint8_t code = data[0] % TEST_FUNS_NUM;
    switch(code) {
        case 0: {
            OHOS::UnsetPolicyStubFuzzTest(data_new, size_new);
            break;
        }
        case 1: {
            OHOS::UnsetPolicyAsyncStubFuzzTest(data_new, size_new);
            break;
        }
        case 2: {
            OHOS::UnsetDenyPolicyStubFuzzTest(data_new, size_new);
            break;
        }
        case 3: {
            OHOS::UnsetAllPolicyByTokenFuzzTest(data_new, size_new);
            break;
        }
        case 4: {
            OHOS::UnPersistPolicyTokenFuzzTest(data_new, size_new);
            break;
        }
        case 5: {
            OHOS::UnpersistPolicyStubFuzzTest(data_new, size_new);
            break;
        }
        case 6: {
            OHOS::StopAccessingPolicyStubFuzzTest(data_new, size_new);
            break;
        }
        case 7: {
            OHOS::StartByEventActionFuzzTest(data_new, size_new);
            break;
        }
        case 8: {
            OHOS::StartAccessingPolicyStubFuzzTest(data_new, size_new);
            break;
        }
        case 9: {
            OHOS::StartAccessingByTokenidStubFuzzTest(data_new, size_new);
            break;
        }
        case 10: {
            OHOS::SetPolicyStubFuzzTest(data_new, size_new);
            break;
        }
        case 11: {
            OHOS::SetPolicyByBundleNameStubFuzzTest(data_new, size_new);
            break;
        }
        case 12: {
            OHOS::SetPolicyAsyncStubFuzzTest(data_new, size_new);
            break;
        }
        case 13: {
            OHOS::SetDenyPolicyStubFuzzTest(data_new, size_new);
            break;
        }
        case 14: {
            OHOS::PersistPolicyTokenStubFuzzTest(data_new, size_new);
            break;
        }
        case 15: {
            OHOS::PersistPolicyStubFuzzTest(data_new, size_new);
            break;
        }
        case 16: {
            OHOS::CleanPolicyByUserIdStubFuzzTest(data_new, size_new);
            break;
        }
        case 17: {
            OHOS::CleanPersistPolicyByPathStubFuzzTest(data_new, size_new);
            break;
        }
        case 18: {
            OHOS::CheckPolicyStubFuzzTest(data_new, size_new);
            break;
        }
        case 19: {
            OHOS::CheckPersistPolicyStubFuzzTest(data_new, size_new);
            break;
        }
        default: {
            break;
        }
    }

    return 0;
}