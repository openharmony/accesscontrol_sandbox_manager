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

#include "setpolicy_checkpolicy_appdata_fuzzer.h"

#include <vector>
#include <cstdint>
#include <string>
#include "alloc_token.h"
#include "fuzz_common.h"
#include "isandbox_manager.h"
#define private public
#include "sandbox_manager_service.h"
#undef private

using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
    // Call SetPolicy via OnRemoteRequest with appdata variants
    static bool SetPolicyAppDataStub(const std::vector<PolicyInfo>& policyVec, uint32_t tokenId,
        uint64_t policyFlag)
    {
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

    // Call CheckPolicy via OnRemoteRequest for a single policy and return the bool result
    static bool CheckPolicyAppDataStub(const PolicyInfo& policy, uint32_t tokenId)
    {
        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }
        if (!datas.WriteUint32(tokenId)) {
            return false;
        }
        std::vector<PolicyInfo> policyVec = {policy};
        PolicyVecRawData policyRawData;
        policyRawData.Marshalling(policyVec);
        if (!datas.WriteUint32(policyRawData.size)) {
            return false;
        }
        if (!datas.WriteRawData(policyRawData.data, policyRawData.size)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_CHECK_POLICY);
        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

        // Read reply: errCode (int32), [if success: size (uint32), raw data]
        int32_t errCode = 0;
        if (!reply.ReadInt32(errCode)) {
            return false;
        }
        if (errCode != SANDBOX_MANAGER_OK) {
            // CheckPolicy itself failed — treat as "not set" (false)
            return false;
        }
        uint32_t resultSize = 0;
        if (!reply.ReadUint32(resultSize)) {
            return false;
        }
        const void* rawData = reply.ReadRawData(resultSize);
        if (rawData == nullptr) {
            return false;
        }
        BoolVecRawData resultRawData;
        resultRawData.size = resultSize;
        resultRawData.RawDataCpy(rawData);
        std::vector<bool> results;
        resultRawData.Unmarshalling(results);
        if (results.empty()) {
            return false;
        }
        return results[0];
    }

    bool SetPolicyCheckPolicyAppDataFuzzTest(const uint8_t *data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        PolicyInfoRandomGenerator gen(data, size);
        uint32_t tokenId = gen.GetData<uint32_t>();
        uint64_t policyFlag = gen.GetData<uint64_t>() % 2; // 2 is flag max

        // Randomly generate 1 policy; path is /storage/Users/currentUser/ + random suffix
        std::vector<PolicyInfo> policyVec;
        PolicyInfo policy;
        policy.mode = gen.GetData<uint8_t>() % 3 + 1; // 3 modes READ/WRITE/READ+WRITE
        policy.type = PolicyType::OTHERS_PATH;

        std::string suffix;
        uint32_t suffixLen = gen.GetData<uint8_t>() % 64; // 0-63 chars
        for (uint32_t i = 0; i < suffixLen; ++i) {
            suffix += gen.GetData<char>();
        }
        policy.path = "/storage/Users/currentUser/" + suffix;

        policyVec.push_back(policy);

        SetPolicyAppDataStub(policyVec, tokenId, policyFlag);

        // appdata must never gain permission regardless of authorized path
        PolicyInfo appdataPolicy;
        appdataPolicy.path = "/storage/Users/currentUser/appdata";
        appdataPolicy.mode = OperateMode::READ_MODE;
        bool isSet = CheckPolicyAppDataStub(appdataPolicy, tokenId);
        if (isSet) {
            return false;
        }

        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AllocTokenWithFuzz(data, size, OHOS::SetPolicyCheckPolicyAppDataFuzzTest);
    return 0;
}
