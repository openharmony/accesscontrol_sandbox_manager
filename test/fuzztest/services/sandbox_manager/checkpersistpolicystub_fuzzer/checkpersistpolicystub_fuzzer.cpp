/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "checkpersistpolicystub_fuzzer.h"

#include <vector>
#include <cstdint>
#include <string>
#include "fuzz_common.h"
#include "isandbox_manager.h"
#include "policy_info_vector_parcel.h"
#define private public
#include "sandbox_manager_service.h"
#undef private
#include "accesstoken_kit.h"
#include "sandbox_manager_kit.h"
#include "token_setproc.h"

using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
    bool CheckPersistPolicyStubFuzzTest(const uint8_t *data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

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

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::CheckPersistPolicyStubFuzzTest(data, size);
    return 0;
}