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

#include "persistpolicytokenstub_fuzzer.h"

#include <vector>
#include <cstdint>
#include <string>
#include "alloc_token.h"
#include "fuzz_common.h"
#include "isandbox_manager.h"
#include "policy_info_vector_parcel.h"
#define private public
#include "sandbox_manager_service.h"
#undef private

using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
    bool PersistPolicyTokenStub(const uint8_t *data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

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

        PolicyInfoVectorParcel policyInfoParcel;
        policyInfoParcel.policyVector = policyVec;
        if (!datas.WriteParcelable(&policyInfoParcel)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_PERSIST_POLICY_BY_TOKEN_ID);
        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        return true;
    }

    bool PersistPolicyTokenStubFuzzTest(const uint8_t *data, size_t size)
    {
        return AllocTokenWithFuzz(data, size, PersistPolicyTokenStub);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::PersistPolicyTokenStubFuzzTest(data, size);
    return 0;
}