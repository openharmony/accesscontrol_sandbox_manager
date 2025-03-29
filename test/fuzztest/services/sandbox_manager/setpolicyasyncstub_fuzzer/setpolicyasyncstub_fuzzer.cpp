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

#include "setpolicyasyncstub_fuzzer.h"

#include <vector>
#include <cstdint>
#include <string>
#include "alloc_token.h"
#include "fuzz_common.h"
#include "policy_info_vector_parcel.h"
#include "isandbox_manager.h"
#define private public
#include "sandbox_manager_service.h"
#undef private

using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
    bool SetPolicyAsyncStub(const uint8_t *data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

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
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetPolicyAsyncStubFuzzTest(data, size);
    return 0;
}