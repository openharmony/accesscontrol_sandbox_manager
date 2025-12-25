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

#include "setpolicybybundlenamestub_fuzzer.h"

#include <vector>
#include <cstdint>
#include <string>
#include "alloc_token.h"
#include "accesstoken_kit.h"
#include "fuzz_common.h"
#include "isandbox_manager.h"
#include "policy_info_vector_parcel.h"
#define private public
#include "sandbox_manager_service.h"
#undef private
#include "token_setproc.h"

using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
namespace {
static uint32_t SELF_TOKEN = 0;
static uint32_t FILE_MANAGER_TOKEN = 0;
};
    bool SetPolicyByBundleNameStub(const uint8_t *data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FILE_MANAGER_TOKEN = Security::AccessToken::AccessTokenKit::GetNativeTokenId(
            "file_manager_service");
        SELF_TOKEN = GetSelfTokenID();
        SetSelfTokenID(FILE_MANAGER_TOKEN);

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
        SetSelfTokenID(SELF_TOKEN);
        return true;
    }

    bool SetPolicyByBundleNameStubFuzzTest(const uint8_t *data, size_t size)
    {
        return AllocTokenWithFuzz(data, size, SetPolicyByBundleNameStub);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetPolicyByBundleNameStubFuzzTest(data, size);
    return 0;
}