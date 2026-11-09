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

#include "revokepermissionbyuserstub_fuzzer.h"

#include <cstdint>
#include <vector>
#include "accesstoken_kit.h"
#include "fuzz_common.h"
#include "isandbox_manager.h"
#include "policy_vec_raw_data.h"
#define private public
#include "sandbox_manager_service.h"
#include "token_setproc.h"
#undef private

using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
    bool RevokePermissionByUserStubFuzzTest(const uint8_t *data, size_t size)
    {
        if (data == nullptr) { return false; }

        PolicyInfoRandomGenerator gen(data, size);
        uint8_t hasPermission = gen.GetData<uint8_t>() & 1;

        uint32_t selfToken = GetSelfTokenID();
        if (hasPermission) {
            uint32_t fileManagerToken = Security::AccessToken::AccessTokenKit::GetNativeTokenId("file_manager_service");
            SetSelfTokenID(fileManagerToken);
        }
        uint32_t tokenId = gen.GetData<uint32_t>();
        std::vector<PolicyInfo> policyVec;
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

        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_REVOKE_PERMISSION_BY_USER);
        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        SetSelfTokenID(selfToken);
        return true;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::RevokePermissionByUserStubFuzzTest(data, size);
    return 0;
}

