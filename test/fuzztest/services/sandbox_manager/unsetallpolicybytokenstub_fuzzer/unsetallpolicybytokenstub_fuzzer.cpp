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

#include "unsetallpolicybytokenstub_fuzzer.h"

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
    bool UnsetAllPolicyByTokenStub(const uint8_t *data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }
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
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::UnsetAllPolicyByTokenFuzzTest(data, size);
    return 0;
}