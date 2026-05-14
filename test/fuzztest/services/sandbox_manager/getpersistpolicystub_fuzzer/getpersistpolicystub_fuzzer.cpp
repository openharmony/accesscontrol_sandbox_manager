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

#include "getpersistpolicystub_fuzzer.h"

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
namespace {
    enum EdgeCaseType {
        EDGE_CASE_INVALID_TOKEN = 0,
        EDGE_CASE_MAX_TOKEN,
        EDGE_CASE_SELF_TOKEN,
        EDGE_CASE_MAX
    };
    const uint8_t EDGE_CASE_TYPE_MAX = EDGE_CASE_MAX;
}
    bool GetPersistPolicyStubFuzzTest(const uint8_t *data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(uint32_t))) {
            return false;
        }

        PolicyInfoRandomGenerator gen(data, size);

        // Extract tokenId from fuzz data
        uint32_t tokenId = gen.GetData<uint32_t>();

        // Test with edge cases
        if (size > sizeof(uint32_t)) {
            uint8_t edgeCase = data[sizeof(uint32_t)] % EDGE_CASE_TYPE_MAX;
            if (edgeCase == EDGE_CASE_INVALID_TOKEN) {
                tokenId = 0;  // Test invalid tokenId
            } else if (edgeCase == EDGE_CASE_MAX_TOKEN) {
                tokenId = 0xFFFFFFFF;  // Test max tokenId
            } else if (edgeCase == EDGE_CASE_SELF_TOKEN) {
                // Use self token ID for valid test
                tokenId = GetSelfTokenID();
            }
        }

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }

        if (!datas.WriteUint32(tokenId)) {
            return false;
        }

        uint32_t code = 0xffc10;  // COMMAND_GET_PERSIST_POLICY from IDL

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
    OHOS::GetPersistPolicyStubFuzzTest(data, size);
    return 0;
}
