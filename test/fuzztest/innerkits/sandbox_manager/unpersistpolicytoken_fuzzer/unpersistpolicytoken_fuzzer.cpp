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

#include "unpersistpolicytoken_fuzzer.h"

#include <vector>
#include <cstdint>
#include <string>
#include "alloc_token.h"
#include "fuzz_common.h"
#include "sandbox_manager_kit.h"

using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
    bool UnPersistPolicyToken(const uint8_t *data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        std::vector<PolicyInfo> policyVec;
        std::vector<uint32_t> result;
        PolicyInfoRandomGenerator gen(data, size);
        gen.GeneratePolicyInfoVec(policyVec);
        uint32_t tokenId = gen.GetData<uint32_t>();

        SandboxManagerKit::SetPolicy(tokenId, policyVec, 1, result);
        SandboxManagerKit::PersistPolicy(tokenId, policyVec, result);
        SandboxManagerKit::UnPersistPolicy(tokenId, policyVec, result);
        return true;
    }

    bool UnPersistPolicyTokenFuzzTest(const uint8_t *data, size_t size)
    {
        return AllocTokenWithFuzz(data, size, UnPersistPolicyToken);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::UnPersistPolicyTokenFuzzTest(data, size);
    return 0;
}