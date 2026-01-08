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

#include "unsetdenypolicy_fuzzer.h"

#include <vector>
#include <cstdint>
#include <string>
#include "alloc_token.h"
#include "fuzz_common.h"
#include "sandbox_manager_kit.h"
#include "sandbox_test_common.h"
#include "token_setproc.h"

using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
    bool UnSetDenyPolicy(const uint8_t *data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        std::vector<PolicyInfo> policyVec;
        PolicyInfo policy;
        std::vector<uint32_t> result;

        PolicyInfoRandomGenerator gen(data, size);
        gen.GeneratePolicyInfo(policy);
        policyVec.push_back(policy);

        uint32_t flag = gen.GetData<uint32_t>();
        if (flag & 1) {
            SandboxManagerKit::SetDenyPolicy(GetSelfTokenID(), policyVec, result);
        }
        SandboxManagerKit::UnSetDenyPolicy(GetSelfTokenID(), policy);
        return true;
    }

    bool UnSetDenyPolicyFuzzTest(const uint8_t *data, size_t size)
    {
        MockTokenId("foundation");
        return AllocTokenWithFuzz(data, size, UnSetDenyPolicy);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::UnSetDenyPolicyFuzzTest(data, size);
    return 0;
}