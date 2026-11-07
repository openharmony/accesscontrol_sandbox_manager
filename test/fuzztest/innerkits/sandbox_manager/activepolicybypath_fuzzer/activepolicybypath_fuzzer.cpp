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

#include "activepolicybypath_fuzzer.h"

#include <cstdint>
#include <string>
#include "alloc_token.h"
#include "fuzz_common.h"
#include "sandbox_manager_kit.h"
#include "sandbox_test_common.h"

using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
    bool ActivePolicyByPath(const uint8_t *data, size_t size)
    {
        if (data == nullptr) { return false; }

        PolicyInfoRandomGenerator gen(data, size);
        uint8_t hasPermission = gen.GetData<uint8_t>() & 1;
        if (hasPermission) {
            MockTokenId("file_manager_service");
        }
        std::string volumeMountPath;
        gen.GenerateString(volumeMountPath);

        SandboxManagerKit::ActivePolicyByPath(volumeMountPath);
        return true;
    }

    bool ActivePolicyByPathFuzzTest(const uint8_t *data, size_t size)
    {
        return AllocTokenWithFuzz(data, size, ActivePolicyByPath);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ActivePolicyByPathFuzzTest(data, size);
    return 0;
}
