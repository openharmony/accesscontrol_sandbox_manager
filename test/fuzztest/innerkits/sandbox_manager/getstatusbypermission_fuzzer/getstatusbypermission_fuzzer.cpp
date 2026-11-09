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

#include "getstatusbypermission_fuzzer.h"

#include <cstdint>
#include <vector>
#include "alloc_token.h"
#include "fuzz_common.h"
#include "sandbox_manager_kit.h"
#include "sandbox_test_common.h"
#include "policy_info.h"

using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
    bool GetStatusByPermission(const uint8_t *data, size_t size)
    {
        if (data == nullptr) { return false; }

        PolicyInfoRandomGenerator gen(data, size);
        uint8_t hasPermission = gen.GetData<uint8_t>() & 1;
        if (hasPermission) {
            MockTokenId("file_manager_service");
        }
        std::vector<uint32_t> tokenIdList;
        uint32_t listSize = gen.GetData<uint32_t>() % 50;
        for (uint32_t i = 0; i < listSize; ++i) {
            tokenIdList.push_back(gen.GetData<uint32_t>());
        }

        std::vector<PermissionStatusInfo> result;
        SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
        return true;
    }

    bool GetStatusByPermissionFuzzTest(const uint8_t *data, size_t size)
    {
        return AllocTokenWithFuzz(data, size, GetStatusByPermission);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::GetStatusByPermissionFuzzTest(data, size);
    return 0;
}
