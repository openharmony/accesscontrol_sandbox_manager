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

#include "cleanpersistpolicybypath_fuzzer.h"

#include <vector>
#include <cstdint>
#include <string>
#include "accesstoken_kit.h"
#include "fuzz_common.h"
#include "sandbox_manager_kit.h"
#include "token_setproc.h"

using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
namespace {
static uint32_t SELF_TOKEN = 0;
static uint32_t FILE_MANAGER_TOKEN = 0;
};
    bool CheckPersistPolicyFuzzTest(const uint8_t *data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }
        FILE_MANAGER_TOKEN = Security::AccessToken::AccessTokenKit::GetNativeTokenId(
            "file_manager_service");
        SELF_TOKEN = GetSelfTokenID();
        SetSelfTokenID(FILE_MANAGER_TOKEN);

        std::vector<std::string> pathList;
        PolicyInfoRandomGenerator gen(data, size);
        gen.GenerateStringVec(pathList);
      
        SandboxManagerKit::CleanPersistPolicyByPath(pathList);
        SetSelfTokenID(SELF_TOKEN);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::CheckPersistPolicyFuzzTest(data, size);
    return 0;
}