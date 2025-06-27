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

#include "startbyeventaction_fuzzer.h"

#include <vector>
#include <cstdint>
#include <string>
#include "alloc_token.h"
#include "fuzz_common.h"
#include "isandbox_manager.h"
#include "policy_info_parcel.h"
#define private public
#include "sandbox_manager_service.h"
#undef private

using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
    bool StartByEventActionFuzzTest(const uint8_t *data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }
        PolicyInfoRandomGenerator gen(data, size);
        std::string name;
        std::string name1;
        std::string name2;
        gen.GenerateString(name);
        gen.GenerateString(name1);
        gen.GenerateString(name2);

        SystemAbilityOnDemandReason startReason;
        startReason.SetName(name.c_str());
        DelayedSingleton<SandboxManagerService>::GetInstance()->StartByEventAction(startReason);

        std::map<std::string, std::string> want = {{name1.c_str(), name2.c_str()}};
        OnDemandReasonExtraData extraData2(0, "test", want);
        startReason.SetExtraData(extraData2);
        DelayedSingleton<SandboxManagerService>::GetInstance()->StartByEventAction(startReason);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::StartByEventActionFuzzTest(data, size);
    return 0;
}