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

#include "activepolicybypathstub_fuzzer.h"

#include <cstdint>
#include <string>
#include "accesstoken_kit.h"
#include "fuzz_common.h"
#include "isandbox_manager.h"
#define private public
#include "sandbox_manager_service.h"
#undef private
#include "token_setproc.h"

using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
namespace {
static uint32_t selfToken = 0;
static uint32_t fileManagerToken = 0;
};

bool ActivePolicyByPathStubFuzzTest(const uint8_t *data, size_t size)
    {
        if (data == nullptr) { return false; }

        PolicyInfoRandomGenerator gen(data, size);
        uint8_t hasPermission = gen.GetData<uint8_t>() & 1;

        selfToken = GetSelfTokenID();
        if (hasPermission) {
            fileManagerToken = Security::AccessToken::AccessTokenKit::GetNativeTokenId("file_manager_service");
            SetSelfTokenID(fileManagerToken);
        }

        std::string volumeMountPath;
        gen.GenerateString(volumeMountPath);

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            SetSelfTokenID(selfToken);
            return false;
        }
        if (!datas.WriteString(volumeMountPath)) {
            SetSelfTokenID(selfToken);
            return false;
        }

        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_ACTIVE_POLICY_BY_PATH);
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
    OHOS::ActivePolicyByPathStubFuzzTest(data, size);
    return 0;
}

