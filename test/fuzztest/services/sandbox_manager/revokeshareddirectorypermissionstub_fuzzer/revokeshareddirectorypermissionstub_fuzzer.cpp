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

#include "revokeshareddirectorypermissionstub_fuzzer.h"

#include <vector>
#include <cstdint>
#include <string>
#include "fuzz_common.h"
#include "isandbox_manager.h"
#define private public
#include "sandbox_manager_service.h"
#undef private
#include "accesstoken_kit.h"
#include "sandbox_manager_kit.h"
#include "token_setproc.h"

using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {

    bool RevokeSharedDirectoryPermissionStubFuzzTest(const uint8_t *data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }

        // No additional parameters needed - uses calling context
        uint32_t code = 0xffc8;  // COMMAND_REVOKE_SHARED_DIRECTORY_PERMISSION from IDL

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
    OHOS::RevokeSharedDirectoryPermissionStubFuzzTest(data, size);
    return 0;
}
