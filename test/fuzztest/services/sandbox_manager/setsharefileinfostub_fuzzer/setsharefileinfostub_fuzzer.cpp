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

#include "setsharefileinfostub_fuzzer.h"

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
namespace {
    enum EdgeCaseType {
        EDGE_CASE_EMPTY_CFGINFO = 0,
        EDGE_CASE_EMPTY_BUNDLENAME,
        EDGE_CASE_PATH_TRAVERSAL,
        EDGE_CASE_JSON_INJECTION,
        EDGE_CASE_NORMAL,
        EDGE_CASE_MAX
    };
    const uint8_t EDGE_CASE_TYPE_MAX = EDGE_CASE_MAX;
    const size_t MIN_DATA_SIZE_FOR_EDGE_CASE = sizeof(uint32_t) * 2;
}

    bool SetShareFileInfoStubFuzzTest(const uint8_t *data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        PolicyInfoRandomGenerator gen(data, size);

        // Generate test parameters
        std::string cfginfo;
        std::string bundleName;
        uint32_t userId = gen.GetData<uint32_t>();
        uint32_t tokenId = gen.GetData<uint32_t>();

        gen.GenerateString(cfginfo);
        gen.GenerateString(bundleName);

        // Test edge cases
        if (size > MIN_DATA_SIZE_FOR_EDGE_CASE) {
            uint8_t edgeCase = data[size - 1] % EDGE_CASE_TYPE_MAX;
            if (edgeCase == EDGE_CASE_EMPTY_CFGINFO) {
                cfginfo = "";  // Empty cfginfo
            } else if (edgeCase == EDGE_CASE_EMPTY_BUNDLENAME) {
                bundleName = "";  // Empty bundleName
            } else if (edgeCase == EDGE_CASE_PATH_TRAVERSAL) {
                bundleName = "../../../etc/passwd";  // Path traversal attempt
            } else if (edgeCase == EDGE_CASE_JSON_INJECTION) {
                cfginfo = "{\"malformed\": \"json\"}";  // JSON injection test
            }
        }

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }

        if (!datas.WriteString(cfginfo)) {
            return false;
        }

        if (!datas.WriteString(bundleName)) {
            return false;
        }

        if (!datas.WriteUint32(userId)) {
            return false;
        }

        if (!datas.WriteUint32(tokenId)) {
            return false;
        }

        uint32_t code = 0xffc3;  // COMMAND_SET_SHARE_FILE_INFO from IDL

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
    OHOS::SetShareFileInfoStubFuzzTest(data, size);
    return 0;
}
