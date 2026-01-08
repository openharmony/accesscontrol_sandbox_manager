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

#include "mac_fuzzer.h"

#include <vector>
#include <cstdint>
#include <string>
#include "alloc_token.h"
#include "fuzz_common.h"
#include "policy_info_vector_parcel.h"
#include "isandbox_manager.h"
#define private public
#include "policy_info_manager.h"
#undef private

using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
namespace {
std::string TEST_JSON_PATH[] = {
    "/system/variant/phone/base/etc/sandbox/appdata-sandbox-app.json",
    "/system/variant/phone/base/etc/sandbox/appdata-sandbox.json",
    "/system/variant/phone/base/etc/sandbox/system-sandbox.json",
    "test"
};

const std::vector<std::string> PREDEFINED_JSONS = {
    R"([{"path":"/data/test", "rename":1, "delete":1, "inherit":1}])",
    R"([{"path":"rename":1, "delete":1, "inherit":1}])",
    R"([{"path":"/data/test", "delete":1, "inherit":1}])",
    R"([{"path":"/data/test", "rename":1, "inherit":1}])",
    R"([{"path":"/data/test", "rename":1, "delete":1}])",
};

const uint32_t JSON_PATH_MAX = 4;
const uint32_t JSON_MAX = 5;
};
bool MacFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    PolicyInfoRandomGenerator gen(data, size);
    uint32_t flag = gen.GetData<uint32_t>() % (JSON_PATH_MAX + 1); // 4 is flag max

    std::string jsonPath;
    if (flag < JSON_PATH_MAX) {
        jsonPath = TEST_JSON_PATH[flag];
    } else {
        gen.GenerateString(jsonPath);
    }

    if (jsonPath.empty()) {
        return true;
    }
    std::string rawData;
    PolicyInfoManager::GetInstance().macAdapter_.ReadDenyFile(jsonPath.c_str(), rawData);

    uint32_t index = gen.GetData<uint32_t>() % (JSON_MAX + 1); // 5 is JSON max
    if (index < JSON_MAX) {
        std::string preJson = PREDEFINED_JSONS[index];
        PolicyInfoManager::GetInstance().macAdapter_.SetDenyCfg(preJson);
    } else {
        if (rawData.empty()) {
            return true;
        }
        PolicyInfoManager::GetInstance().macAdapter_.SetDenyCfg(rawData);
    }

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::MacFuzzTest(data, size);
    return 0;
}