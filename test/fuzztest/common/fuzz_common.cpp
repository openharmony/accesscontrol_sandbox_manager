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

#include "fuzz_common.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
const uint32_t POLICY_PATH_LIMIT = 4095;
const uint64_t POLICY_VECTOR_SIZE_LIMIT = 50;
};
void PolicyInfoRandomGenerator::GeneratePolicyInfo(PolicyInfo &policyInfo)
{
    policyInfo.mode = GetData<uint8_t>() % 3 + 1; // 3 is RW
    GenerateString(policyInfo.path);
}

void PolicyInfoRandomGenerator::GeneratePolicyInfoVec(std::vector<PolicyInfo> &policyInfoVec)
{
    uint32_t size = GetData<uint32_t>() % POLICY_VECTOR_SIZE_LIMIT;
    policyInfoVec.clear();
    for (uint32_t i = 0; i < size; ++i) {
        PolicyInfo policyInfo;
        GeneratePolicyInfo(policyInfo);
        policyInfoVec.push_back(policyInfo);
    }
}

void PolicyInfoRandomGenerator::GenerateString(std::string &str)
{
    uint32_t length = GetData<uint32_t>() % POLICY_PATH_LIMIT;
    str = "/";
    for (uint32_t i = 1; i < length; ++i) {
        str += GetData<char>();
    }
}

void PolicyInfoRandomGenerator::GenerateStringVec(std::vector<std::string> &strVec)
{
    uint32_t size = GetData<uint32_t>() % POLICY_VECTOR_SIZE_LIMIT;
    strVec.clear();
    for (uint32_t i = 0; i < size; ++i) {
        std::string str;
        GenerateString(str);
        strVec.push_back(str);
    }
}
}
}
}