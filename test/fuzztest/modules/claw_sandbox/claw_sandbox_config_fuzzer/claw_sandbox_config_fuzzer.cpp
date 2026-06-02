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

#include "claw_sandbox_config_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "fuzz_common.h"
#include "sandbox_cmd_parser.h"

using namespace OHOS::AccessControl::SANDBOX;
using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
namespace {
const uint32_t MAX_JSON_FIELD_LENGTH = 256;

const std::vector<std::string> PREDEFINED_CONFIGS = {
    R"({"callerTokenId": 1, "callerPid": 1, "uid": 20020026, "gid": 20020026,
        "challenge": "c", "appIdentifier": "a", "bundleName": "b", "cliName": "cli", "subCliName": "sub"})",
    R"({"callerTokenId": 1, "callerPid": 1, "uid": 20020026, "gid": 20020026,
        "challenge": "c", "appIdentifier": "a", "bundleName": "b", "cliName": "cli", "subCliName": "sub",
        "name": "abcdef0123456789"})",
    R"({"callerTokenId": 1, "callerPid": 1, "uid": 20020026, "gid": 20020026,
        "challenge": "c", "appIdentifier": "a", "bundleName": "b", "cliName": "cli", "subCliName": "sub",
        "nsFlags": ["mnt", "net", "pid", "uts", "ipc", "user"]})",
    R"({"callerTokenId": -1, "callerPid": 1, "uid": 20020026, "gid": 20020026,
        "challenge": "c", "appIdentifier": "a", "bundleName": "b", "cliName": "cli", "subCliName": "sub"})",
    R"({"callerTokenId": 1, "callerPid": 4294967296, "uid": 20020026, "gid": 20020026,
        "challenge": "c", "appIdentifier": "a", "bundleName": "b", "cliName": "cli", "subCliName": "sub"})",
    R"({"callerTokenId": 1, "callerPid": 1, "uid": 20020026, "gid": 20020026,
        "challenge": 1, "appIdentifier": "a", "bundleName": "b", "cliName": "cli", "subCliName": "sub"})",
    R"({"callerTokenId": 1, "callerPid": 1, "uid": 20020026, "gid": 20020026,
        "challenge": "c", "appIdentifier": "a", "bundleName": "b", "cliName": "cli", "subCliName": "sub",
        "name": "not-hex"})",
    R"({"callerTokenId": 1, "callerPid": 1, "uid": 20020026, "gid": 20020026,
        "challenge": "c", "appIdentifier": "a", "bundleName": "b", "cliName": "cli", "subCliName": "sub",
        "nsFlags": [123]})",
};

const std::vector<std::string> NS_FLAGS = {
    "mnt", "net", "pid", "uts", "ipc", "user", "unknown", ""
};

std::string TrimForJson(const std::string &str)
{
    std::string out;
    for (char ch : str) {
        if (out.length() >= MAX_JSON_FIELD_LENGTH) {
            break;
        }
        unsigned char c = static_cast<unsigned char>(ch);
        if (c >= 0x20 && ch != '"' && ch != '\\') {
            out.push_back(ch);
        }
    }
    return out;
}

std::string GenerateJsonString(PolicyInfoRandomGenerator &gen)
{
    std::string str;
    gen.GenerateString(str);
    return TrimForJson(str);
}

std::string GenerateNsFlags(PolicyInfoRandomGenerator &gen)
{
    uint32_t count = gen.GetData<uint32_t>() % (NS_FLAGS.size() + 4);
    std::string json = "[";
    for (uint32_t i = 0; i < count; ++i) {
        if (i != 0) {
            json += ",";
        }
        uint32_t index = gen.GetData<uint32_t>() % (NS_FLAGS.size() + 1);
        if (index < NS_FLAGS.size()) {
            json += "\"" + NS_FLAGS[index] + "\"";
        } else {
            json += std::to_string(gen.GetData<uint32_t>());
        }
    }
    json += "]";
    return json;
}

std::string BuildConfigJson(PolicyInfoRandomGenerator &gen)
{
    std::string json = "{";
    json += "\"callerTokenId\":" + std::to_string(gen.GetData<uint64_t>()) + ",";
    json += "\"callerPid\":" + std::to_string(gen.GetData<uint32_t>()) + ",";
    json += "\"uid\":" + std::to_string(gen.GetData<uint32_t>()) + ",";
    json += "\"gid\":" + std::to_string(gen.GetData<uint32_t>()) + ",";
    json += "\"challenge\":\"" + GenerateJsonString(gen) + "\",";
    json += "\"appIdentifier\":\"" + GenerateJsonString(gen) + "\",";
    json += "\"bundleName\":\"" + GenerateJsonString(gen) + "\",";
    json += "\"cliName\":\"" + GenerateJsonString(gen) + "\",";
    json += "\"subCliName\":\"" + GenerateJsonString(gen) + "\"";

    if ((gen.GetData<uint8_t>() % 2) == 0) {
        json += ",\"name\":\"" + GenerateJsonString(gen) + "\"";
    }
    if ((gen.GetData<uint8_t>() % 2) == 0) {
        json += ",\"nsFlags\":" + GenerateNsFlags(gen);
    }
    json += "}";
    return json;
}

void ParseConfigOnce(const std::string &json)
{
    SandboxConfig config;
    CmdParser::ParseConfig(json, config);
}
}

bool ClawSandboxConfigFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    PolicyInfoRandomGenerator gen(data, size);
    uint32_t index = gen.GetData<uint32_t>() % (PREDEFINED_CONFIGS.size() + 1);
    if (index < PREDEFINED_CONFIGS.size()) {
        ParseConfigOnce(PREDEFINED_CONFIGS[index]);
    } else {
        ParseConfigOnce(BuildConfigJson(gen));
    }

    std::string raw(reinterpret_cast<const char *>(data), size);
    ParseConfigOnce(raw);
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::ClawSandboxConfigFuzzTest(data, size);
    return 0;
}
