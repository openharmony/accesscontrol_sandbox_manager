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

#include "claw_sandbox_cmd_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "fuzz_common.h"
#include "sandbox_cmd_parser.h"
#include "sandbox_error.h"
#include "sandbox_exec.h"

using namespace OHOS::AccessControl::SANDBOX;
using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {
SandboxManager::SandboxManager() {}
SandboxManager::~SandboxManager() {}
int SandboxManager::Initialize(const SandboxConfig &config, const CmdInfo &cmdInfo)
{
    (void)config;
    (void)cmdInfo;
    return SANDBOX_SUCCESS;
}
int SandboxManager::Execute()
{
    return SANDBOX_SUCCESS;
}
int SandboxManager::DeleteSandboxDir()
{
    return SANDBOX_SUCCESS;
}
} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS

namespace OHOS {
namespace {
const uint32_t MAX_CMD_SEGMENT_LENGTH = 512;
const uint32_t MAX_ARG_COUNT = 8;

const std::string VALID_CONFIG = R"({"callerTokenId":1,"callerPid":1,"uid":20020026,"gid":20020026,
    "challenge":"c","appid":"a","bundleName":"b","cliName":"cli","subCliName":"sub"})";
const std::string EMPTY_SUBCLI_CONFIG = R"({"callerTokenId":1,"callerPid":1,"uid":20020026,"gid":20020026,
    "challenge":"c","appid":"a","bundleName":"b","cliName":"cli","subCliName":""})";
const std::string DELETE_CONFIG = R"({"callerTokenId":1,"callerPid":1,"uid":20020026,"gid":20020026,
    "challenge":"c","appid":"a","bundleName":"b","cliName":"cli","subCliName":"sub","name":"abcdef0123456789"})";

const std::vector<std::vector<std::string>> PREDEFINED_ARGV = {
    {},
    {""},
    {"echo"},
    {"echo", "hello", "world"},
    {"echo", "sub"},
    {"ls", "-la"},
    {"cmd", ""},
    {"--looks-like-option"},
    {std::string(MAX_CMD_SEGMENT_LENGTH * 4, 'a')},
};

std::string LimitString(const std::string &str)
{
    if (str.length() <= MAX_CMD_SEGMENT_LENGTH) {
        return str;
    }
    return str.substr(0, MAX_CMD_SEGMENT_LENGTH);
}

std::string GenerateCmdSegment(PolicyInfoRandomGenerator &gen)
{
    std::string str;
    gen.GenerateString(str);
    return LimitString(str);
}

std::vector<std::string> BuildGeneratedArgv(PolicyInfoRandomGenerator &gen)
{
    uint32_t count = gen.GetData<uint8_t>() % (MAX_ARG_COUNT + 1);
    std::vector<std::string> args;
    args.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        std::string segment = GenerateCmdSegment(gen);
        uint8_t mode = gen.GetData<uint8_t>() % 4;
        if (mode == 0) {
            args.emplace_back("");
        } else if (mode == 1) {
            args.emplace_back("-" + segment);
        } else if (mode == 2) {
            args.emplace_back("--" + segment);
        } else {
            args.emplace_back(segment);
        }
    }
    return args;
}

std::vector<char *> BuildPointerArgv(std::vector<std::string> &storage)
{
    std::vector<char *> argv;
    argv.reserve(storage.size() + 1);
    for (auto &arg : storage) {
        argv.push_back(const_cast<char *>(arg.c_str()));
    }
    argv.push_back(nullptr);
    return argv;
}

void ParseCommandArgvOnce(std::vector<std::string> args, bool injectNull)
{
    std::vector<char *> argv = BuildPointerArgv(args);
    if (injectNull && argv.size() > 1) {
        argv[(argv.size() - 1) / 2] = nullptr;
    }
    CmdParser::ParseCommandFromArgv(static_cast<int>(args.size()), argv.data());
}

void ExerciseInvalidCommandArgv()
{
    std::vector<std::string> args = {"cmd"};
    std::vector<char *> argv = BuildPointerArgv(args);
    CmdParser::ParseCommandFromArgv(0, argv.data());
    CmdParser::ParseCommandFromArgv(-1, argv.data());
    CmdParser::ParseCommandFromArgv(1, nullptr);
}

void ParseExecArgumentsOnce(std::vector<std::string> args)
{
    std::vector<char *> argv = BuildPointerArgv(args);
    SandboxExec exec;
    exec.ParseArguments(static_cast<int>(args.size()), argv.data());
}

std::vector<std::string> BuildExecArgv(PolicyInfoRandomGenerator &gen, const std::string &raw)
{
    std::vector<std::string> cmdArgs = BuildGeneratedArgv(gen);
    uint8_t mode = gen.GetData<uint8_t>() % 16;
    switch (mode) {
        case 0: {
            std::vector<std::string> args = {"claw_sandbox", "--config", VALID_CONFIG, "--cmd"};
            args.insert(args.end(), cmdArgs.begin(), cmdArgs.end());
            return args;
        }
        case 1: {
            std::vector<std::string> args = {"claw_sandbox", "--config", EMPTY_SUBCLI_CONFIG, "--cmd"};
            args.insert(args.end(), cmdArgs.begin(), cmdArgs.end());
            return args;
        }
        case 2:
            return {"claw_sandbox", "--config", raw, "--cmd", "cmd"};
        case 3:
            return {"claw_sandbox", "--config", VALID_CONFIG, "--cmd"};
        case 4:
            return {"claw_sandbox", "--config", VALID_CONFIG};
        case 5:
            return {"claw_sandbox", "--config"};
        case 6: {
            std::vector<std::string> args = {"claw_sandbox", "--cmd"};
            args.insert(args.end(), cmdArgs.begin(), cmdArgs.end());
            return args;
        }
        case 7:
            return {"claw_sandbox", "--cmd", "cmd", "--config", VALID_CONFIG};
        case 8:
            return {"claw_sandbox", "--help"};
        case 9:
            return {"claw_sandbox", "-h"};
        case 10:
            return {"claw_sandbox", "--help", "--config", raw, "--cmd", "cmd"};
        case 11:
            return {"claw_sandbox", "-d", "--config", DELETE_CONFIG};
        case 12:
            return {"claw_sandbox", "-d", "--config", raw};
        case 13:
            return {"claw_sandbox", "-d", "--cmd", "cmd"};
        case 14: {
            std::vector<std::string> args = {"claw_sandbox", "-c", VALID_CONFIG, "-m"};
            args.insert(args.end(), cmdArgs.begin(), cmdArgs.end());
            return args;
        }
        default:
            return {"claw_sandbox", "-c", raw, "-m", "cmd"};
    }
}
}

bool ClawSandboxCmdFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    PolicyInfoRandomGenerator gen(data, size);
    uint32_t index = gen.GetData<uint32_t>() % (PREDEFINED_ARGV.size() + 1);
    if (index < PREDEFINED_ARGV.size()) {
        ParseCommandArgvOnce(PREDEFINED_ARGV[index], (gen.GetData<uint8_t>() % 2) == 0);
    } else {
        ParseCommandArgvOnce(BuildGeneratedArgv(gen), (gen.GetData<uint8_t>() % 2) == 0);
    }
    ExerciseInvalidCommandArgv();

    std::string raw(reinterpret_cast<const char *>(data), size);
    ParseCommandArgvOnce({raw}, false);
    ParseExecArgumentsOnce(BuildExecArgv(gen, raw));
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::ClawSandboxCmdFuzzTest(data, size);
    return 0;
}
