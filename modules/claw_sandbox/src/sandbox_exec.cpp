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

#include "sandbox_exec.h"
#include "sandbox_error.h"
#include "sandbox_log.h"

#include <cstdio>
#include <cstring>
#include <iostream>

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

int SandboxExec::ParseArguments(int argc, char *argv[])
{
    // Check for --help/-h first, so it works regardless of other arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage();
            helpRequested_ = true;
            return SANDBOX_SUCCESS;
        }
        if (strcmp(argv[i], "-d") == 0) {
            deleteRequested_ = true;
        }
    }

    int ret = ParseConfigArg(argc, argv);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    ret = ParseCmdArg(argc, argv);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    if (!configParsed_) {
        std::cerr << "Error: Missing required argument: --config" << std::endl;
        SANDBOX_LOGE("Missing required argument: --config");
        return SANDBOX_ERR_BAD_PARAMETERS;
    }

    // --cmd is required for sandbox execution, but delete mode only needs config.name.
    return SANDBOX_SUCCESS;
}

int SandboxExec::ParseConfigArg(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 || strcmp(argv[i], "-c") == 0) {
            if (i + 1 >= argc) {
                std::cerr << "Error: --config requires a JSON string argument" << std::endl;
                SANDBOX_LOGE("--config requires a JSON string argument");
                return SANDBOX_ERR_BAD_PARAMETERS;
            }
            int ret = CmdParser::ParseConfig(argv[++i], config_);
            if (ret != 0) {
                std::cerr << "Error: Failed to parse config" << std::endl;
                SANDBOX_LOGE("Failed to parse config");
                return SANDBOX_ERR_CONFIG_INVALID;
            }
            configParsed_ = true;
        }
    }
    return SANDBOX_SUCCESS;
}

int SandboxExec::ParseCmdArg(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--cmd") == 0 || strcmp(argv[i], "-m") == 0) {
            if (i + 1 >= argc) {
                std::cerr << "Error: --cmd requires a command string argument" << std::endl;
                SANDBOX_LOGE("--cmd requires a command string argument");
                return SANDBOX_ERR_BAD_PARAMETERS;
            }
            cmdInfo_ = CmdParser::ParseCommand(argv[++i]);
            if (cmdInfo_.argv.empty()) {
                std::cerr << "Error: Empty command after parsing" << std::endl;
                SANDBOX_LOGE("Empty command after parsing");
                return SANDBOX_ERR_CMD_INVALID;
            }
            cmdParsed_ = true;
            SANDBOX_LOGD("Command parsed: raw=%{public}s", cmdInfo_.raw.c_str());
        }
    }
    if (!cmdParsed_ && !deleteRequested_) {
        std::cerr << "Error: Missing required argument: --cmd" << std::endl;
        SANDBOX_LOGE("Missing required argument: --cmd");
        return SANDBOX_ERR_BAD_PARAMETERS;
    }
    return SANDBOX_SUCCESS;
}

int SandboxExec::Run()
{
    if (!configParsed_) {
        std::cerr << "Error: Arguments not parsed yet" << std::endl;
        SANDBOX_LOGE("Arguments not parsed yet");
        return SANDBOX_ERR_GENERIC;
    }

    // Create sandbox manager and execute
    SandboxManager manager;
    if (manager.Initialize(config_, cmdInfo_) != SANDBOX_SUCCESS) {
        std::cerr << "Error: Failed to initialize SandboxManager" << std::endl;
        SANDBOX_LOGE("Failed to initialize SandboxManager");
        return SANDBOX_ERR_GENERIC;
    }
    if (deleteRequested_) {
        return manager.DeleteSandboxDir();
    }

    SANDBOX_LOGD("Starting sandbox execution...");

    // Execute() runs the 15-step sandbox workflow, with the final step ExecuteCommand()
    // calling setpgid(0, 0) to create a process group, then execvp to replace the
    // current process with the target command.
    // On success, the current process is replaced and never returns;
    // on failure, the corresponding error code is returned.
    int ret = manager.Execute();
    return ret;
}

void SandboxExec::PrintUsage()
{
    printf("Usage:\n");
    printf("  claw_sandbox --config <jsonstr> --cmd <cmdline>\n");
    printf("  claw_sandbox -d --config <jsonstr>\n");
    printf("\n");
    printf("Options:\n");
    printf("  --config <jsonstr>   JSON configuration string\n");
    printf("  --cmd <cmdline>      Command to execute in sandbox\n");
    printf("  -d                   Delete sandbox directory named in config.name\n");
    printf("  --help, -h           Show this help message\n");
    printf("\n");
    printf("Example:\n");
    printf("  claw_sandbox --config '{\"callerTokenId\":1234,"
           "\"uid\":20020026,\"gid\":20020026,\"callerPid\":1234,"
           "\"appid\":\"com.example\",\"nsFlags\":[\"net\",\"mnt\"],"
           "\"challenge\":\"challenge_value\",\"bundleName\":\"com.example.bundle\","
           "\"cliName\":\"ohos-timer\",\"subCliName\":\"\"}' "
           " --cmd \"ls -la\"\n");
    printf("  claw_sandbox -d --config '{\"callerTokenId\":1234,"
           "\"uid\":20020026,\"gid\":20020026,\"callerPid\":1234,"
           "\"challenge\":\"c\",\"appid\":\"com.example\",\"bundleName\":\"com.example.app\","
           "\"cliName\":\"cli\",\"subCliName\":\"sub\",\"name\":\"abcdef0123456789\"}'\n");
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
