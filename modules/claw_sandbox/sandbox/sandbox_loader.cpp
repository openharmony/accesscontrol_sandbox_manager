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

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <sys/stat.h>
#include "sandbox_manager.h"
#include "sandbox_log.h"
#include "command_parser.h"

using namespace OHOS::Sandbox;

static void PrintUsage(const char *programName)
{
    printf("Options:\n");
    printf(" --config <jsonstr> Json string config (required)\n");
    printf(" --cmd <cmdline Command to execute in sand box (required)\n");
    printf(" -c <path> Same as --config\n");
    printf(" -m <cmdline> Same as --cmd\n");
}

std::string Trim(const std::string& str)
{
    size_t first = str.find_first_not_of(" \t\n\r\f\v");
    if (first == std::string::npos) {
        return "";
    }
    size_t last = str.find_last_not_of(" \t\n\r\f\v");
    return str.substr(first, last - first + 1);
}

int main(int argc, char *argv[])
{
    const char *configStr = nullptr;
    std::vector<std::string> cmdArgs;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--config" || arg == "-c") {
            if (i + 1 < argc) {
                configStr = argv[++i];
            }
        } else if (arg == "--cmd" || arg == "-m") {
            if (i + 1 < argc) {
                cmdArgs = CommandParser::Parse(argv[++i]);
            }
        } else {
            printf("Unknown option: %s\n", arg.c_str());
            PrintUsage(argv[0]);
            return 1;
        }
    }

    if (configStr == nullptr) {
        printf("Error: --config is required\n");
        PrintUsage(argv[0]);
        return 1;
    }

    SandboxManager manager;

    if (!cmdArgs.empty()) {
        std::vector<char *> cmdCharArgs;
        for (auto &arg : cmdArgs) {
            cmdCharArgs.push_back(arg.data());
        }
        manager.SetCommand(static_cast<int>(cmdCharArgs.size()), cmdCharArgs.data());
    }

    if (manager.LoadConfigJsonStr(configStr) != 0) {
        SANDBOX_LOGE("Failed to load config");
        return 1;
    }

    std::string appDataPath = "/etc/cli/claw_sandbox_template.json";
    if (manager.LoadAppDataConfig(appDataPath) != 0) {
        SANDBOX_LOGE("Failed to load appdata config");
        return 1;
    }

    SANDBOX_LOGD("Step 1: Setting namespace...");
    if (manager.SetNamespace() != 0) {
        SANDBOX_LOGE("Failed to set namespace");
        return 1;
    }
    SANDBOX_LOGD("Step 1: Namespace set successfully");

    if (manager.CreateSandboxPath() != 0) {
        SANDBOX_LOGE("Failed to create sandbox path");
        return 1;
    }

    SANDBOX_LOGD("Step 2: Setting root as slave before mounting...");
    if (manager.RemountRootSlave() != 0) {
        SANDBOX_LOGE("Failed to remount root as slave");
        return 1;
    }

    SANDBOX_LOGD("Step 2: Mounting system paths...");
    if (manager.MountSystemPaths() != 0) {
        SANDBOX_LOGW("Warning: Failed to mount some system paths");
    }
    SANDBOX_LOGD("Step 2:System paths mounted");

    SANDBOX_LOGD("Step 3: Mounting app data paths...");
    if (manager.MountAppDataPaths() != 0) {
        SANDBOX_LOGW("Warning: Failed to mount some app data paths");
    }
    SANDBOX_LOGD("Step 3: App data paths mounted");

    SANDBOX_LOGD("Step 4: Performing pivot_root...");
    if (manager.PivotRoot() != 0) {
        SANDBOX_LOGE("Failed to pivot root");
        return 1;
    }
    SANDBOX_LOGD("Step 4: pivot_root completed successfully");

    SANDBOX_LOGD("Step 5: Set AccessToken...");
    if (manager.SetAccessToken() != 0) {
        SANDBOX_LOGW("Warning: Failed to Set AccessToken");
    }
    SANDBOX_LOGD("Step 5: Set AccessToken successfully");

    SANDBOX_LOGD("Step 6: Setting uid/gid/groups...");
    if (manager.SetUidGid() != 0) {
        SANDBOX_LOGE("Failed to set uid/gid");
        return 1;
    }
    SANDBOX_LOGD("Step 6: uid/gid set successfully");

    SANDBOX_LOGD("Step 7: Setting seccomp...");
    if (manager.SetSeccomp() != 0) {
        SANDBOX_LOGE("Failed to set seccomp");
        return 1;
    }
    SANDBOX_LOGD("Step 7: Seccomp set successfully");

    SANDBOX_LOGD("Step 8: Setting SELinux...");
    if (manager.SetSelinux() != 0) {
        SANDBOX_LOGE("Failed to set SELinux");
        return 1;
    }
    SANDBOX_LOGD("Step 8: SELinux set successfully");

    SANDBOX_LOGD("Step 9: Dropping all capabilities...");
    if (manager.DropCapabilities() != 0) {
        SANDBOX_LOGW("Warning: Failed to drop capabilities");
    }
    SANDBOX_LOGD("Step 9: Capabilities dropped");

    SANDBOX_LOGD("Step 10: Executing target program...");
    return manager.Execute();
}