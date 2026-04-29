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

#ifndef SANDBOX_SANDBOX_CONFIG_H
#define SANDBOX_SANDBOX_CONFIG_H

#include <string>
#include <vector>
#include <map>
#include <sys/mount.h>

namespace OHOS {
namespace Sandbox {

struct MountEntry {
    std::string srcPath;
    std::string destPath;
    unsigned long flags;
    unsigned long propagation;
    bool checkExists;

    MountEntry() : flags(MS_BIND | MS_REC), propagation(MS_SLAVE), checkExists(false) {}
};

struct AppDataConfig {
    bool sandboxSwitch;
    std::string sandboxRoot;
    std::vector<std::string> nsFlags;
    std::vector<MountEntry> mountPaths;
    std::vector<std::pair<std::string, std::string>> symbolLinks;
};

struct SandboxConfig {
    uint64_t callerTokenId;
    uint64_t tokenId;
    std::string name;
    std::string bundleName;
    std::string currentUserId;
    std::string challenge;
    uid_t uid;
    gid_t gid;
    pid_t callerPid;
    std::vector<gid_t> groups;
    std::vector<std::string> permissions;
    AppDataConfig appDataConfig;

    SandboxConfig() : tokenId(0), name(""), uid(0), gid(0) {}
};

struct SystemPathConfig {
    const char *srcPath;
    const char *destPath;
};

constexpr const char *SELINUX_LABEL = "u:r:claw_cli:s0";
constexpr const char *SANDBOX_BASE_DIR = "/mnt/sandbox/claw";
constexpr int MAX_MOUNT_ENTRIES = 256;
constexpr int MAX_POLICY_LINE_LEN = 256;

constexpr unsigned long DEFAULT_MOUNT_FLAGS = MS_BIND | MS_REC;
constexpr unsigned long DEFAULT_PROPAGATION = MS_SLAVE;

}
}

#endif