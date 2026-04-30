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

#ifndef CLAW_SANDBOX_SANDBOX_MANAGER_H
#define CLAW_SANDBOX_SANDBOX_MANAGER_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <linux/filter.h>
#include "cJSON.h"
#include "sandbox_cmd_parser.h"
#include "sandbox_error.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

/**
 * @brief Sandbox manager, responsible for executing the 15-step sandbox creation workflow
 *
 * All methods return SANDBOX_SUCCESS (0) on success, or the corresponding error code on failure.
 */
class SandboxManager {
public:
    SandboxManager();
    ~SandboxManager();

    /**
     * @brief Initialize the sandbox manager
     * @param config Sandbox configuration
     * @param cmdInfo Command info
     * @return SANDBOX_SUCCESS on successful initialization
     */
    int Initialize(const SandboxConfig &config, const CmdInfo &cmdInfo);

    /**
     * @brief Execute the sandbox workflow
     * @return SANDBOX_SUCCESS on success (current process replaced by execvp),
     *         error code on failure (e.g. SANDBOX_ERR_NS_FAILED, SANDBOX_ERR_MOUNT_FAILED, etc.)
     */
    int Execute();

private:
    // Template configuration items (defined before use)
    struct MountEntry {
        std::string source;
        std::string target;
        std::vector<std::string> mountFlags;  // e.g. ["bind", "rec", "rdonly", "slave"]
        bool checkExists = false;
    };

    // Permission-level mount entry with additional fields
    struct PermissionMountEntry {
        MountEntry mount;
        std::vector<std::string> decPaths;       // decryption paths (dec-paths)
        std::string mountSharedFlag;             // mount shared flag (mount-shared-flag)
    };

    // Per-permission configuration
    struct PermissionConfig {
        bool sandboxSwitch = false;              // sandbox-switch: "ON"/"OFF"
        std::vector<int> gids;                   // gids array
        std::vector<PermissionMountEntry> mounts; // mounts array
    };

    struct TemplateConfig {
        std::vector<MountEntry> systemMounts;
        std::vector<MountEntry> appMounts;
        std::vector<std::string> seccompAllowList;
        std::string selinuxContext;
        std::map<std::string, PermissionConfig> permissions;  // permission name -> config
    };

    // 15-step workflow (all return int error codes)
    int ValidateConfig();
    int LoadTemplate();
    int EnterCallerSandbox();
    int CreateNewRoot();
    int UnshareNamespaces();
    int MountNewRoot();
    int MountSystemDirs();
    int MountAppDirs();
    int PivotRoot();
    int SetAccessToken();
    int SetUidGid();
    int SetProcessGroup();
    int SetSeccomp();
    int SetSelinux();
    int DropCapabilities();
    int ExecuteCommand();

    // Helper methods
    int MountDir(const std::string &source, const std::string &target,
                 const std::vector<std::string> &mountFlags);
    int CreateDir(const std::string &path);
    void Cleanup();
    int LoadJsonConfig(const std::string &jsonPath);

    // Mount a single system entry (simple bind mount, no remount readonly or propagation)
    int MountSystemEntry(const MountEntry &entry, const std::string &targetPrefix);

    // Mount a single entry (extracted from MountAppDirs for 50-line limit)
    int MountSingleEntry(const MountEntry &entry, const std::string &targetPrefix);

    // LoadJsonConfig sub-helpers (each under 50 lines)
    int ParseSystemMountsJson(cJSON *root);
    int ParseAppMountsJson(cJSON *root);
    void ParseSeccompJson(cJSON *root);
    int ParsePermissionJson(cJSON *root);
    int ParsePermissionMounts(cJSON *obj, PermissionConfig &pc);
    void ParsePermissionSwitch(cJSON *obj, PermissionConfig &pc);
    void ParsePermissionGids(cJSON *obj, PermissionConfig &pc);
    int LoadDefaultConfig();
    static void ParseMountEntry(cJSON *entry, MountEntry &me);
    static void ParsePermissionMountEntry(cJSON *entry, PermissionMountEntry &pme);
    static std::string ReplaceVariable(std::string str,
        const std::string &from, const std::string &to);

    // ParsePermissionJson sub-helpers (extracted to reduce nesting depth)
    int ParseSinglePermissionItem(cJSON *permItem);
    int ParseSinglePermissionConfig(cJSON *obj, const std::string &permName);

    // Seccomp sub-helpers
    int BuildSeccompFilter(struct sock_fprog &prog);

    // CreateNewRoot sub-helpers
    int CreateSandboxWithName(const std::string &name);
    int CreateSandboxAutoName();

    /**
     * @brief Convert string mount flag array to unsigned long bitmask
     * @param mountFlags String array, e.g. ["bind", "rec", "rdonly", "slave"]
     * @return Combined mount flags bitmask
     */
    static unsigned long ConvertMountFlags(const std::vector<std::string> &mountFlags);

    SandboxConfig config_;
    CmdInfo cmdInfo_;
    TemplateConfig templateConfig_;
    std::string newRootPath_;
    std::string putOldPath_;
    std::vector<std::string> mountedDirs_;
    std::vector<struct sock_filter> seccompFilter_;  // Persists filter data for PR_SET_SECCOMP
    bool initialized_ = false;
    bool pivotRootDone_ = false;
};

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS

#endif // CLAW_SANDBOX_SANDBOX_MANAGER_H
