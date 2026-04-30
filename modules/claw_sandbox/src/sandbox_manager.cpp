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

#include "sandbox_manager.h"
#include "sandbox_error.h"
#include "sandbox_log.h"

#include <cstring>
#include <map>
#include <fstream>
#include <sstream>
#include <iostream>
#include <random>
#include <iomanip>
#include <grp.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <sys/stat.h>
#include <linux/securebits.h>
#include <linux/capability.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#ifdef WITH_SECCOMP
#include "seccomp_policy.h"
#endif
#include <selinux/selinux.h>
#include <access_token.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <cstdlib>

#include "securec.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"
#include "permission_list_state.h"
#include "access_token.h"
#include "ipc_skeleton.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

// SELinux label constant (consistent with the original implementation)
constexpr const char *SELINUX_LABEL = "u:r:claw_cli:s0";

// Number of capability data structures (CAP_NUM = 2 for _LINUX_CAPABILITY_VERSION_3)
constexpr int CAP_NUM = 2;

// Sandbox base directory
constexpr const char *SANDBOX_BASE_DIR = "/mnt/sandbox/claw";

// Read proc group
constexpr const char *READ_PROC_GROUP = "readproc";

// Maximum retry count for generating sandbox name
constexpr int MAX_TRY_CNT = 3;

// Sandbox directory mode
constexpr mode_t DIR_MODE = 0711;

// Hex string generation constants
constexpr int HEX_MAX = 15;
constexpr int HEX_CNT = 16;
constexpr int UID_BASE = 200000;

// Namespace path buffer size
constexpr size_t NS_PATH_BUF_SIZE = 256;

// BPF instruction count for architecture check (load arch, jump aarch64, kill other, load nr)
constexpr size_t ARCH_CHECK_BPF_CNT = 4;

// BPF instructions per syscall entry (JUMP + RET)
constexpr size_t BPF_PER_SYSCALL = 2;

// Mount flag string to numeric value mapping table
static const std::map<std::string, unsigned long> MOUNT_FLAGS_MAP = {
    {"rec", MS_REC}, {"MS_REC", MS_REC},
    {"bind", MS_BIND}, {"MS_BIND", MS_BIND},
    {"move", MS_MOVE}, {"MS_MOVE", MS_MOVE},
    {"slave", MS_SLAVE}, {"MS_SLAVE", MS_SLAVE},
    {"rdonly", MS_RDONLY}, {"MS_RDONLY", MS_RDONLY},
    {"ro", MS_RDONLY},
    {"shared", MS_SHARED}, {"MS_SHARED", MS_SHARED},
    {"unbindable", MS_UNBINDABLE}, {"MS_UNBINDABLE", MS_UNBINDABLE},
    {"remount", MS_REMOUNT}, {"MS_REMOUNT", MS_REMOUNT},
    {"nosuid", MS_NOSUID}, {"MS_NOSUID", MS_NOSUID},
    {"nodev", MS_NODEV}, {"MS_NODEV", MS_NODEV},
    {"noexec", MS_NOEXEC}, {"MS_NOEXEC", MS_NOEXEC},
    {"noatime", MS_NOATIME}, {"MS_NOATIME", MS_NOATIME},
    {"lazytime", MS_LAZYTIME}, {"MS_LAZYTIME", MS_LAZYTIME},
    {"private", MS_PRIVATE}, {"MS_PRIVATE", MS_PRIVATE},
};

unsigned long SandboxManager::ConvertMountFlags(const std::vector<std::string> &mountFlags)
{
    unsigned long result = 0;
    for (const auto &flag : mountFlags) {
        auto it = MOUNT_FLAGS_MAP.find(flag);
        if (it != MOUNT_FLAGS_MAP.end()) {
            result |= it->second;
        } else {
            SANDBOX_LOGW("Unknown mount flag: %{public}s", flag.c_str());
        }
    }
    return result;
}

SandboxManager::SandboxManager() {}

SandboxManager::~SandboxManager()
{
    Cleanup();
}

int SandboxManager::Initialize(const SandboxConfig &config, const CmdInfo &cmdInfo)
{
    config_ = config;
    cmdInfo_ = cmdInfo;
    // Derive currentUserId from uid (not parsed from JSON config)
    config_.currentUserId = std::to_string(config_.uid / UID_BASE);
    initialized_ = true;
    return SANDBOX_SUCCESS;
}

int SandboxManager::Execute()
{
    if (!initialized_) {
        std::cerr << "Error: SandboxManager not initialized" << std::endl;
        SANDBOX_LOGE("SandboxManager not initialized");
        return SANDBOX_ERR_GENERIC;
    }

    // Step 1: Validate configuration parameters
    int ret = ValidateConfig();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 2: Load built-in template configuration
    ret = LoadTemplate();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 3: setns into the caller's sandbox
    ret = EnterCallerSandbox();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 4: Create sandbox path (using config_.name or auto-generated name)
    ret = CreateNewRoot();
    if (ret != SANDBOX_SUCCESS) {
        Cleanup();
        return ret;
    }

    // Step 5: unshare to create namespaces
    ret = UnshareNamespaces();
    if (ret != SANDBOX_SUCCESS) {
        Cleanup();
        return ret;
    }

    // Step 6: Set the new root directory as a mount point
    ret = MountNewRoot();
    if (ret != SANDBOX_SUCCESS) {
        Cleanup();
        return ret;
    }

    // Step 7: Create and mount system directories
    ret = MountSystemDirs();
    if (ret != SANDBOX_SUCCESS) {
        Cleanup();
        return ret;
    }

    // Step 8: Create and mount application directories
    ret = MountAppDirs();
    if (ret != SANDBOX_SUCCESS) {
        Cleanup();
        return ret;
    }

    // Step 9: pivot_root to switch root directory
    ret = PivotRoot();
    if (ret != SANDBOX_SUCCESS) {
        Cleanup();
        return ret;
    }

    // Step 10: Set AccessToken
    ret = SetAccessToken();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 11: Set UID/GID (with SECBIT_KEEP_CAPS to preserve capabilities across setuid)
    ret = SetUidGid();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 12: Create a new process group (must be done BEFORE SetSeccomp,
    //          because seccomp blocks setpgid/setsid to prevent process group escape)
    ret = SetProcessGroup();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 13: Set Seccomp (always applied to block setpgid/setsid for process group protection)
    ret = SetSeccomp();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 14: Set Selinux label
    ret = SetSelinux();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 15: Drop Capabilities (must be after seccomp to avoid interfering with
    //          setpgid/setsid; capset() syscall is not blocked by seccomp in
    //          block mode, and in whitelist mode it will be allowed if listed)
    ret = DropCapabilities();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 16: Execute the command
    return ExecuteCommand();
}

// ==================== 15-step workflow implementation ====================

int SandboxManager::ValidateConfig()
{
    if (config_.callerPid <= 0) {
        std::cerr << "Error: Invalid callerPid: " << config_.callerPid << std::endl;
        SANDBOX_LOGE("Invalid callerPid: %{public}d", config_.callerPid);
        return SANDBOX_ERR_BAD_PARAMETERS;
    }
    if (config_.uid < UID_BASE || config_.gid < UID_BASE) {
        std::cerr << "Error: Invalid uid/gid: " << config_.uid << "/" << config_.gid << std::endl;
        SANDBOX_LOGE("Invalid uid/gid: %{public}u/%{public}u",
            config_.uid, config_.gid);
        return SANDBOX_ERR_BAD_PARAMETERS;
    }
    if (config_.callerTokenId == 0) {
        std::cerr << "Error: Invalid callerTokenId: " << config_.callerTokenId << std::endl;
        SANDBOX_LOGE("Invalid callerTokenId: %{public}llu",
            (unsigned long long)config_.callerTokenId);
        return SANDBOX_ERR_BAD_PARAMETERS;
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::LoadTemplate()
{
    const char *templatePath = "/etc/sandbox/claw_sandbox_template.json";
    return LoadJsonConfig(templatePath);
}

int SandboxManager::EnterCallerSandbox()
{
    // Get Gid by group name
    struct group *grp = getgrnam(READ_PROC_GROUP);
    if (grp == nullptr) {
        std::cerr << "Error: Cannot find readproc group" << std::endl;
        SANDBOX_LOGE("Error: Cannot find readproc group");
        return SANDBOX_ERR_NS_FAILED;
    }

    std::vector<gid_t> gids = {grp->gr_gid};
    if (setgroups(gids.size(), gids.data()) == -1) {
        std::cerr << "Error: setgroups failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("setgroups failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_NS_FAILED;
    }

    // Enter the caller's mount namespace
    char nsPath[NS_PATH_BUF_SIZE] = {0};
    int ret = snprintf_s(nsPath, sizeof(nsPath), sizeof(nsPath) - 1,
                         "/proc/%d/ns/mnt", config_.callerPid);
    if (ret < 0) {
        std::cerr << "Error: snprintf_s failed for ns path" << std::endl;
        SANDBOX_LOGE("snprintf_s failed");
        return SANDBOX_ERR_NS_FAILED;
    }

    int fd = open(nsPath, O_RDONLY);
    if (fd < 0) {
        std::cerr << "Error: Failed to open " << nsPath << ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to open %{public}s: %{public}s",
            nsPath, strerror(errno));
        return SANDBOX_ERR_NS_FAILED;
    }

    if (setns(fd, 0) < 0) {
        std::cerr << "Error: setns failed for " << nsPath << ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("setns failed for %{public}s: %{public}s",
            nsPath, strerror(errno));
        close(fd);
        return SANDBOX_ERR_NS_FAILED;
    }
    close(fd);
    SANDBOX_LOGD("Entered caller sandbox (pid=%{public}d)", config_.callerPid);
    return SANDBOX_SUCCESS;
}

static std::string GenerateSandboxName(void)
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<> dis(0, HEX_MAX);

    std::ostringstream oss;
    for (int i = 0; i < HEX_CNT; ++i) {
        oss << std::hex << dis(gen);
    }
    return oss.str();
}

static bool IsDirectoryExist(const std::string &path)
{
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return false;
    }
    return S_ISDIR(st.st_mode);
}

static int CreateDirRecursive(const std::string &path, mode_t mode)
{
    if (path.empty()) {
        std::cerr << "Error: CreateDirRecursive called with empty path" << std::endl;
        SANDBOX_LOGE("CreateDirRecursive called with empty path");
        return SANDBOX_ERR_PATH_INVALID;
    }

    // Use std::string to build subpaths safely instead of raw char buffer + memcpy_s
    std::string::size_type pos = 0;
    while ((pos = path.find('/', pos + 1)) != std::string::npos) {
        std::string subPath = path.substr(0, pos);
        if (subPath.empty()) {
            continue;
        }
        if (mkdir(subPath.c_str(), mode) == -1 && errno != EEXIST) {
            std::cerr << "Error: mkdir " << subPath << " failed: " << strerror(errno) << std::endl;
            SANDBOX_LOGE("mkdir %{public}s failed: %{public}s", subPath.c_str(), strerror(errno));
            return SANDBOX_ERR_PATH_CREATE_FAILED;
        }
    }
    if (mkdir(path.c_str(), mode) == -1 && errno != EEXIST) {
        std::cerr << "Error: mkdir " << path << " failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("mkdir %{public}s failed: %{public}s", path.c_str(), strerror(errno));
        return SANDBOX_ERR_PATH_CREATE_FAILED;
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::CreateSandboxWithName(const std::string &name)
{
    std::string sandboxPath = std::string(SANDBOX_BASE_DIR) + "/" + name;
    int ret = CreateDirRecursive(sandboxPath, DIR_MODE);
    if (ret != SANDBOX_SUCCESS) {
        std::cerr << "Error: Failed to create sandbox directory: " << sandboxPath
                  << " (" << strerror(errno) << ")" << std::endl;
        SANDBOX_LOGE("Failed to create sandbox directory: %{public}s, errno: %{public}s",
            sandboxPath.c_str(), strerror(errno));
        return ret;
    }
    config_.name = name;
    newRootPath_ = sandboxPath;
    return SANDBOX_SUCCESS;
}

int SandboxManager::CreateSandboxAutoName()
{
    uint32_t tryCnt = 0;
    while (tryCnt < MAX_TRY_CNT) {
        std::string sandboxName = GenerateSandboxName();
        std::string sandboxPath = std::string(SANDBOX_BASE_DIR) + "/" + sandboxName;
        if (IsDirectoryExist(sandboxPath)) {
            tryCnt++;
            continue;
        }
        int ret = CreateDirRecursive(sandboxPath, DIR_MODE);
        if (ret != SANDBOX_SUCCESS) {
            std::cerr << "Error: Failed to create sandbox directory: " << sandboxPath
                      << " (" << strerror(errno) << ")" << std::endl;
            SANDBOX_LOGE("Failed to create sandbox directory: %{public}s, errno: %{public}s",
                sandboxPath.c_str(), strerror(errno));
            return ret;
        }
        config_.name = sandboxName;
        newRootPath_ = sandboxPath;
        return SANDBOX_SUCCESS;
    }
    std::cerr << "Error: Exhausted all retries for sandbox path creation" << std::endl;
    SANDBOX_LOGE("Exhausted all retries for sandbox path creation");
    return SANDBOX_ERR_SANDBOX_PATH_EXHAUSTED;
}

int SandboxManager::CreateNewRoot()
{
    int ret;
    if (!config_.name.empty()) {
        ret = CreateSandboxWithName(config_.name);
    } else {
        ret = CreateSandboxAutoName();
    }
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    putOldPath_ = newRootPath_ + "/put_old";
    if (mkdir(putOldPath_.c_str(), S_IRWXU | S_IRGRP | S_IXGRP) < 0) {
        std::cerr << "Error: mkdir put_old failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("mkdir put_old failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_PATH_CREATE_FAILED;
    }
    SANDBOX_LOGD("Created new root at %{public}s", newRootPath_.c_str());
    return SANDBOX_SUCCESS;
}

int SandboxManager::UnshareNamespaces()
{
    int flags = CmdParser::ConvertNsFlags(config_.nsFlags);
    if (unshare(flags) < 0) {
        std::cerr << "Error: unshare(0x" << std::hex << flags << std::dec
                  << ") failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("unshare(0x%{public}x) failed: %{public}s",
            flags, strerror(errno));
        return SANDBOX_ERR_NS_FAILED;
    }

    SANDBOX_LOGD("Unshared namespaces successfully");
    return SANDBOX_SUCCESS;
}

int SandboxManager::MountNewRoot()
{
    // Bind mount the new root directory onto itself (pivot_root requires
    // the new root to be a mount point)
    if (mount(newRootPath_.c_str(), newRootPath_.c_str(),
              nullptr, MS_BIND | MS_REC, nullptr) < 0) {
        std::cerr << "Error: mount --bind new root failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("mount --bind new root failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_MOUNT_FAILED;
    }
    mountedDirs_.push_back(newRootPath_);
    return SANDBOX_SUCCESS;
}

int SandboxManager::MountSystemEntry(const MountEntry &entry, const std::string &targetPrefix)
{
    std::string target = targetPrefix + entry.target;

    // Skip if source does not exist (no error)
    struct stat st;
    if (stat(entry.source.c_str(), &st) != 0) {
        return SANDBOX_SUCCESS;
    }

    int ret = CreateDir(target);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Simple bind mount without remount readonly or propagation changes
    unsigned long mountFlags = ConvertMountFlags(entry.mountFlags);
    if (mount(entry.source.c_str(), target.c_str(), nullptr, mountFlags, nullptr) < 0) {
        std::cerr << "Error: Failed to mount " << entry.source << " -> " << target
                  << ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to mount %{public}s -> %{public}s: %{public}s",
            entry.source.c_str(), target.c_str(), strerror(errno));
        return SANDBOX_ERR_MOUNT_FAILED;
    }

    mountedDirs_.push_back(target);
    return SANDBOX_SUCCESS;
}

int SandboxManager::MountSingleEntry(const MountEntry &entry, const std::string &targetPrefix)
{
    constexpr unsigned long PROPAGATION_MASK = MS_SLAVE | MS_SHARED | MS_PRIVATE | MS_UNBINDABLE;
    std::string target = targetPrefix + entry.target;

    if (entry.checkExists) {
        struct stat st;
        if (stat(entry.source.c_str(), &st) != 0) {
            return SANDBOX_SUCCESS;
        }
    }

    int ret = CreateDir(target);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    unsigned long allFlags = ConvertMountFlags(entry.mountFlags);
    unsigned long mountFlags = allFlags & ~PROPAGATION_MASK;
    unsigned long propFlags = allFlags & PROPAGATION_MASK;

    if (mount(entry.source.c_str(), target.c_str(), nullptr, mountFlags, nullptr) < 0) {
        std::cerr << "Error: Failed to mount " << entry.source << " -> " << target
                  << ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to mount %{public}s -> %{public}s: %{public}s",
            entry.source.c_str(), target.c_str(), strerror(errno));
        return SANDBOX_ERR_MOUNT_FAILED;
    }

    if (allFlags & MS_RDONLY) {
        if (mount(entry.source.c_str(), target.c_str(), nullptr,
                  MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, nullptr) < 0) {
            SANDBOX_LOGW("Failed to remount readonly %{public}s: %{public}s",
                target.c_str(), strerror(errno));
        }
    }

    if (propFlags != 0) {
        if (mount(nullptr, target.c_str(), nullptr, propFlags, nullptr) < 0) {
            SANDBOX_LOGW("Failed to set propagation on %{public}s: %{public}s",
                target.c_str(), strerror(errno));
        }
    }

    mountedDirs_.push_back(target);
    return SANDBOX_SUCCESS;
}

int SandboxManager::MountSystemDirs()
{
    for (const auto &entry : templateConfig_.systemMounts) {
        int ret = MountSystemEntry(entry, newRootPath_);
        if (ret != SANDBOX_SUCCESS) {
            return ret;
        }
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::MountAppDirs()
{
    for (const auto &entry : templateConfig_.appMounts) {
        int ret = MountSingleEntry(entry, newRootPath_);
        if (ret != SANDBOX_SUCCESS) {
            return ret;
        }
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::PivotRoot()
{
    if (syscall(SYS_pivot_root, newRootPath_.c_str(), putOldPath_.c_str()) < 0) {
        std::cerr << "Error: pivot_root failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("pivot_root failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_NS_FAILED;
    }

    if (chdir("/") < 0) {
        std::cerr << "Error: chdir / after pivot_root failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("chdir / after pivot_root failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_CHDIR_FAILED;
    }

    // Unmount the old root
    if (umount2("/put_old", MNT_DETACH) < 0) {
        SANDBOX_LOGW("umount put_old failed: %{public}s", strerror(errno));
    }

    // Remove the put_old directory
    if (rmdir("/put_old") < 0) {
        SANDBOX_LOGW("rmdir put_old failed: %{public}s", strerror(errno));
    }

    pivotRootDone_ = true;
    SANDBOX_LOGD("pivot_root completed");
    return SANDBOX_SUCCESS;
}

int SandboxManager::SetAccessToken()
{
    int ret = SetSelfTokenID(config_.callerTokenId);
    if (ret != 0) {
        std::cerr << "Error: SetSelfTokenID failed: " << ret << std::endl;
        SANDBOX_LOGE("SetSelfTokenID failed: %{public}d", ret);
        return SANDBOX_ERR_SET_TOKENID_FAILED;
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::SetUidGid()
{
    // Attempt to set SECBIT_KEEP_CAPS before changing UID/GID.
    // This prevents the kernel from dropping effective capabilities when
    // the real/effective/saved UID changes via setresuid().
    //
    // PR_SET_SECUREBITS requires CAP_SETPCAP. If the process lacks this
    // capability (e.g., running in a user namespace without CAP_SETPCAP),
    // the call will fail with EPERM. In that case, log a warning and
    // continue — setresuid() will clear effective capabilities, but
    // DropCapabilities() (Step 15) will still zero out permitted and
    // inheritable sets via capset().
    if (prctl(PR_SET_SECUREBITS,
              SECBIT_KEEP_CAPS | SECBIT_KEEP_CAPS_LOCKED,
              0, 0, 0) < 0) {
        SANDBOX_LOGW("PR_SET_SECUREBITS (KEEP_CAPS) failed: %{public}s. "
            "Effective capabilities will be cleared by setresuid().",
            strerror(errno));
    }

    std::vector<gid_t> gids = {config_.gid};
    if (setgroups(gids.size(), gids.data()) == -1) {
        std::cerr << "Error: setgroups failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("setgroups failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_NS_FAILED;
    }

    if (setresgid(config_.gid, config_.gid, config_.gid) != 0) {
        std::cerr << "Error: setresgid failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("setresgid failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_SET_UGID_FAILED;
    }

    if (setresuid(config_.uid, config_.uid, config_.uid) != 0) {
        std::cerr << "Error: setresuid failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("setresuid failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_SET_UGID_FAILED;
    }

    return SANDBOX_SUCCESS;
}

// Syscall name to number mapping table (built at compile time via lambda)
static const std::map<std::string, int> SYSCALL_MAP = []() {
    std::map<std::string, int> m;
    m["execve"] = __NR_execve;
    m["execveat"] = __NR_execveat;
    m["clone"] = __NR_clone;
    m["clone3"] = __NR_clone3;
    m["waitid"] = __NR_waitid;
    m["kill"] = __NR_kill;
    m["socket"] = __NR_socket;
    m["connect"] = __NR_connect;
    m["bind"] = __NR_bind;
    m["listen"] = __NR_listen;
    m["accept4"] = __NR_accept4;
    m["unlinkat"] = __NR_unlinkat;
    m["renameat2"] = __NR_renameat2;
    m["mkdirat"] = __NR_mkdirat;
    m["fchmodat"] = __NR_fchmodat;
    m["fchownat"] = __NR_fchownat;
    m["utimensat"] = __NR_utimensat;
    m["fallocate"] = __NR_fallocate;
    m["prctl"] = __NR_prctl;
#ifdef __NR_fork
    m["fork"] = __NR_fork;
#endif
#ifdef __NR_vfork
    m["vfork"] = __NR_vfork;
#endif
#ifdef __NR_tkill
    m["tkill"] = __NR_tkill;
#endif
#ifdef __NR_accept
    m["accept"] = __NR_accept;
#endif
#ifdef __NR_sendto
    m["sendto"] = __NR_sendto;
#endif
#ifdef __NR_recvfrom
    m["recvfrom"] = __NR_recvfrom;
#endif
#ifdef __NR_sendmsg
    m["sendmsg"] = __NR_sendmsg;
#endif
#ifdef __NR_recvmsg
    m["recvmsg"] = __NR_recvmsg;
#endif
#ifdef __NR_getsockopt
    m["getsockopt"] = __NR_getsockopt;
#endif
#ifdef __NR_setsockopt
    m["setsockopt"] = __NR_setsockopt;
#endif
#ifdef __NR_symlinkat
    m["symlinkat"] = __NR_symlinkat;
#endif
#ifdef __NR_linkat
    m["linkat"] = __NR_linkat;
#endif
#ifdef __NR_renameat
    m["renameat"] = __NR_renameat;
#endif
#ifdef __NR_mknodat
    m["mknodat"] = __NR_mknodat;
#endif
#ifdef __NR_chmod
    m["chmod"] = __NR_chmod;
#endif
#ifdef __NR_chown
    m["chown"] = __NR_chown;
#endif
#ifdef __NR_truncate
    m["truncate"] = __NR_truncate;
#endif
#ifdef __NR_ftruncate
    m["ftruncate"] = __NR_ftruncate;
#endif
#ifdef __NR_getcwd
    m["getcwd"] = __NR_getcwd;
#endif
#ifdef __NR_chdir
    m["chdir"] = __NR_chdir;
#endif
#ifdef __NR_fchdir
    m["fchdir"] = __NR_fchdir;
#endif
#ifdef __NR_open
    m["open"] = __NR_open;
#endif
#ifdef __NR_statfs
    m["statfs"] = __NR_statfs;
#endif
#ifdef __NR_fstatfs
    m["fstatfs"] = __NR_fstatfs;
#endif
#ifdef __NR_getcpu
    m["getcpu"] = __NR_getcpu;
#endif
#ifdef __NR_sched_yield
    m["sched_yield"] = __NR_sched_yield;
#endif
#ifdef __NR_mlock
    m["mlock"] = __NR_mlock;
#endif
#ifdef __NR_munlock
    m["munlock"] = __NR_munlock;
#endif
#ifdef __NR_personality
    m["personality"] = __NR_personality;
#endif
#ifdef __NR_arch_prctl
    m["arch_prctl"] = __NR_arch_prctl;
#endif
#ifdef __NR_wait4
    m["wait4"] = __NR_wait4;
#endif
    return m;
}();

static int ResolveSyscallName(const std::string &name)
{
    auto it = SYSCALL_MAP.find(name);
    if (it != SYSCALL_MAP.end()) {
        return it->second;
    }
    return -1;
}

static void AppendAllowFilter(std::vector<struct sock_filter> &filter,
                              size_t &idx, int nr)
{
    filter[idx++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1);
    filter[idx++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
}

__attribute__((unused)) static void AppendKillFilter(std::vector<struct sock_filter> &filter,
                                                     size_t &idx, int nr)
{
    filter[idx++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1);
    filter[idx++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL);
}

/**
 * @brief Append a BPF rule that returns an error (EACCES) for a given syscall number.
 *        Used for blocked syscalls like setpgid/setsid, so the calling process
 *        receives an error instead of being killed (avoids SIGSYS for shell job control).
 */
static void AppendErrnoFilter(std::vector<struct sock_filter> &filter,
                              size_t &idx, int nr)
{
    filter[idx++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1);
    filter[idx++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO + EACCES);
}

int SandboxManager::BuildSeccompFilter(struct sock_fprog &prog)
{
    // Default blocked syscalls: setpgid and setsid
    // (prevents descendant processes from escaping the process group)
    static const std::vector<int> blockedSyscalls = {
        __NR_setpgid, __NR_setsid,
    };

    // Determine default action:
    // - If allow list is non-empty: default KILL (whitelist mode, only listed syscalls allowed)
    // - If allow list is empty: default ALLOW (only blocked syscalls denied)
    bool hasAllowList = !templateConfig_.seccompAllowList.empty();
    unsigned int defaultAction = hasAllowList ? SECCOMP_RET_KILL : SECCOMP_RET_ALLOW;

    // Calculate total BPF instructions:
    // ARCH_CHECK_BPF_CNT for arch check (aarch64) + allowList * BPF_PER_SYSCALL
    // + blockedSyscalls * BPF_PER_SYSCALL + 1 for default action
    size_t totalLen = ARCH_CHECK_BPF_CNT
                      + templateConfig_.seccompAllowList.size() * BPF_PER_SYSCALL
                      + blockedSyscalls.size() * BPF_PER_SYSCALL + 1;
    seccompFilter_.resize(totalLen);
    size_t idx = 0;

    // Load architecture field
    seccompFilter_[idx++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                     offsetof(struct seccomp_data, arch));
    // Allow AUDIT_ARCH_AARCH64 (ARM64)
    seccompFilter_[idx++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                     AUDIT_ARCH_AARCH64, 1, 0);
    // Kill on unsupported architecture
    seccompFilter_[idx++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL);
    // Load syscall number
    seccompFilter_[idx++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                     offsetof(struct seccomp_data, nr));

    // Apply allow list from template config (seccompAllowList)
    for (const auto &name : templateConfig_.seccompAllowList) {
        int nr = ResolveSyscallName(name);
        if (nr < 0) {
            SANDBOX_LOGW("Unknown syscall in seccompAllowList: %{public}s", name.c_str());
            continue;
        }
        AppendAllowFilter(seccompFilter_, idx, nr);
    }

    // Apply blocked syscalls (setpgid, setsid)
    // Use SECCOMP_RET_ERRNO + EACCES instead of SECCOMP_RET_KILL,
    // so the calling process receives an error instead of being killed.
    // This allows shells (e.g. sh -c) to continue running even if they
    // attempt job control via setpgid/setsid.
    for (int nr : blockedSyscalls) {
        AppendErrnoFilter(seccompFilter_, idx, nr);
    }

    // Default action: KILL if allow list present, ALLOW if only block
    seccompFilter_[idx++] = BPF_STMT(BPF_RET | BPF_K, defaultAction);

    prog.len = static_cast<unsigned short>(idx);
    prog.filter = seccompFilter_.data();
    return SANDBOX_SUCCESS;
}

int SandboxManager::SetSeccomp()
{
    // Apply seccomp filters in the correct order:
    // 1. PR_SET_NO_NEW_PRIVS (required before any seccomp filter)
    // 2. SetSeccompPolicyWithName (APP-level filter, if WITH_SECCOMP defined)
    // 3. Custom seccomp filter (blocked syscalls: setpgid/setsid, optional whitelist)
    //
    // The custom filter MUST be installed BEFORE SetSeccompPolicyWithName,
    // because the APP-level filter (SetSeccompPolicyWithName) is a strict
    // whitelist that does NOT allow prctl. If the APP filter is installed
    // first, the subsequent prctl(PR_SET_SECCOMP, ...) for the custom filter
    // would be blocked, causing SIGSYS (signal 31).
    //
    // The custom filter explicitly allows prctl (see BuildSeccompFilter),
    // so SetSeccompPolicyWithName's internal prctl(PR_SET_SECCOMP, ...)
    // will pass through the custom filter successfully.
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        std::cerr << "Error: PR_SET_NO_NEW_PRIVS failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("PR_SET_NO_NEW_PRIVS failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_SET_SECCOMP_FAILED;
    }
#ifdef WITH_SECCOMP
    // Step 2: Set APP-level seccomp policy on top of the custom filter.
    // The custom filter allows prctl, so this prctl(PR_SET_SECCOMP, ...)
    // call will pass through successfully.
    const char *filterName = APP_NAME;
    bool ret = SetSeccompPolicyWithName(APP, filterName);
    if (!ret) {
        std::cerr << "Error: SetSeccompPolicyWithName failed for filter: "
                  << filterName << std::endl;
        SANDBOX_LOGE("SetSeccompPolicyWithName failed for filter: %{public}s",
                     filterName);
        return SANDBOX_ERR_SET_SECCOMP_FAILED;
    }
    SANDBOX_LOGD("APP-level seccomp policy set: %{public}s", filterName);
#endif
    // Step 2: Install custom seccomp filter first.
    // This adds blocked syscalls (setpgid, setsid) and optional whitelist.
    // prctl is explicitly allowed so that SetSeccompPolicyWithName can
    // install its own filter on top.
    struct sock_fprog prog;
    int buildRet = BuildSeccompFilter(prog);
    if (buildRet != SANDBOX_SUCCESS) {
        return buildRet;
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        std::cerr << "Error: PR_SET_SECCOMP failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("PR_SET_SECCOMP failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_SET_SECCOMP_FAILED;
    }

    SANDBOX_LOGD("Custom seccomp filter installed (allow list + blocked syscalls)");
    return SANDBOX_SUCCESS;
}

int SandboxManager::SetSelinux()
{
    if (!is_selinux_enabled()) {
        SANDBOX_LOGI("SELinux is not enabled, skipping");
        return SANDBOX_SUCCESS;
    }

    if (setcon(SELINUX_LABEL) != 0) {
        std::cerr << "Error: setcon(" << SELINUX_LABEL << ") failed: "
                  << strerror(errno) << std::endl;
        SANDBOX_LOGE("setcon(%{public}s) failed: %{public}s",
            SELINUX_LABEL, strerror(errno));
        return SANDBOX_ERR_SET_SELINUX_FAILED;
    }

    return SANDBOX_SUCCESS;
}

int SandboxManager::DropCapabilities()
{
    // Attempt to set SECBIT_NO_SETUID_FIXUP to prevent setuid/setgid bits
    // on executables from affecting the process's capability sets after execve.
    // This requires CAP_SETPCAP. If unavailable (e.g., after setresuid without
    // SECBIT_KEEP_CAPS), log a warning and continue.
    //
    // Note: SECBIT_KEEP_CAPS was already attempted in SetUidGid() (Step 11).
    // If it succeeded, effective capabilities were preserved across setresuid.
    // If it failed, effective capabilities were cleared, but permitted and
    // inheritable sets remain and will be zeroed by capset() below.
    if (prctl(PR_SET_SECUREBITS,
              SECBIT_KEEP_CAPS | SECBIT_NO_SETUID_FIXUP |
              SECBIT_KEEP_CAPS_LOCKED | SECBIT_NO_SETUID_FIXUP_LOCKED,
              0, 0, 0) < 0) {
        SANDBOX_LOGW("PR_SET_SECUREBITS failed: %{public}s. "
            "setuid/setgid fixup protection not applied.",
            strerror(errno));
    }

    struct __user_cap_header_struct capHeader;
    capHeader.version = _LINUX_CAPABILITY_VERSION_3;
    capHeader.pid = 0;
    struct __user_cap_data_struct caps[CAP_NUM];

    caps[0].effective = 0;
    caps[0].permitted = 0;
    caps[0].inheritable = 0;
    caps[1].effective = 0;
    caps[1].permitted = 0;
    caps[1].inheritable = 0;

    // capset() may be blocked by seccomp in whitelist mode if __NR_capset is
    // not in the allow list. In that case, log a warning and continue.
    if (capset(&capHeader, caps) != 0) {
        SANDBOX_LOGW("capset failed (may be blocked by seccomp): %{public}s",
            strerror(errno));
        // Non-fatal: the process is already running as non-root with
        // restricted capabilities
        return SANDBOX_SUCCESS;
    }

    SANDBOX_LOGD("All capabilities dropped via capset");
    return SANDBOX_SUCCESS;
}

int SandboxManager::SetProcessGroup()
{
    // Create a new process group so that the caller can clean up all descendant
    // processes via the process group ID.
    // This MUST be called BEFORE SetSeccomp(), because seccomp blocks
    // setpgid/setsid to prevent descendant processes from escaping the group.
    if (setpgid(0, 0) < 0) {
        std::cerr << "Error: setpgid(0, 0) failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("setpgid(0, 0) failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_GENERIC;
    }

    SANDBOX_LOGD("Created process group: %{public}d", getpgid(0));
    return SANDBOX_SUCCESS;
}

int SandboxManager::ExecuteCommand()
{
    // If no command was provided, fall back to default shell (/bin/sh -i)
    if (cmdInfo_.argv.empty()) {
        SANDBOX_LOGD("No command provided, falling back to default shell");
        execl("/system/bin/sh", "sh", "-i", nullptr);
        int execErrno = errno;
        std::cerr << "Error: execl(/system/bin/sh) failed: " << strerror(execErrno) << std::endl;
        SANDBOX_LOGE("execl(/system/bin/sh) failed: %{public}s", strerror(execErrno));
        return SANDBOX_ERR_CMD_INVALID;
    }

    // Build the argv array
    std::vector<char*> argv;
    for (auto& arg : cmdInfo_.argv) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    argv.push_back(nullptr);

    // Execute the target command -- on success, the current process is replaced
    SANDBOX_LOGD("Executing command: %{public}s", argv[0] ? argv[0] : "null");
    execvp(argv[0], argv.data());

    // Only reached if exec fails
    int execErrno = errno;
    std::cerr << "Error: execvp(" << (argv[0] ? argv[0] : "null")
              << ") failed: " << strerror(execErrno) << std::endl;
    SANDBOX_LOGE("execvp(%{public}s) failed: %{public}s",
        argv[0] ? argv[0] : "null", strerror(execErrno));
    return SANDBOX_ERR_CMD_INVALID;
}

// ==================== Helper methods ====================

int SandboxManager::MountDir(const std::string &source, const std::string &target,
                             const std::vector<std::string> &mountFlags)
{
    constexpr unsigned long PROPAGATION_MASK = MS_SLAVE | MS_SHARED | MS_PRIVATE | MS_UNBINDABLE;

    int ret = CreateDir(target);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    unsigned long allFlags = ConvertMountFlags(mountFlags);
    unsigned long bindFlags = allFlags & ~PROPAGATION_MASK;
    unsigned long propFlags = allFlags & PROPAGATION_MASK;

    if (mount(source.c_str(), target.c_str(), nullptr, bindFlags, nullptr) < 0) {
        std::cerr << "Error: mount " << source << " -> " << target
                  << " failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("mount %{public}s -> %{public}s failed: %{public}s",
            source.c_str(), target.c_str(), strerror(errno));
        return SANDBOX_ERR_MOUNT_FAILED;
    }

    if (propFlags != 0) {
        if (mount(nullptr, target.c_str(), nullptr, propFlags, nullptr) < 0) {
            SANDBOX_LOGW("Failed to set propagation on %{public}s: %{public}s",
                target.c_str(), strerror(errno));
        }
    }

    mountedDirs_.push_back(target);
    return SANDBOX_SUCCESS;
}

static int MkdirIfNotExist(const std::string &dirPath)
{
    struct stat st;
    if (stat(dirPath.c_str(), &st) == 0) {
        return SANDBOX_SUCCESS;
    }
    if (mkdir(dirPath.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0) {
        if (errno == EEXIST) {
            return SANDBOX_SUCCESS;
        }
        std::cerr << "Error: mkdir " << dirPath << " failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("mkdir %{public}s failed: %{public}s",
            dirPath.c_str(), strerror(errno));
        return SANDBOX_ERR_PATH_CREATE_FAILED;
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::CreateDir(const std::string &path)
{
    size_t pos = 0;
    while ((pos = path.find_first_of('/', pos + 1)) != std::string::npos) {
        std::string subPath = path.substr(0, pos);
        if (subPath.empty()) {
            continue;
        }
        int ret = MkdirIfNotExist(subPath);
        if (ret != SANDBOX_SUCCESS) {
            return ret;
        }
    }
    return MkdirIfNotExist(path);
}

void SandboxManager::Cleanup()
{
    if (pivotRootDone_) {
        SANDBOX_LOGD("Cleanup: pivot_root was performed, skip manual cleanup");
        SANDBOX_LOGD("Cleanup: namespace will be cleaned up by kernel on process exit");
        return;
    }

    // Unmount mounted directories in reverse order
    for (auto it = mountedDirs_.rbegin(); it != mountedDirs_.rend(); ++it) {
        if (umount2(it->c_str(), MNT_DETACH) < 0) {
            SANDBOX_LOGW("umount %{public}s failed: %{public}s",
                it->c_str(), strerror(errno));
        }
    }
    mountedDirs_.clear();

    // Clean up temporary directories
    if (!newRootPath_.empty()) {
        if (!putOldPath_.empty()) {
            rmdir(putOldPath_.c_str());
            putOldPath_.clear();
        }
        rmdir(newRootPath_.c_str());
        newRootPath_.clear();
    }
}

int SandboxManager::LoadDefaultConfig()
{
    // System mount entries (simple bind mount, no remount readonly or propagation)
    templateConfig_.systemMounts = {
        {"/proc", "/proc", {"bind", "rec"}, false},
        {"/sys", "/sys", {"bind", "rec"}, false},
        {"/dev", "/dev", {"bind", "rec"}, false},
        {"/tmp", "/tmp", {"bind", "rec"}, false},
        {"/usr", "/usr", {"bind", "rec"}, false},
        {"/etc", "/etc", {"bind", "rec"}, false},
        {"/lib", "/lib", {"bind", "rec"}, false},
        {"/bin", "/bin", {"bind", "rec"}, false},
        {"/sbin", "/sbin", {"bind", "rec"}, false},
        {"/sys_prod", "/sys_prod", {"bind", "rec"}, false},
        {"/system/fonts", "/system/fonts", {"bind", "rec"}, false},
        {"/system/lib", "/system/lib", {"bind", "rec"}, false},
        {"/system/usr", "/system/usr", {"bind", "rec"}, false},
        {"/system/profile", "/system/profile", {"bind", "rec"}, false},
        {"/system/bin", "/system/bin", {"bind", "rec"}, false},
        {"/system/lib64", "/system/lib64", {"bind", "rec"}, false},
        {"/system/etc", "/system/etc", {"bind", "rec"}, false},
        {"/system/framework", "/system/framework", {"bind", "rec"}, false},
        {"/system/resource", "/system/resource", {"bind", "rec"}, false},
        {"/vendor/lib", "/vendor/lib", {"bind", "rec"}, false},
        {"/vendor/lib64", "/vendor/lib64", {"bind", "rec"}, false},
        {"/config", "/config", {"bind", "rec"}, false},
    };
    templateConfig_.appMounts = {};
    templateConfig_.selinuxContext = "u:r:claw_cli:s0";
    return SANDBOX_SUCCESS;
}

void SandboxManager::ParseMountEntry(cJSON *entry, MountEntry &me)
{
    cJSON *src = cJSON_GetObjectItem(entry, "source");
    if (cJSON_IsString(src)) {
        me.source = src->valuestring;
    }
    cJSON *tgt = cJSON_GetObjectItem(entry, "target");
    if (cJSON_IsString(tgt)) {
        me.target = tgt->valuestring;
    }
    cJSON *mf = cJSON_GetObjectItem(entry, "mount-flags");
    if (cJSON_IsArray(mf)) {
        int mfSize = cJSON_GetArraySize(mf);
        for (int j = 0; j < mfSize; j++) {
            cJSON *item = cJSON_GetArrayItem(mf, j);
            if (cJSON_IsString(item)) {
                me.mountFlags.push_back(item->valuestring);
            }
        }
    }
    cJSON *ce = cJSON_GetObjectItem(entry, "check-exists");
    if (cJSON_IsBool(ce)) {
        me.checkExists = cJSON_IsTrue(ce);
    }
}

std::string SandboxManager::ReplaceVariable(std::string str,
    const std::string &from, const std::string &to)
{
    // Guard against empty search string to avoid infinite loop
    if (from.empty()) {
        return str;
    }
    std::string::size_type pos = 0;
    while ((pos = str.find(from, pos)) != std::string::npos) {
        str.replace(pos, from.length(), to);
        pos += to.length();
    }
    return str;
}

int SandboxManager::ParseSystemMountsJson(cJSON *root)
{
    cJSON *sysMounts = cJSON_GetObjectItem(root, "system-mounts");
    if (!cJSON_IsArray(sysMounts)) {
        return SANDBOX_SUCCESS;
    }
    int size = cJSON_GetArraySize(sysMounts);
    for (int i = 0; i < size; i++) {
        cJSON *entry = cJSON_GetArrayItem(sysMounts, i);
        if (!cJSON_IsObject(entry)) {
            continue;
        }
        MountEntry me;
        ParseMountEntry(entry, me);
        if (!me.source.empty() && !me.target.empty()) {
            templateConfig_.systemMounts.push_back(me);
        }
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::ParseAppMountsJson(cJSON *root)
{
    cJSON *appMounts = cJSON_GetObjectItem(root, "app-mounts");
    if (!cJSON_IsArray(appMounts)) {
        return SANDBOX_SUCCESS;
    }
    int size = cJSON_GetArraySize(appMounts);
    for (int i = 0; i < size; i++) {
        cJSON *entry = cJSON_GetArrayItem(appMounts, i);
        if (!cJSON_IsObject(entry)) {
            continue;
        }
        MountEntry me;
        ParseMountEntry(entry, me);
        if (!me.source.empty() && !me.target.empty()) {
            templateConfig_.appMounts.push_back(me);
        }
    }
    return SANDBOX_SUCCESS;
}

void SandboxManager::ParsePermissionMountEntry(cJSON *entry, PermissionMountEntry &pme)
{
    // Parse base mount fields
    ParseMountEntry(entry, pme.mount);

    // Parse optional dec-paths array
    cJSON *decPaths = cJSON_GetObjectItem(entry, "dec-paths");
    if (cJSON_IsArray(decPaths)) {
        int dpSize = cJSON_GetArraySize(decPaths);
        for (int j = 0; j < dpSize; j++) {
            cJSON *item = cJSON_GetArrayItem(decPaths, j);
            if (cJSON_IsString(item)) {
                pme.decPaths.push_back(item->valuestring);
            }
        }
    }

    // Parse optional mount-shared-flag
    cJSON *msf = cJSON_GetObjectItem(entry, "mount-shared-flag");
    if (cJSON_IsString(msf)) {
        pme.mountSharedFlag = msf->valuestring;
    }
}

void SandboxManager::ParsePermissionSwitch(cJSON *obj, PermissionConfig &pc)
{
    cJSON *sw = cJSON_GetObjectItem(obj, "sandbox-switch");
    if (cJSON_IsString(sw) && strcmp(sw->valuestring, "ON") == 0) {
        pc.sandboxSwitch = true;
    }
}

void SandboxManager::ParsePermissionGids(cJSON *obj, PermissionConfig &pc)
{
    cJSON *gids = cJSON_GetObjectItem(obj, "gids");
    if (cJSON_IsArray(gids)) {
        int gidSize = cJSON_GetArraySize(gids);
        for (int j = 0; j < gidSize; j++) {
            cJSON *gidItem = cJSON_GetArrayItem(gids, j);
            if (cJSON_IsNumber(gidItem)) {
                pc.gids.push_back(gidItem->valueint);
            }
        }
    }
}

int SandboxManager::ParsePermissionMounts(cJSON *obj, PermissionConfig &pc)
{
    cJSON *mounts = cJSON_GetObjectItem(obj, "mounts");
    if (!cJSON_IsArray(mounts)) {
        return SANDBOX_SUCCESS;
    }
    int mSize = cJSON_GetArraySize(mounts);
    for (int j = 0; j < mSize; j++) {
        cJSON *mEntry = cJSON_GetArrayItem(mounts, j);
        if (!cJSON_IsObject(mEntry)) {
            continue;
        }
        PermissionMountEntry pme;
        ParsePermissionMountEntry(mEntry, pme);
        pc.mounts.push_back(pme);
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::ParsePermissionJson(cJSON *root)
{
    cJSON *perm = cJSON_GetObjectItem(root, "permission");
    if (!cJSON_IsObject(perm)) {
        return SANDBOX_SUCCESS;
    }

    // Iterate over each permission name (e.g. "ohos.permission.FILE_ACCESS_MANAGER")
    cJSON *permItem = nullptr;
    cJSON_ArrayForEach(permItem, perm) {
        int ret = ParseSinglePermissionItem(permItem);
        if (ret != SANDBOX_SUCCESS) {
            return ret;
        }
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::ParseSinglePermissionItem(cJSON *permItem)
{
    if (!cJSON_IsArray(permItem)) {
        return SANDBOX_SUCCESS;
    }
    std::string permName = permItem->string;
    if (permName.empty()) {
        return SANDBOX_SUCCESS;
    }

    // Each permission name maps to an array of config objects
    int arrSize = cJSON_GetArraySize(permItem);
    for (int i = 0; i < arrSize; i++) {
        cJSON *obj = cJSON_GetArrayItem(permItem, i);
        if (!cJSON_IsObject(obj)) {
            continue;
        }
        int ret = ParseSinglePermissionConfig(obj, permName);
        if (ret != SANDBOX_SUCCESS) {
            return ret;
        }
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::ParseSinglePermissionConfig(cJSON *obj, const std::string &permName)
{
    PermissionConfig pc;
    ParsePermissionSwitch(obj, pc);
    ParsePermissionGids(obj, pc);
    int ret = ParsePermissionMounts(obj, pc);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    templateConfig_.permissions[permName] = pc;
    return SANDBOX_SUCCESS;
}

void SandboxManager::ParseSeccompJson(cJSON *root)
{
    cJSON *seccomp = cJSON_GetObjectItem(root, "seccomp");
    if (!cJSON_IsObject(seccomp)) {
        return;
    }
    cJSON *allowList = cJSON_GetObjectItem(seccomp, "allow-list");
    if (!cJSON_IsArray(allowList)) {
        return;
    }
    int size = cJSON_GetArraySize(allowList);
    for (int i = 0; i < size; i++) {
        cJSON *item = cJSON_GetArrayItem(allowList, i);
        if (cJSON_IsString(item)) {
            templateConfig_.seccompAllowList.push_back(item->valuestring);
        }
    }
}

int SandboxManager::LoadJsonConfig(const std::string &jsonPath)
{
    std::ifstream file(jsonPath);
    if (!file.is_open()) {
        SANDBOX_LOGW("Template config not found at %{public}s, using defaults",
            jsonPath.c_str());
        return LoadDefaultConfig();
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();

    // Replace variables at file content level (before JSON parse)
    content = ReplaceVariable(content, "<PackageName>", config_.bundleName);
    content = ReplaceVariable(content, "<currentUserId>", config_.currentUserId);

    cJSON *root = cJSON_Parse(content.c_str());
    if (root == nullptr) {
        std::cerr << "Error: Failed to parse template JSON: " << jsonPath << std::endl;
        SANDBOX_LOGE("Failed to parse template JSON: %{public}s", jsonPath.c_str());
        return SANDBOX_ERR_TEMPLATE_INVALID;
    }

    int ret = ParseSystemMountsJson(root);
    if (ret != SANDBOX_SUCCESS) {
        cJSON_Delete(root);
        return ret;
    }

    ret = ParseAppMountsJson(root);
    if (ret != SANDBOX_SUCCESS) {
        cJSON_Delete(root);
        return ret;
    }

    ret = ParsePermissionJson(root);
    if (ret != SANDBOX_SUCCESS) {
        cJSON_Delete(root);
        return ret;
    }

    ParseSeccompJson(root);

    cJSON_Delete(root);
    SANDBOX_LOGD("Template config loaded from %{public}s", jsonPath.c_str());
    return SANDBOX_SUCCESS;
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
