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
#include "sandbox_aids.h"
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
#include <dirent.h>
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

// Minimum UID allowed by seccomp filter (20000000 = 20 million).
// Any attempt to setuid/setreuid/setresuid/setfsuid to a UID below this
// value will be blocked by the seccomp filter, returning EACCES.
constexpr unsigned int UID_MIN_LIMIT = 20000000;

// Namespace path buffer size
constexpr size_t NS_PATH_BUF_SIZE = 256;

// BPF instruction count for architecture check (load arch, jump aarch64, kill other, load nr)
constexpr size_t ARCH_CHECK_BPF_CNT = 4;

// BPF instructions per syscall entry (JUMP + RET)
constexpr size_t BPF_PER_SYSCALL = 2;

// BPF instructions per uid-range-checked syscall entry (1 argument):
//   JUMP(nr match) + LD(args[0]) + JUMP(>= limit) + RET(KILL)
constexpr size_t BPF_PER_UID_SYSCALL_1ARG = 4;

// BPF instructions per uid-range-checked syscall entry (2 arguments: setreuid):
//   JUMP(nr match) + [LD(args[i]) + JUMP(>= limit) + RET(KILL)] * 2
constexpr size_t BPF_PER_UID_SYSCALL_2ARG = 7;

// BPF instructions per uid-range-checked syscall entry (3 arguments: setresuid):
//   JUMP(nr match) + [LD(args[i]) + JUMP(>= limit) + RET(KILL)] * 3
constexpr size_t BPF_PER_UID_SYSCALL_3ARG = 10;

// BPF jump offset when syscall number does NOT match a uid-range-checked syscall.
// This skips all remaining instructions for that syscall (total insns - 1 for the JEQ itself).
constexpr uint8_t BPF_JEQ_SKIP_1ARG = BPF_PER_UID_SYSCALL_1ARG - 1;  // 3
constexpr uint8_t BPF_JEQ_SKIP_2ARG = BPF_PER_UID_SYSCALL_2ARG - 1;  // 6
constexpr uint8_t BPF_JEQ_SKIP_3ARG = BPF_PER_UID_SYSCALL_3ARG - 1;  // 9

// Number of default blocked syscalls (setpgid, setsid)
constexpr size_t BLOCKED_SYSCALL_COUNT = 2;

// System app mask: bit 32 of AccessTokenIDEx indicates system app
constexpr uint64_t SYSTEM_APP_MASK = (static_cast<uint64_t>(1) << 32);

// Low 32-bit mask for extracting AccessTokenID from AccessTokenIDEx
constexpr uint64_t TOKEN_ID_LOWMASK = 0xFFFFFFFF;

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

    // Steps 1-4: Validate, load template, generate token, enter caller sandbox
    int ret = ExecuteEarlySteps();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Steps 5-10: Create root, unshare, mount, pivot_root (with cleanup on failure)
    ret = ExecuteMountSteps();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Steps 11-16: Set token, uid/gid, process group, seccomp, drop caps, exec
    return ExecuteLateSteps();
}

/**
 * @brief Execute steps 1-4: validate config, load template, generate token,
 *        and enter the caller's sandbox namespace.
 *        These steps do NOT require cleanup on failure.
 */
int SandboxManager::ExecuteEarlySteps()
{
    int ret = ValidateConfig();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    ret = LoadTemplate();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    ret = GenerateTokenId();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    ret = EnterCallerSandbox();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    return SANDBOX_SUCCESS;
}

/**
 * @brief Execute steps 5-10: create root, unshare namespaces, mount directories,
 *        and pivot_root. These steps require cleanup on failure.
 */
int SandboxManager::ExecuteMountSteps()
{
    int ret = CreateNewRoot();
    if (ret != SANDBOX_SUCCESS) {
        Cleanup();
        return ret;
    }

    ret = UnshareNamespaces();
    if (ret != SANDBOX_SUCCESS) {
        Cleanup();
        return ret;
    }

    ret = MountNewRoot();
    if (ret != SANDBOX_SUCCESS) {
        Cleanup();
        return ret;
    }

    ret = MountSystemDirs();
    if (ret != SANDBOX_SUCCESS) {
        Cleanup();
        return ret;
    }

    ret = MountAppDirs();
    if (ret != SANDBOX_SUCCESS) {
        Cleanup();
        return ret;
    }

    ret = PivotRoot();
    if (ret != SANDBOX_SUCCESS) {
        Cleanup();
        return ret;
    }
    return SANDBOX_SUCCESS;
}

/**
 * @brief Execute steps 11-16: set access token, uid/gid, process group,
 *        seccomp filter, drop capabilities, and execute the command.
 *        These steps do NOT require cleanup on failure.
 */
int SandboxManager::ExecuteLateSteps()
{
    int ret = SetAccessToken();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 12: Set SetAinfo
    ret = SetAinfo();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 13: Set UID/GID (with SECBIT_KEEP_CAPS to preserve capabilities across setuid)
    ret = SetUidGid();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 14: Create a new process group (must be done BEFORE SetSeccomp,
    //          because seccomp blocks setpgid/setsid to prevent process group escape)
    ret = SetProcessGroup();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 15: Set Seccomp (always applied to block setpgid/setsid for process group protection)
    ret = SetSeccomp();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 16: Drop Capabilities (must be after seccomp to avoid interfering with
    //          setpgid/setsid; capset() syscall is not blocked by seccomp in
    //          block mode, and in whitelist mode it will be allowed if listed)
    ret = DropCapabilities();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 17: Execute the command
    return ExecuteCommand();
}

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

    // Validate callerTokenId: must be TOKEN_HAP and System Hap
    AccessTokenID accessTokenId = static_cast<AccessTokenID>(
        config_.callerTokenId & TOKEN_ID_LOWMASK);
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(accessTokenId);
    if (tokenType != TOKEN_HAP) {
        std::cerr << "Error: callerTokenId type is not TOKEN_HAP, type=" <<
                  static_cast<int>(tokenType) << std::endl;
        SANDBOX_LOGE("callerTokenId type is not TOKEN_HAP, type=%{public}d",
            static_cast<int>(tokenType));
        return SANDBOX_ERR_BAD_PARAMETERS;
    }
    if ((config_.callerTokenId & SYSTEM_APP_MASK) != SYSTEM_APP_MASK) {
        std::cerr << "Error: callerTokenId is not System Hap" << std::endl;
        SANDBOX_LOGE("callerTokenId is not System Hap");
        return SANDBOX_ERR_BAD_PARAMETERS;
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::LoadTemplate()
{
    const char *templatePath = "/etc/sandbox/claw_sandbox_template.json";
    return LoadJsonConfig(templatePath);
}

/**
 * @brief Open /proc/<pid> directory and verify its uid/gid match the expected
 *        values. This prevents TOCTOU races where the PID is reused by a
 *        different process after the original caller exits.
 *
 * @param pid Process ID to open
 * @param expectedUid Expected UID of the process directory
 * @param expectedGid Expected GID of the process directory
 * @param[out] procFd Output file descriptor for the opened proc directory
 * @return SANDBOX_SUCCESS on success, SANDBOX_ERR_NS_FAILED on failure
 */
static int OpenCallerProcDir(pid_t pid, uid_t expectedUid, gid_t expectedGid,
                             int &procFd)
{
    char procPath[NS_PATH_BUF_SIZE] = {0};
    int ret = snprintf_s(procPath, sizeof(procPath), sizeof(procPath) - 1,
                         "/proc/%d", pid);
    if (ret < 0) {
        std::cerr << "Error: snprintf_s failed for proc path" << std::endl;
        SANDBOX_LOGE("snprintf_s failed for proc path");
        return SANDBOX_ERR_NS_FAILED;
    }

    procFd = open(procPath, O_RDONLY | O_DIRECTORY);
    if (procFd < 0) {
        std::cerr << "Error: Failed to open " << procPath << ": " <<
                  strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to open %{public}s: %{public}s",
            procPath, strerror(errno));
        return SANDBOX_ERR_NS_FAILED;
    }

    struct stat procStat;
    if (fstat(procFd, &procStat) != 0) {
        std::cerr << "Error: fstat failed for " << procPath << ": " <<
                  strerror(errno) << std::endl;
        SANDBOX_LOGE("fstat failed for %{public}s: %{public}s",
            procPath, strerror(errno));
        close(procFd);
        procFd = -1;
        return SANDBOX_ERR_NS_FAILED;
    }

    if (procStat.st_uid != expectedUid || procStat.st_gid != expectedGid) {
        std::cerr << "Error: PID " << pid <<
                  " uid/gid mismatch: expected " <<
                  expectedUid << "/" << expectedGid <<
                  ", got " << procStat.st_uid << "/" << procStat.st_gid <<
                  " (PID may have been reused)" << std::endl;
        SANDBOX_LOGE("PID %{public}d uid/gid mismatch: expected "
            "%{public}u/%{public}u, got %{public}u/%{public}u",
            pid, expectedUid, expectedGid,
            procStat.st_uid, procStat.st_gid);
        close(procFd);
        procFd = -1;
        return SANDBOX_ERR_NS_FAILED;
    }

    return SANDBOX_SUCCESS;
}

/**
 * @brief Set the supplementary group list to the "readproc" group GID.
 *        This is required to read /proc/<pid> entries for the caller process.
 * @return SANDBOX_SUCCESS on success, SANDBOX_ERR_NS_FAILED on failure
 */
static int SetReadProcGroup(void)
{
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
    return SANDBOX_SUCCESS;
}

int SandboxManager::EnterCallerSandbox()
{
    int ret = SetReadProcGroup();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 1: Open /proc/<callerPid> directory and verify uid/gid.
    // Holding this fd prevents PID reuse from causing us to enter the
    // namespace of a different process (TOCTOU race condition).
    int procFd = -1;
    ret = OpenCallerProcDir(static_cast<pid_t>(config_.callerPid),
                            static_cast<uid_t>(config_.uid),
                            static_cast<gid_t>(config_.gid),
                            procFd);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 2: Open the mount namespace file via openat() using the pinned
    // proc directory fd. This avoids constructing a /proc/<pid>/ns/mnt
    // path that could be subject to a race condition.
    int nsFd = openat(procFd, "ns/mnt", O_RDONLY);
    if (nsFd < 0) {
        std::cerr << "Error: Failed to open ns/mnt for pid " <<
                  config_.callerPid << ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to open ns/mnt for pid %{public}d: %{public}s",
            config_.callerPid, strerror(errno));
        close(procFd);
        return SANDBOX_ERR_NS_FAILED;
    }

    // Step 3: Close the proc directory fd now that we hold the ns fd.
    // The ns fd keeps the namespace alive independently.
    close(procFd);

    // Step 4: Enter the caller's mount namespace via setns().
    if (setns(nsFd, 0) < 0) {
        std::cerr << "Error: setns failed for pid " << config_.callerPid <<
                  ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("setns failed for pid %{public}d: %{public}s",
            config_.callerPid, strerror(errno));
        close(nsFd);
        return SANDBOX_ERR_NS_FAILED;
    }
    close(nsFd);

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
        std::cerr << "Error: Failed to create sandbox directory: " << sandboxPath <<
                  " (" << strerror(errno) << ")" << std::endl;
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
            std::cerr << "Error: Failed to create sandbox directory: " << sandboxPath <<
                      " (" << strerror(errno) << ")" << std::endl;
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
        std::cerr << "Error: unshare(0x" << std::hex << flags << std::dec <<
                  ") failed: " << strerror(errno) << std::endl;
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
        std::cerr << "Error: Failed to mount " << entry.source << " -> " << target <<
                  ": " << strerror(errno) << std::endl;
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
        std::cerr << "Error: Failed to mount " << entry.source << " -> " << target <<
                  ": " << strerror(errno) << std::endl;
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

int SandboxManager::GenerateTokenId()
{
    CliInitInfo initInfo = {
        .hostTokenId = config_.callerTokenId,
        .challenge = config_.challenge,
        .cliInfo = {
            .cliName = config_.cliName,
            .subCliName = config_.subCliName
        }
    };
    AccessTokenIDEx tokenIdEx;
    std::vector<PermissionWithValue> kernelPermList;

    int ret = AccessTokenKit::InitCliToken(initInfo, tokenIdEx, kernelPermList);
    if (ret != 0) {
        std::cerr << "Error: InitCliToken failed: " << ret << std::endl;
        SANDBOX_LOGE("InitCliToken failed: %{public}d", ret);
        return SANDBOX_ERR_GEN_TOKENID_FAILED;
    }

    config_.tokenIdEx = tokenIdEx;
    config_.kernelPermList = kernelPermList;
    return SANDBOX_SUCCESS;
}

int SandboxManager::SetAccessToken()
{
    // supports privacy records for cli process
    int ret = SetFirstCallerTokenID(config_.callerTokenId);
    if (ret != 0) {
        std::cerr << "Error: SetFirstCallerTokenID failed: " << ret << std::endl;
        SANDBOX_LOGE("SetFirstCallerTokenID failed: %{public}d", ret);
        return SANDBOX_ERR_SET_TOKENID_FAILED;
    }

    ret = SetSelfTokenID(config_.tokenIdEx.tokenIDEx);
    if (ret != 0) {
        std::cerr << "Error: SetSelfTokenID failed: " << ret << std::endl;
        SANDBOX_LOGE("SetSelfTokenID failed: %{public}d", ret);
        return SANDBOX_ERR_SET_TOKENID_FAILED;
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::SetAinfo()
{
    AidsClient aids;
    int ret = aids.setLabel();
    if (ret != 0) {
        // Setting up an AI identity is optional for the time being
        SANDBOX_LOGW("SetAinfo failed: %{public}d", ret);
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
#ifdef __LINUX__
    if (prctl(PR_SET_SECUREBITS,
              SECBIT_KEEP_CAPS | SECBIT_KEEP_CAPS_LOCKED,
              0, 0, 0) < 0) {
        SANDBOX_LOGW("PR_SET_SECUREBITS (KEEP_CAPS) failed: %{public}s. "
            "Effective capabilities will be cleared by setresuid().",
            strerror(errno));
    }
#endif

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
#ifdef __NR_setuid
    m["setuid"] = __NR_setuid;
#endif
#ifdef __NR_setreuid
    m["setreuid"] = __NR_setreuid;
#endif
#ifdef __NR_setresuid
    m["setresuid"] = __NR_setresuid;
#endif
#ifdef __NR_setfsuid
    m["setfsuid"] = __NR_setfsuid;
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
    filter[idx++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES);
}

/**
 * @brief Append a BPF rule that checks whether the first argument (args[0])
 *        of a single-argument uid-related syscall (setuid, setfsuid) is
 *        >= UID_MIN_LIMIT.
 *
 * If uid >= UID_MIN_LIMIT, the syscall is allowed (skip the RET instruction).
 * If uid < UID_MIN_LIMIT, the process is killed with SIGKILL (SECCOMP_RET_KILL).
 *
 * This prevents sandboxed processes from switching to a UID below 20000000
 * (20 million), which is the minimum UID for application processes.
 *
 * BPF instruction layout (BPF_PER_UID_SYSCALL_1ARG = 4 insns):
 *   1. BPF_JUMP(JEQ, nr) - check if syscall number matches
 *   2. BPF_STMT(LD, args[0]) - load the first argument (uid)
 *   3. BPF_JUMP(JGE, UID_MIN_LIMIT, jt=1, jf=0) - if >= limit, skip KILL
 *   4. BPF_STMT(RET, KILL) - kill if uid < limit
 */
static void AppendUidRangeFilter(std::vector<struct sock_filter> &filter,
                                 size_t &idx, int nr)
{
    // Check if syscall number matches
    filter[idx++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0,
                             BPF_JEQ_SKIP_1ARG);
    // Load args[0] (the uid value being set)
    filter[idx++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                             offsetof(struct seccomp_data, args[0]));
    // If args[0] >= UID_MIN_LIMIT, skip the next instruction (allow).
    // If args[0] < UID_MIN_LIMIT, fall through to KILL.
    filter[idx++] = BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K,
                             UID_MIN_LIMIT, 1, 0);
    // args[0] < UID_MIN_LIMIT: kill with SIGKILL
    filter[idx++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL);
}

/**
 * @brief Append a BPF rule that checks BOTH arguments of the setreuid syscall
 *        (ruid=args[0], euid=args[1]) against UID_MIN_LIMIT.
 *
 * setreuid has two arguments: ruid (real UID) and euid (effective UID).
 * BOTH must be >= UID_MIN_LIMIT for the syscall to be allowed.
 * If either argument is < UID_MIN_LIMIT, the process is killed with SIGKILL.
 *
 * BPF instruction layout (BPF_PER_UID_SYSCALL_2ARG = 7 insns):
 *   1. BPF_JUMP(JEQ, nr) - check if this is setreuid
 *   2. BPF_STMT(LD, args[0]) - load ruid
 *   3. BPF_JUMP(JGE, UID_MIN_LIMIT, jt=1, jf=0) - if ruid >= limit, check euid
 *   4. BPF_STMT(RET, KILL) - ruid < limit: kill
 *   5. BPF_STMT(LD, args[1]) - load euid
 *   6. BPF_JUMP(JGE, UID_MIN_LIMIT, jt=1, jf=0) - if euid >= limit, allow
 *   7. BPF_STMT(RET, KILL) - euid < limit: kill
 */
static void AppendSetreuidRangeFilter(std::vector<struct sock_filter> &filter,
                                      size_t &idx, int nr)
{
    // Check if syscall number matches setreuid
    filter[idx++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0,
                             BPF_JEQ_SKIP_2ARG);
    // Load args[0] (ruid)
    filter[idx++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                             offsetof(struct seccomp_data, args[0]));
    // If ruid >= UID_MIN_LIMIT, continue to check euid (skip 1 insn).
    // If ruid < UID_MIN_LIMIT, fall through to KILL.
    filter[idx++] = BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K,
                             UID_MIN_LIMIT, 1, 0);
    // ruid < UID_MIN_LIMIT: kill with SIGKILL
    filter[idx++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL);
    // Load args[1] (euid)
    filter[idx++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                             offsetof(struct seccomp_data, args[1]));
    // If euid >= UID_MIN_LIMIT, skip the next instruction (allow).
    // If euid < UID_MIN_LIMIT, fall through to KILL.
    filter[idx++] = BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K,
                             UID_MIN_LIMIT, 1, 0);
    // euid < UID_MIN_LIMIT: kill with SIGKILL
    filter[idx++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL);
}

/**
 * @brief Append a BPF rule that checks ALL THREE arguments of the setresuid
 *        syscall (ruid=args[0], euid=args[1], suid=args[2]) against UID_MIN_LIMIT.
 *
 * setresuid has three arguments: ruid (real UID), euid (effective UID),
 * and suid (saved UID). ALL THREE must be >= UID_MIN_LIMIT for the syscall
 * to be allowed. If any argument is < UID_MIN_LIMIT, the process is killed
 * with SIGKILL.
 *
 * BPF instruction layout (BPF_PER_UID_SYSCALL_3ARG = 10 insns):
 *   1. BPF_JUMP(JEQ, nr) - check if this is setresuid
 *   2. BPF_STMT(LD, args[0]) - load ruid
 *   3. BPF_JUMP(JGE, UID_MIN_LIMIT, jt=1, jf=0) - if ruid >= limit, check euid
 *   4. BPF_STMT(RET, KILL) - ruid < limit: kill
 *   5. BPF_STMT(LD, args[1]) - load euid
 *   6. BPF_JUMP(JGE, UID_MIN_LIMIT, jt=1, jf=0) - if euid >= limit, check suid
 *   7. BPF_STMT(RET, KILL) - euid < limit: kill
 *   8. BPF_STMT(LD, args[2]) - load suid
 *   9. BPF_JUMP(JGE, UID_MIN_LIMIT, jt=1, jf=0) - if suid >= limit, allow
 *  10. BPF_STMT(RET, KILL) - suid < limit: kill
 */
static void AppendSetresuidRangeFilter(std::vector<struct sock_filter> &filter,
                                       size_t &idx, int nr)
{
    // Check if syscall number matches setresuid
    filter[idx++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0,
                             BPF_JEQ_SKIP_3ARG);
    // Load args[0] (ruid)
    filter[idx++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                             offsetof(struct seccomp_data, args[0]));
    // If ruid >= UID_MIN_LIMIT, continue to check euid (skip 1 insn).
    // If ruid < UID_MIN_LIMIT, fall through to KILL.
    filter[idx++] = BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K,
                             UID_MIN_LIMIT, 1, 0);
    // ruid < UID_MIN_LIMIT: kill with SIGKILL
    filter[idx++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL);
    // Load args[1] (euid)
    filter[idx++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                             offsetof(struct seccomp_data, args[1]));
    // If euid >= UID_MIN_LIMIT, continue to check suid (skip 1 insn).
    // If euid < UID_MIN_LIMIT, fall through to KILL.
    filter[idx++] = BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K,
                             UID_MIN_LIMIT, 1, 0);
    // euid < UID_MIN_LIMIT: kill with SIGKILL
    filter[idx++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL);
    // Load args[2] (suid)
    filter[idx++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                             offsetof(struct seccomp_data, args[2]));
    // If suid >= UID_MIN_LIMIT, skip the next instruction (allow).
    // If suid < UID_MIN_LIMIT, fall through to KILL.
    filter[idx++] = BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K,
                             UID_MIN_LIMIT, 1, 0);
    // suid < UID_MIN_LIMIT: kill with SIGKILL
    filter[idx++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL);
}

static void AppendArchCheck(std::vector<struct sock_filter> &filter, size_t &idx)
{
    // Load architecture field
    filter[idx++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                             offsetof(struct seccomp_data, arch));
    // Allow AUDIT_ARCH_AARCH64 (ARM64)
    filter[idx++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                             AUDIT_ARCH_AARCH64, 1, 0);
    // Kill on unsupported architecture
    filter[idx++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL);
    // Load syscall number
    filter[idx++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                             offsetof(struct seccomp_data, nr));
}

static void AppendAllowList(std::vector<struct sock_filter> &filter, size_t &idx,
                            const std::vector<std::string> &allowList)
{
    for (const auto &name : allowList) {
        int nr = ResolveSyscallName(name);
        if (nr < 0) {
            SANDBOX_LOGW("Unknown syscall in seccompAllowList: %{public}s",
                         name.c_str());
            continue;
        }
        AppendAllowFilter(filter, idx, nr);
    }
}

static void AppendBlockedSyscalls(std::vector<struct sock_filter> &filter,
                                  size_t &idx)
{
    // Default blocked syscalls: setpgid and setsid
    // (prevents descendant processes from escaping the process group)
    static const std::vector<int> blockedSyscalls = {
        __NR_setpgid, __NR_setsid,
    };

    // Use SECCOMP_RET_ERRNO | EACCES instead of SECCOMP_RET_KILL,
    // so the calling process receives an error instead of being killed.
    // This allows shells (e.g. sh -c) to continue running even if they
    // attempt job control via setpgid/setsid.
    for (int nr : blockedSyscalls) {
        AppendErrnoFilter(filter, idx, nr);
    }
}

static void AppendUidRangeSyscalls(std::vector<struct sock_filter> &filter,
                                   size_t &idx)
{
    // UID-related syscalls that must be restricted:
    // the first argument (uid) must be >= UID_MIN_LIMIT (20000000).
    // This prevents sandboxed processes from switching to a system UID.
    static const std::vector<int> uidRangeSyscalls = {
#ifdef __NR_setuid
        __NR_setuid,
#endif
#ifdef __NR_setreuid
        __NR_setreuid,
#endif
#ifdef __NR_setresuid
        __NR_setresuid,
#endif
#ifdef __NR_setfsuid
        __NR_setfsuid,
#endif
    };

    // Different syscalls have different argument counts:
    //   setuid(uid):      1 arg  (args[0])
    //   setreuid(ruid, euid): 2 args (args[0], args[1]) - BOTH must be >= limit
    //   setresuid(ruid, euid, suid): 3 args (args[0], args[1], args[2]) - ALL must be >= limit
    //   setfsuid(uid):    1 arg  (args[0])
    //
    // Each argument check uses BPF_JGE (jump if greater than or equal):
    //   jt=1: if uid >= UID_MIN_LIMIT, skip the BLOCK instruction (allow)
    //   jf=0: if uid < UID_MIN_LIMIT, fall through to BLOCK
    for (int nr : uidRangeSyscalls) {
#ifdef __NR_setreuid
        if (nr == __NR_setreuid) {
            AppendSetreuidRangeFilter(filter, idx, nr);
            continue;
        }
#endif
#ifdef __NR_setresuid
        if (nr == __NR_setresuid) {
            AppendSetresuidRangeFilter(filter, idx, nr);
            continue;
        }
#endif
        // setuid, setfsuid (single-argument syscalls)
        AppendUidRangeFilter(filter, idx, nr);
    }
}

int SandboxManager::BuildSeccompFilter(struct sock_fprog &prog)
{
    // Determine default action:
    // - If allow list is non-empty: default KILL (whitelist mode, only listed syscalls allowed)
    // - If allow list is empty: default ALLOW (only blocked syscalls denied)
    bool hasAllowList = !templateConfig_.seccompAllowList.empty();
    unsigned int defaultAction = hasAllowList ? SECCOMP_RET_KILL : SECCOMP_RET_ALLOW;

    // Calculate total BPF instructions:
    // ARCH_CHECK_BPF_CNT for arch check (aarch64) + allowList * BPF_PER_SYSCALL
    // + blockedSyscalls * BPF_PER_SYSCALL
    // + uid range syscalls (1-arg: 4, 2-arg: 7, 3-arg: 10)
    // + 1 for default action
    //
    // uidRangeSyscalls layout:
    //   setuid:     BPF_PER_UID_SYSCALL_1ARG (4 insns)
    //   setreuid:   BPF_PER_UID_SYSCALL_2ARG (7 insns)
    //   setresuid:  BPF_PER_UID_SYSCALL_3ARG (10 insns)
    //   setfsuid:   BPF_PER_UID_SYSCALL_1ARG (4 insns)
    size_t totalLen = ARCH_CHECK_BPF_CNT
                      + templateConfig_.seccompAllowList.size() * BPF_PER_SYSCALL
                      + BLOCKED_SYSCALL_COUNT * BPF_PER_SYSCALL
                      + BPF_PER_UID_SYSCALL_1ARG  // setuid
                      + BPF_PER_UID_SYSCALL_2ARG  // setreuid
                      + BPF_PER_UID_SYSCALL_3ARG  // setresuid
                      + BPF_PER_UID_SYSCALL_1ARG  // setfsuid
                      + 1;
    seccompFilter_.resize(totalLen);
    size_t idx = 0;

    // Step 1: Architecture check (must be AARCH64)
    AppendArchCheck(seccompFilter_, idx);

    // Step 2: Apply allow list from template config (seccompAllowList)
    AppendAllowList(seccompFilter_, idx, templateConfig_.seccompAllowList);

    // Step 3: Apply blocked syscalls (setpgid, setsid)
    AppendBlockedSyscalls(seccompFilter_, idx);

    // Step 4: Apply UID range check for setuid/setreuid/setresuid/setfsuid
    AppendUidRangeSyscalls(seccompFilter_, idx);

    // Step 5: Default action
    seccompFilter_[idx++] = BPF_STMT(BPF_RET | BPF_K, defaultAction);

    prog.len = static_cast<unsigned short>(idx);
    prog.filter = seccompFilter_.data();
    return SANDBOX_SUCCESS;
}

static int SetNoNewPrivs(void)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        std::cerr << "Error: PR_SET_NO_NEW_PRIVS failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("PR_SET_NO_NEW_PRIVS failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_SET_SECCOMP_FAILED;
    }
    return SANDBOX_SUCCESS;
}

#ifdef WITH_SECCOMP
static int SetAppSeccompPolicy(void)
{
    const char *filterName = APP_NAME;
    bool ret = SetSeccompPolicyWithName(APP, filterName);
    if (!ret) {
        std::cerr << "Error: SetSeccompPolicyWithName failed for filter: " <<
                  filterName << std::endl;
        SANDBOX_LOGE("SetSeccompPolicyWithName failed for filter: %{public}s",
                     filterName);
        return SANDBOX_ERR_SET_SECCOMP_FAILED;
    }
    SANDBOX_LOGD("APP-level seccomp policy set: %{public}s", filterName);
    return SANDBOX_SUCCESS;
}
#endif

int SandboxManager::InstallCustomSeccompFilter()
{
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

int SandboxManager::SetSeccomp()
{
    // Apply seccomp filters in the correct order:
    // 1. PR_SET_NO_NEW_PRIVS (required before any seccomp filter)
    // 2. Custom seccomp filter (blocked syscalls: setpgid/setsid, optional whitelist)
    // 3. SetSeccompPolicyWithName (APP-level filter, if WITH_SECCOMP defined)
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
    int ret = SetNoNewPrivs();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    ret = InstallCustomSeccompFilter();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
#ifdef WITH_SECCOMP
    ret = SetAppSeccompPolicy();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
#endif
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
#ifdef __LINUX__
    if (prctl(PR_SET_SECUREBITS,
              SECBIT_KEEP_CAPS | SECBIT_NO_SETUID_FIXUP |
              SECBIT_KEEP_CAPS_LOCKED | SECBIT_NO_SETUID_FIXUP_LOCKED,
              0, 0, 0) < 0) {
        SANDBOX_LOGW("PR_SET_SECUREBITS failed: %{public}s. "
            "setuid/setgid fixup protection not applied.",
            strerror(errno));
    }
#endif

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
    std::cerr << "Error: execvp(" << (argv[0] ? argv[0] : "null") <<
              ") failed: " << strerror(execErrno) << std::endl;
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
        std::cerr << "Error: mount " << source << " -> " << target <<
                  " failed: " << strerror(errno) << std::endl;
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
