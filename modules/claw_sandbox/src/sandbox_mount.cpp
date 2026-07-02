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

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iostream>
#include <map>
#include <random>
#include <iomanip>
#include <memory>
#include <utility>
#include <filesystem>
#include <grp.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <cstdlib>
#include <climits>

#include "securec.h"
#include "accesstoken_kit.h"
#include "permission_list_state.h"
#include "access_token.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

// Sandbox base directory
constexpr const char *SANDBOX_BASE_DIR = "/mnt/sandbox/claw";

// Read proc group
constexpr const char *READ_PROC_GROUP = "readproc";

// Maximum retry count for generating sandbox name
constexpr int MAX_TRY_CNT = 3;

// Sandbox directory mode
constexpr mode_t DIR_MODE = 0711;

// Base value for signal exit codes (128 + signal_number follows shell convention)
constexpr int SIGNAL_EXIT_BASE = 128;

// Hex string generation constants
constexpr int HEX_MAX = 15;
constexpr int HEX_CNT = 16;

// Namespace path buffer size
constexpr size_t NS_PATH_BUF_SIZE = 256;

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

static int OpenCallerMountNamespace(pid_t callerPid, uid_t uid, gid_t gid, int &nsFd)
{
    int procFd = -1;
    int ret = OpenCallerProcDir(callerPid, uid, gid, procFd);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    nsFd = openat(procFd, "ns/mnt", O_RDONLY);
    if (nsFd < 0) {
        std::cerr << "Error: Failed to open ns/mnt for pid " <<
                  callerPid << ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to open ns/mnt for pid %{public}d: %{public}s",
            callerPid, strerror(errno));
        close(procFd);
        return SANDBOX_ERR_NS_FAILED;
    }
    close(procFd);
    return SANDBOX_SUCCESS;
}

static int ReadNamespaceId(pid_t callerPid, char *nsTarget, size_t nsTargetSize)
{
    char nsPath[NS_PATH_BUF_SIZE] = {0};
    int ret = snprintf_s(nsPath, sizeof(nsPath), sizeof(nsPath) - 1,
                         "/proc/%u/ns/mnt", callerPid);
    if (ret < 0) {
        std::cerr << "Error: snprintf_s failed for ns path" << std::endl;
        SANDBOX_LOGE("snprintf_s failed for ns path");
        return SANDBOX_ERR_NS_FAILED;
    }
    ssize_t nsTargetLen = readlink(nsPath, nsTarget, nsTargetSize - 1);
    if (nsTargetLen < 0) {
        std::cerr << "Error: readlink " << nsPath << " failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("readlink %{public}s failed: %{public}s",
            nsPath, strerror(errno));
        return SANDBOX_ERR_NS_FAILED;
    }
    nsTarget[nsTargetLen] = '\0';
    return SANDBOX_SUCCESS;
}

static int VerifyNamespaceChanged(pid_t callerPid, const char *nsTarget)
{
    char nsSelf[NS_PATH_BUF_SIZE] = {0};
    ssize_t nsSelfLen = readlink("/proc/self/ns/mnt", nsSelf, sizeof(nsSelf) - 1);
    if (nsSelfLen < 0) {
        std::cerr << "Error: readlink /proc/self/ns/mnt failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("readlink /proc/self/ns/mnt failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_NS_FAILED;
    }
    nsSelf[nsSelfLen] = '\0';

    if (strcmp(nsTarget, nsSelf) != 0) {
        std::cerr << "Error: setns namespace mismatch for pid " << callerPid <<
                  ": expected " << nsTarget << ", got " << nsSelf << std::endl;
        SANDBOX_LOGE("setns namespace mismatch for pid %{public}d: expected %{public}s, got %{public}s",
            callerPid, nsTarget, nsSelf);
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

    pid_t callerPid = static_cast<pid_t>(config_.callerPid);
    uid_t uid = static_cast<uid_t>(config_.uid);
    gid_t gid = static_cast<gid_t>(config_.gid);

    int nsFd = -1;
    ret = OpenCallerMountNamespace(callerPid, uid, gid, nsFd);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    char nsTarget[NS_PATH_BUF_SIZE] = {0};
    ret = ReadNamespaceId(callerPid, nsTarget, sizeof(nsTarget));
    if (ret != SANDBOX_SUCCESS) {
        close(nsFd);
        return ret;
    }

    if (setns(nsFd, 0) < 0) {
        std::cerr << "Error: setns failed for pid " << callerPid <<
                  ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("setns failed for pid %{public}d: %{public}s",
            callerPid, strerror(errno));
        close(nsFd);
        return SANDBOX_ERR_NS_FAILED;
    }
    close(nsFd);

    ret = VerifyNamespaceChanged(callerPid, nsTarget);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    SANDBOX_LOGD("Entered caller sandbox (pid=%{public}d)", callerPid);
    return SANDBOX_SUCCESS;
}

static std::string GenerateSandboxName(void)
{
    // Use std::random_device for cryptographically secure random bytes.
    // On most platforms (Linux/macOS), std::random_device is backed by
    // /dev/urandom, providing non-deterministic random numbers.
    std::random_device rd;
    std::ostringstream oss;
    for (int i = 0; i < HEX_CNT; ++i) {
        unsigned int val = rd();
        oss << std::hex << (val % (HEX_MAX + 1));
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
    if (unshare(config_.nsFlags) < 0) {
        std::cerr << "Error: unshare(0x" << std::hex << config_.nsFlags << std::dec <<
                  ") failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("unshare(0x%{public}x) failed: %{public}s",
            config_.nsFlags, strerror(errno));
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

/**
 * @brief If CLONE_NEWPID is set, fork a child process after unsharing namespaces.
 *       This is required to enter the new PID namespace, as the original process
 *       will still be in the old PID namespace until it forks. The child process will
 *       continue executing the sandbox setup, while the parent process will wait for
 *       the child to exit and then exit itself. This also has the benefit of making
 *       the sandboxed process a child of the init process in the new PID namespace,
 *       which can help with reaping zombie processes.
 * @return SANDBOX_SUCCESS on success, SANDBOX_ERR_NS_FAILED on failure
 */
int SandboxManager::ForkAfterUnshare()
{
    if ((config_.nsFlags & CLONE_NEWPID) == 0) {
        return SANDBOX_SUCCESS;
    }

    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "Error: fork failed after unshare: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("fork failed after unshare: %{public}s", strerror(errno));
        return SANDBOX_ERR_GENERIC;
    } else if (pid > 0) {
        // Parent process: wait for child to exit and then exit
        int status = 0;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            SANDBOX_LOGD("Child process exited with status %{public}d", WEXITSTATUS(status));
            // use _exit to avoid call deconstructors and lower down the risk of
            // multiple Cleanup calls if the child process called exit() instead of _exit()
            _exit(WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            SANDBOX_LOGD("Child process killed by signal %{public}d", WTERMSIG(status));
            _exit(SIGNAL_EXIT_BASE + WTERMSIG(status));
        } else {
            SANDBOX_LOGD("Child process exited with unknown status");
            _exit(SANDBOX_ERR_GENERIC);
        }
    }
    // Child process continues with sandbox setup in new PID namespace
    return SANDBOX_SUCCESS;
}

int SandboxManager::MountProcFs()
{
    if ((config_.nsFlags & CLONE_NEWPID) != 0) {
        if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, nullptr) < 0) {
            std::cerr << "Error: mount procfs failed: " << strerror(errno) << std::endl;
            SANDBOX_LOGE("mount procfs failed: %{public}s", strerror(errno));
            return SANDBOX_ERR_MOUNT_FAILED;
        }
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::MountSystemEntry(const MountEntry &entry, const std::string &targetPrefix)
{
    std::string target = targetPrefix + entry.target;

    // Skip if source does not exist (no error)
    struct stat st;
    if (stat(entry.source.c_str(), &st) != 0) {
        SANDBOX_LOGD("MountSystemEntry: %{public}s does not exist, skipping", entry.source.c_str());
        return SANDBOX_SUCCESS;
    }

    int ret = CreateDir(target);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGD("MountSysDirs: %{public}s create dir failed", target.c_str());
        return ret;
    }

    // Simple bind mount without remount readonly or propagation changes
    unsigned long mountFlags = ConvertMountFlags(entry.mountFlags);
    if (entry.source == "/proc" && (config_.nsFlags & CLONE_NEWPID) != 0) {
        // Always mount procfs via mount -t proc, never bind-mount the host's /proc.
        // Bind-mounting /proc would expose the host process list inside the sandbox,
        // which is a security concern regardless of PID namespace isolation.
        return SANDBOX_SUCCESS;
    }
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

int SandboxManager::SymlinkSingleEntry(const SymLinkEntry &entry, const std::string &targetPrefix)
{
    std::string target = targetPrefix + entry.target;

    if (access(entry.source.c_str(), F_OK) != 0) {
        SANDBOX_LOGD("SymlinkSingleEntry: %{public}s does not exist, skipping", entry.source.c_str());
        return SANDBOX_SUCCESS;
    }

    if (symlink(entry.source.c_str(), target.c_str()) < 0) {
        std::cerr << "Error: Failed to symlink " << target << " -> " << entry.source <<
                  ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to symlink %{public}s -> %{public}s: %{public}s",
            target.c_str(), entry.source.c_str(), strerror(errno));
        return SANDBOX_ERR_SYMLINK_FAILED;
    }

    return SANDBOX_SUCCESS;
}

int SandboxManager::MountSingleEntry(const MountEntry &entry, const std::string &targetPrefix)
{
    constexpr unsigned long PROPAGATION_MASK = MS_SLAVE | MS_SHARED | MS_PRIVATE | MS_UNBINDABLE;
    std::string target = targetPrefix + entry.target;

    if (entry.checkExists) {
        struct stat st;
        if (stat(entry.source.c_str(), &st) != 0) {
            SANDBOX_LOGD("MountSingleEntry: %{public}s does not exists, skipping", entry.source.c_str());
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

int SandboxManager::MountSymLinks()
{
    for (const auto &entry : templateConfig_.symLinks) {
        int ret = SymlinkSingleEntry(entry, newRootPath_);
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

static bool IsPathUnderMountPoint(const std::string &path, const std::string &mountPoint)
{
    if (mountPoint == "/") {
        return !path.empty() && path[0] == '/';
    }
    if (path == mountPoint) {
        return true;
    }
    return path.size() > mountPoint.size() &&
        path.compare(0, mountPoint.size(), mountPoint) == 0 &&
        path[mountPoint.size()] == '/';
}

static bool MountOptionsReadOnly(const std::string &options)
{
    std::istringstream iss(options);
    std::string option;
    while (std::getline(iss, option, ',')) {
        if (option == "ro") {
            return true;
        }
    }
    return false;
}

static int GetMountReadOnly(const std::string &path, bool &readOnly)
{
    std::ifstream mountInfo("/proc/self/mountinfo");
    if (!mountInfo.is_open()) {
        std::cerr << "Error: Failed to open /proc/self/mountinfo: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to open /proc/self/mountinfo: %{public}s", strerror(errno));
        return SANDBOX_ERR_PATH_INVALID;
    }

    std::string line;
    size_t bestLen = 0;
    bool found = false;
    while (std::getline(mountInfo, line)) {
        std::istringstream iss(line);
        std::string id;
        std::string parent;
        std::string majorMinor;
        std::string root;
        std::string mountPoint;
        std::string options;
        if (!(iss >> id >> parent >> majorMinor >> root >> mountPoint >> options)) {
            continue;
        }
        if (IsPathUnderMountPoint(path, mountPoint) && mountPoint.size() >= bestLen) {
            bestLen = mountPoint.size();
            readOnly = MountOptionsReadOnly(options);
            found = true;
        }
    }

    if (!found) {
        std::cerr << "Error: Failed to find mount point for " << path << std::endl;
        SANDBOX_LOGE("Failed to find mount point for %{public}s", path.c_str());
        return SANDBOX_ERR_PATH_INVALID;
    }
    return SANDBOX_SUCCESS;
}

static int IsExactMountPoint(const std::string &path, bool &isMountPoint)
{
    std::ifstream mountInfo("/proc/self/mountinfo");
    if (!mountInfo.is_open()) {
        std::cerr << "Error: Failed to open /proc/self/mountinfo: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to open /proc/self/mountinfo: %{public}s", strerror(errno));
        return SANDBOX_ERR_PATH_INVALID;
    }

    isMountPoint = false;
    std::string line;
    std::string id;
    std::string parent;
    std::string majorMinor;
    std::string root;
    std::string mountPoint;
    while (std::getline(mountInfo, line)) {
        std::istringstream iss(line);
        if (!(iss >> id >> parent >> majorMinor >> root >> mountPoint)) {
            continue;
        }
        if (mountPoint == path) {
            isMountPoint = true;
            return SANDBOX_SUCCESS;
        }
    }
    return SANDBOX_SUCCESS;
}

bool SandboxManager::IsPolicyWriteEscalation(bool policyReadOnly, bool existingReadOnly)
{
    // Policy may tighten access to readonly, but must not widen an existing readonly mount to writable.
    return !policyReadOnly && existingReadOnly;
}

SandboxManager::ConditionalMatchResult SandboxManager::MatchConditionalSource(const std::string &target,
    std::string &physicalSource) const
{
    if (templateConfig_.conditionalRules.empty()) {
        return CONDITIONAL_NOMATCH;
    }

    bool anyPrefixMatched = false;
    for (const auto &rule : templateConfig_.conditionalRules) {
        // Skip rules with empty target (would match everything via rfind)
        if (rule.target.empty()) {
            continue;
        }
        // Prefix match: target must start with rule.target
        if (target.rfind(rule.target, 0) != 0) {
            continue;
        }
        anyPrefixMatched = true;

        // Empty permissions means unconditionally permitted
        if (rule.permissions.empty()) {
            physicalSource = rule.source + target.substr(rule.target.length());
            SANDBOX_LOGD("Conditional rule matched (no permissions), target=%{public}s, "
                "physicalSource=%{public}s", target.c_str(), physicalSource.c_str());
            return CONDITIONAL_MATCHED;
        }
        // OR logic: any single granted permission is sufficient
        for (const auto &perm : rule.permissions) {
            if (IsPermissionGranted(perm)) {
                physicalSource = rule.source + target.substr(rule.target.length());
                SANDBOX_LOGD("Conditional rule matched, target=%{public}s, "
                    "physicalSource=%{public}s, permission=%{public}s",
                    target.c_str(), physicalSource.c_str(), perm.c_str());
                return CONDITIONAL_MATCHED;
            }
        }
        // Prefix matched but no permission granted for this rule — continue
        // to check if other rules match (OR across rules)
    }

    if (anyPrefixMatched) {
        SANDBOX_LOGD("Conditional rule prefix matched but no permission granted, "
            "target=%{public}s", target.c_str());
        return CONDITIONAL_BLOCKED;
    }
    return CONDITIONAL_NOMATCH;
}

int SandboxManager::MountPolicyPath(const SandboxConfig::PolicyMount &policyMount)
{
    std::string target = policyMount.source;
    std::string mountTarget = newRootPath_ + target;

    // Step 1: If target is already a mount point, just remount (no need for conditional)
    bool targetIsMountPoint = false;
    int ret = IsExactMountPoint(mountTarget, targetIsMountPoint);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    if (targetIsMountPoint) {
        return RemountPolicyMount(policyMount, mountTarget);
    }

    // Step 2: Not an existing mount point — try conditional rule to derive physical source
    std::string physicalSource;
    ConditionalMatchResult matchResult = MatchConditionalSource(target, physicalSource);
    if (matchResult == CONDITIONAL_MATCHED) {
        return BindMountConditionalPath(policyMount, mountTarget, physicalSource);
    }
    if (matchResult == CONDITIONAL_BLOCKED) {
        std::cerr << "Error: policy mount target is denied by conditional rules: " <<
                  target << std::endl;
        SANDBOX_LOGE("policy mount target is denied by conditional rules: %{public}s",
            target.c_str());
        return SANDBOX_ERR_PATH_INVALID;
    }

    // CONDITIONAL_NOMATCH — no rule can resolve this path
    std::cerr << "Error: policy mount target is not a mount point and no "
              << "conditional rule matched: " << target << std::endl;
    SANDBOX_LOGE("policy mount target is not a mount point and no "
        "conditional rule matched: %{public}s", target.c_str());
    return SANDBOX_ERR_PATH_INVALID;
}

int SandboxManager::RemountPolicyMount(const SandboxConfig::PolicyMount &policyMount,
                                       const std::string &target)
{
    if (!policyMount.readOnly) {
        bool targetReadOnly = false;
        int ret = GetMountReadOnly(target, targetReadOnly);
        if (ret != SANDBOX_SUCCESS) {
            return ret;
        }
        if (IsPolicyWriteEscalation(policyMount.readOnly, targetReadOnly)) {
            std::cerr << "Error: policy rw target is readonly in sandbox template: " <<
                      target << std::endl;
            SANDBOX_LOGE("policy rw target is readonly in sandbox template: %{public}s",
                target.c_str());
            return SANDBOX_ERR_PATH_INVALID;
        }
    }
    unsigned long remountFlags = MS_BIND | MS_REMOUNT | MS_REC;
    if (policyMount.readOnly) {
        remountFlags |= MS_RDONLY;
    }
    if (mount(target.c_str(), target.c_str(), nullptr, remountFlags, nullptr) < 0) {
        std::cerr << "Error: Failed to remount policy path " << target << " as " <<
                  (policyMount.readOnly ? "ro" : "rw") << ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to remount policy path %{public}s as %{public}s: %{public}s",
            target.c_str(), policyMount.readOnly ? "ro" : "rw", strerror(errno));
        return SANDBOX_ERR_MOUNT_FAILED;
    }
    SANDBOX_LOGD("Policy mount remounted, target=%{public}s, mode=%{public}s",
        target.c_str(), policyMount.readOnly ? "ro" : "rw");
    return SANDBOX_SUCCESS;
}

int SandboxManager::BindMountConditionalPath(const SandboxConfig::PolicyMount &policyMount,
                                             const std::string &mountTarget,
                                             const std::string &physicalSource)
{
    // Check physical source exists
    struct stat st;
    if (stat(physicalSource.c_str(), &st) != 0) {
        std::cerr << "Error: Conditional physical source does not exist: " <<
                  physicalSource << std::endl;
        SANDBOX_LOGE("Conditional physical source does not exist: %{public}s",
            physicalSource.c_str());
        return SANDBOX_ERR_PATH_INVALID;
    }

    // Create target directory under new root
    int ret = CreateDir(mountTarget);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Bind mount physical source → target
    unsigned long bindFlags = MS_BIND | MS_REC;
    if (mount(physicalSource.c_str(), mountTarget.c_str(), nullptr, bindFlags, nullptr) < 0) {
        std::cerr << "Error: Failed to bind mount conditional path " << physicalSource <<
                  " -> " << mountTarget << ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to bind mount conditional path %{public}s -> %{public}s: %{public}s",
            physicalSource.c_str(), mountTarget.c_str(), strerror(errno));
        return SANDBOX_ERR_MOUNT_FAILED;
    }

    // Remount readonly if required (tighten, always OK)
    if (policyMount.readOnly) {
        unsigned long roFlags = MS_BIND | MS_REMOUNT | MS_REC | MS_RDONLY;
        if (mount(nullptr, mountTarget.c_str(), nullptr, roFlags, nullptr) < 0) {
            SANDBOX_LOGW("Failed to remount conditional path %{public}s as readonly: %{public}s",
                mountTarget.c_str(), strerror(errno));
        }
    }

    SANDBOX_LOGD("Policy bind mount via conditional, source=%{public}s, target=%{public}s, "
        "mode=%{public}s", physicalSource.c_str(), mountTarget.c_str(),
        policyMount.readOnly ? "ro" : "rw");

    mountedDirs_.push_back(mountTarget);
    return SANDBOX_SUCCESS;
}

int SandboxManager::ApplyPolicyMounts()
{
    std::vector<SandboxConfig::PolicyMount> policyMounts = config_.policy.mounts;
    SANDBOX_LOGD("Applying policy mounts, count=%{public}zu", policyMounts.size());
    for (const auto &item : policyMounts) {
        SANDBOX_LOGD("Applying policy mount source=%{public}s, mode=%{public}s",
            item.source.c_str(), item.readOnly ? "ro" : "rw");
        int ret = MountPolicyPath(item);
        if (ret != SANDBOX_SUCCESS) {
            return ret;
        }
    }
    SANDBOX_LOGD("Applied policy mounts successfully, total=%{public}zu", policyMounts.size());
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
    if (mkdir(dirPath.c_str(), DIR_MODE) < 0) {
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

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
