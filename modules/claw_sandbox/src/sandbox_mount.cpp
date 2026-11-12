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

/*
 * Sandbox mount namespace: enter the caller's namespace, create the sandbox
 * root, and build the view. The view is described once as a mount plan and
 * executed in one ordered pass; template symbol links come after the binds,
 * because their sources only exist once the view is attached.
 */

#include "sandbox_manager.h"
#include "sandbox_error.h"
#include "sandbox_log.h"
#include "sandbox_utils.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

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

// Hex string generation constants
constexpr int HEX_CNT = 16;

// Namespace path buffer size
constexpr size_t NS_PATH_BUF_SIZE = 256;

/*
 * ============================== Mount plan ==============================
 *
 * Template and policy binds are collected into one plan, validated and sorted
 * before anything is created, then applied in one ordered pass.
 */

namespace {

constexpr mode_t BIND_TARGET_FILE_MODE = 0600;

constexpr unsigned long PROPAGATION_MASK = MS_SLAVE | MS_SHARED | MS_PRIVATE | MS_UNBINDABLE;

/*
 * A remount rewrites the whole flag set; dropping any of these widens access.
 * Atime flags are left out: a readonly mount never updates atime.
 */
constexpr unsigned long BIND_REMOUNT_KEEP_FLAGS = MS_NOSUID | MS_NODEV | MS_NOEXEC;

// Flag names accepted in templates and in mountinfo's option field.
const std::map<std::string, unsigned long> MOUNT_FLAGS_MAP = {
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

struct MountInfoEntry {
    std::string mountPoint;
    unsigned long flags = 0;
};

bool HasOnlyKnownMountFlags(const std::vector<std::string> &mountFlags)
{
    for (const auto &flag : mountFlags) {
        if (MOUNT_FLAGS_MAP.find(flag) == MOUNT_FLAGS_MAP.end()) {
            return false;
        }
    }
    return true;
}

std::string NormalizeRootPath(const std::string &root)
{
    std::string result = root;
    while (result.size() > 1 && result.back() == '/') {
        result.pop_back();
    }
    return result;
}

/*
 * View paths are absolute, so joining is concatenation. The root is normalised
 * here to keep the output canonical; the view path is left alone because
 * rejecting a malformed one is validation's job.
 */
std::string JoinViewPath(const std::string &root, const std::string &viewPath)
{
    const std::string normalizedRoot = NormalizeRootPath(root);
    if (normalizedRoot == "/") {
        return viewPath;
    }
    return normalizedRoot + viewPath;
}

/*
 * The sixth mountinfo field lists per-mount options with the same names the
 * template parser accepts; superblock options after "-" are not remount's.
 */
unsigned long MountOptionsToFlags(const std::string &options)
{
    unsigned long flags = 0;
    std::istringstream iss(options);
    std::string option;
    while (std::getline(iss, option, ',')) {
        auto it = MOUNT_FLAGS_MAP.find(option);
        if (it != MOUNT_FLAGS_MAP.end()) {
            flags |= it->second;
        }
    }
    return flags;
}

int ReadMountInfo(std::vector<MountInfoEntry> &entries)
{
    std::ifstream mountInfo("/proc/self/mountinfo");
    if (!mountInfo.is_open()) {
        std::cerr << "Error: Failed to open /proc/self/mountinfo: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to open /proc/self/mountinfo: %{public}s", strerror(errno));
        return SANDBOX_ERR_PATH_INVALID;
    }

    std::string line;
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
        MountInfoEntry entry;
        entry.mountPoint = DecodeOctalEscapes(mountPoint);
        entry.flags = MountOptionsToFlags(options);
        entries.push_back(std::move(entry));
    }
    return SANDBOX_SUCCESS;
}

int GetMountFlags(const std::string &path, unsigned long &flags)
{
    std::vector<MountInfoEntry> entries;
    int ret = ReadMountInfo(entries);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    size_t bestLen = 0;
    bool found = false;
    for (const auto &entry : entries) {
        if (IsPathUnder(path, entry.mountPoint) && entry.mountPoint.size() >= bestLen) {
            bestLen = entry.mountPoint.size();
            flags = entry.flags;
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

const char *PolicyMountModeName(SandboxConfig::PolicyMountMode mode)
{
    switch (mode) {
        case SandboxConfig::PolicyMountMode::RO:
            return "ro";
        case SandboxConfig::PolicyMountMode::NONE:
            return "none";
        default:
            return "unknown";
    }
}

int SplitBindTarget(const std::string &target, std::vector<std::string> &components)
{
    if (!IsCanonicalAbsolutePath(target) || target == "/") {
        std::cerr << "Error: Invalid bind mount target: " << target << std::endl;
        SANDBOX_LOGE("Invalid bind mount target: %{public}s", target.c_str());
        return SANDBOX_ERR_PATH_INVALID;
    }

    size_t start = 1;
    while (start < target.size()) {
        size_t end = target.find('/', start);
        if (end == std::string::npos) {
            end = target.size();
        }
        components.push_back(target.substr(start, end - start));
        start = end + 1;
    }
    if (components.empty()) {
        return SANDBOX_ERR_PATH_INVALID;
    }
    return SANDBOX_SUCCESS;
}

/*
 * Number of path components. "/" is the root and must sort before every other
 * target; counting the single slash it contains would put it on the same level
 * as "/data".
 */
size_t TargetDepth(const std::string &target)
{
    return target == "/" ? 0 :
        static_cast<size_t>(std::count(target.begin(), target.end(), '/'));
}

int OpenBindRoot(const std::string &root, int &rootFd)
{
    rootFd = open(root.c_str(), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (rootFd < 0) {
        std::cerr << "Error: Failed to open sandbox root " << root << ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to open sandbox root %{public}s: %{public}s", root.c_str(), strerror(errno));
        return SANDBOX_ERR_PATH_INVALID;
    }
    SANDBOX_FDSAN_MARK(rootFd, SANDBOX_FDSAN_SITE_POLICY_TARGET);
    return SANDBOX_SUCCESS;
}

/*
 * Walk (and create) every component but the last, relative to the pinned
 * sandbox root. No component may be a symlink. On success dirFd is the parent
 * directory of the leaf, which is copied to leaf.
 */
int OpenBindParent(const std::string &root, const std::string &target, int &dirFd, std::string &leaf)
{
    std::vector<std::string> components;
    int ret = SplitBindTarget(target, components);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    ret = OpenBindRoot(NormalizeRootPath(root), dirFd);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    for (size_t i = 0; i + 1 < components.size(); ++i) {
        const std::string &component = components[i];
        int nextFd = openat(dirFd, component.c_str(),
                            O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (nextFd < 0 && errno == ENOENT) {
            if (mkdirat(dirFd, component.c_str(), DIR_MODE) < 0 && errno != EEXIST) {
                std::cerr << "Error: Failed to create bind mount parent " << component <<
                             ": " << strerror(errno) << std::endl;
                SANDBOX_LOGE("Failed to create bind mount parent %{public}s: %{public}s",
                    component.c_str(), strerror(errno));
                SANDBOX_FDSAN_CLOSE(dirFd, SANDBOX_FDSAN_SITE_POLICY_TARGET);
                return SANDBOX_ERR_PATH_CREATE_FAILED;
            }
            nextFd = openat(dirFd, component.c_str(),
                            O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        if (nextFd < 0) {
            std::cerr << "Error: Bind mount target component " << component <<
                         " is not a real directory: " << strerror(errno) << std::endl;
            SANDBOX_LOGE("Bind mount target component %{public}s is not a real directory: %{public}s",
                component.c_str(), strerror(errno));
            SANDBOX_FDSAN_CLOSE(dirFd, SANDBOX_FDSAN_SITE_POLICY_TARGET);
            return SANDBOX_ERR_PATH_INVALID;
        }
        SANDBOX_FDSAN_MARK(nextFd, SANDBOX_FDSAN_SITE_POLICY_TARGET);
        SANDBOX_FDSAN_CLOSE(dirFd, SANDBOX_FDSAN_SITE_POLICY_TARGET);
        dirFd = nextFd;
    }

    leaf = components.back();
    return SANDBOX_SUCCESS;
}

int PrepareBindDirectoryTarget(int dirFd, const std::string &leaf, int &targetFd)
{
    targetFd = -1;
    if (mkdirat(dirFd, leaf.c_str(), DIR_MODE) < 0 && errno != EEXIST) {
        std::cerr << "Error: Failed to create bind mount directory " << leaf <<
                     ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to create bind mount directory %{public}s: %{public}s",
            leaf.c_str(), strerror(errno));
        return SANDBOX_ERR_PATH_CREATE_FAILED;
    }
    targetFd = openat(dirFd, leaf.c_str(),
                      O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (targetFd < 0) {
        std::cerr << "Error: Failed to open bind mount directory " << leaf <<
                     ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to open bind mount directory %{public}s: %{public}s",
            leaf.c_str(), strerror(errno));
        return SANDBOX_ERR_PATH_INVALID;
    }
    SANDBOX_FDSAN_MARK(targetFd, SANDBOX_FDSAN_SITE_POLICY_TARGET);
    return SANDBOX_SUCCESS;
}

/*
 * A non-directory target is mounted as-is. A symlink leaf is refused because
 * mount() would follow it and land elsewhere; a directory leaf is refused
 * because it does not match the source.
 */
int ValidateNonDirectoryBindTarget(int targetFd, const std::string &leaf)
{
    struct stat st;
    if (fstat(targetFd, &st) != 0) {
        std::cerr << "Error: Failed to stat bind mount target " << leaf <<
                     ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to stat bind mount target %{public}s: %{public}s",
            leaf.c_str(), strerror(errno));
        return SANDBOX_ERR_PATH_INVALID;
    }
    if (S_ISLNK(st.st_mode)) {
        std::cerr << "Error: Bind mount target " << leaf << " is a symlink" << std::endl;
        SANDBOX_LOGE("Bind mount target %{public}s is a symlink", leaf.c_str());
        return SANDBOX_ERR_PATH_INVALID;
    }
    if (S_ISDIR(st.st_mode)) {
        std::cerr << "Error: Bind mount target " << leaf <<
                     " is a directory but the source is not" << std::endl;
        SANDBOX_LOGE("Bind mount target %{public}s is a directory but the source is not",
            leaf.c_str());
        return SANDBOX_ERR_PATH_INVALID;
    }
    return SANDBOX_SUCCESS;
}

/*
 * Any non-directory inode can be bind mounted. A missing target is created as
 * a regular file for the mount to cover.
 */
int PrepareBindNonDirectoryTarget(int dirFd, const std::string &leaf, int &targetFd)
{
    targetFd = openat(dirFd, leaf.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (targetFd < 0 && errno == ENOENT) {
        int createFd = openat(dirFd, leaf.c_str(),
                              O_CREAT | O_WRONLY | O_CLOEXEC | O_NOFOLLOW,
                              BIND_TARGET_FILE_MODE);
        if (createFd < 0 && errno != EEXIST) {
            std::cerr << "Error: Failed to create bind mount file " << leaf <<
                         ": " << strerror(errno) << std::endl;
            SANDBOX_LOGE("Failed to create bind mount file %{public}s: %{public}s",
                leaf.c_str(), strerror(errno));
            return SANDBOX_ERR_PATH_CREATE_FAILED;
        }
        if (createFd >= 0) {
            SANDBOX_FDSAN_MARK(createFd, SANDBOX_FDSAN_SITE_POLICY_TARGET);
            SANDBOX_FDSAN_CLOSE(createFd, SANDBOX_FDSAN_SITE_POLICY_TARGET);
        }
        targetFd = openat(dirFd, leaf.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC);
    }
    if (targetFd < 0) {
        std::cerr << "Error: Failed to open bind mount target " << leaf <<
                     ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to open bind mount target %{public}s: %{public}s",
            leaf.c_str(), strerror(errno));
        return SANDBOX_ERR_PATH_INVALID;
    }
    SANDBOX_FDSAN_MARK(targetFd, SANDBOX_FDSAN_SITE_POLICY_TARGET);

    int ret = ValidateNonDirectoryBindTarget(targetFd, leaf);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_FDSAN_CLOSE(targetFd, SANDBOX_FDSAN_SITE_POLICY_TARGET);
        targetFd = -1;
        return ret;
    }
    return SANDBOX_SUCCESS;
}

/*
 * Create or validate one target without resolving a symlink: walk from a
 * pinned parent and return an O_PATH fd so mount() can target
 * /proc/self/fd/<leaf>. Reopen the target before remounting - the fd names the
 * mount that existed when it was opened, not the one just attached.
 */
int OpenBindTarget(const std::string &root, const std::string &target,
                   bool isDirectory, int &targetFd, std::string &procTargetPath)
{
    int dirFd = -1;
    std::string leaf;
    int ret = OpenBindParent(root, target, dirFd, leaf);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    ret = isDirectory ? PrepareBindDirectoryTarget(dirFd, leaf, targetFd) :
                        PrepareBindNonDirectoryTarget(dirFd, leaf, targetFd);
    SANDBOX_FDSAN_CLOSE(dirFd, SANDBOX_FDSAN_SITE_POLICY_TARGET);
    if (ret != SANDBOX_SUCCESS) {
        std::cerr << "Error: Failed to prepare bind mount target " << target <<
                     ", ret=" << ret << std::endl;
        SANDBOX_LOGE("Failed to prepare bind mount target %{public}s, ret=%{public}d",
            target.c_str(), ret);
        return ret;
    }

    procTargetPath = "/proc/self/fd/" + std::to_string(targetFd);
    return SANDBOX_SUCCESS;
}

/*
 * A "/" target names the sandbox root itself rather than a path below it. The
 * root is created by CreateNewRoot and is never walked component by component:
 * a bind aimed at "/" lands directly on it.
 */
int OpenMountTarget(const std::string &root, const std::string &target, bool isDirectory,
                    int &targetFd, std::string &procTargetPath)
{
    if (target != "/") {
        return OpenBindTarget(root, target, isDirectory, targetFd, procTargetPath);
    }
    if (!isDirectory) {
        std::cerr << "Error: Bind target / requires a directory source" << std::endl;
        SANDBOX_LOGE("Bind target / requires a directory source");
        return SANDBOX_ERR_PATH_INVALID;
    }
    targetFd = open(NormalizeRootPath(root).c_str(),
                    O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (targetFd < 0) {
        std::cerr << "Error: Failed to open sandbox root " << root <<
                     ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to open sandbox root %{public}s: %{public}s",
            root.c_str(), strerror(errno));
        return SANDBOX_ERR_PATH_INVALID;
    }
    SANDBOX_FDSAN_MARK(targetFd, SANDBOX_FDSAN_SITE_POLICY_TARGET);
    procTargetPath = "/proc/self/fd/" + std::to_string(targetFd);
    return SANDBOX_SUCCESS;
}

/*
 * Pin the source inode with O_PATH. Symlinks are followed, as mount() does;
 * every inode type is bindable and only directories are recursed into. A
 * failure only leaves a hilog line here; the caller knows whether a missing
 * source is benign (checkExists) or fatal and logs to the user accordingly.
 */
int OpenBindSource(const std::string &source, bool &isDirectory)
{
    int fd = open(source.c_str(), O_PATH | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    SANDBOX_FDSAN_MARK(fd, SANDBOX_FDSAN_SITE_MOUNT_SRC);

    struct stat st;
    if (fstat(fd, &st) != 0) {
        SANDBOX_LOGE("fstat failed for %{public}s: %{public}s", source.c_str(), strerror(errno));
        SANDBOX_FDSAN_CLOSE(fd, SANDBOX_FDSAN_SITE_MOUNT_SRC);
        return -1;
    }
    isDirectory = S_ISDIR(st.st_mode);
    return fd;
}

// Remount the bind just attached readonly, keeping nosuid/nodev/noexec.
int RemountBindReadOnly(const std::string &mountTarget,
                        const std::string &procTargetPath, bool isDirectory)
{
    unsigned long mountedFlags = 0;
    int ret = GetMountFlags(mountTarget, mountedFlags);
    if (ret == SANDBOX_SUCCESS) {
        unsigned long remountFlags = MS_BIND | MS_REMOUNT | MS_RDONLY |
            (isDirectory ? MS_REC : 0) | (mountedFlags & BIND_REMOUNT_KEEP_FLAGS);
        if (mount(nullptr, procTargetPath.c_str(), nullptr, remountFlags, nullptr) == 0) {
            SANDBOX_LOGD("Remounted bind path %{public}s as readonly", mountTarget.c_str());
            return SANDBOX_SUCCESS;
        }
        std::cerr << "Error: Failed to remount bind path " << mountTarget <<
                     " as readonly: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to remount bind path %{public}s as readonly: %{public}s",
            mountTarget.c_str(), strerror(errno));
        ret = SANDBOX_ERR_MOUNT_FAILED;
    }
    umount2(mountTarget.c_str(), MNT_DETACH);
    return ret;
}

} // namespace

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

// A mount point entry is the only thing that separates an attached mount from
// an ordinary directory that happens to have the same name.
bool SandboxManager::IsMountPoint(const std::string &path)
{
    std::vector<MountInfoEntry> entries;
    if (ReadMountInfo(entries) != SANDBOX_SUCCESS) {
        return false;
    }
    for (const auto &entry : entries) {
        if (entry.mountPoint == path) {
            return true;
        }
    }
    return false;
}

int SandboxManager::PrepareMountPlan()
{
    int ret = BuildMountPlan();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    ret = ValidateTemplateBindOps();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    std::set<std::string> policyTargets;
    ret = ValidatePolicyBindOps(policyTargets);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    ApplyPolicyOverrides(policyTargets);
    SortMountPlan(mountPlan_);

    SANDBOX_LOGD("Mount plan ready: binds=%{public}zu", mountPlan_.size());
    return SANDBOX_SUCCESS;
}

int SandboxManager::BuildMountPlan()
{
    mountPlan_.clear();

    int ret = AppendTemplateBindOps(MountOrigin::SYSTEM, templateConfig_.systemMounts);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    ret = AppendTemplateBindOps(MountOrigin::APP, templateConfig_.appMounts);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    AppendPolicyBindOps();
    return SANDBOX_SUCCESS;
}

int SandboxManager::AppendTemplateBindOps(MountOrigin origin,
                                          const std::vector<MountEntry> &entries)
{
    for (const auto &entry : entries) {
        if (origin == MountOrigin::SYSTEM &&
            entry.source == "/proc" && (config_.nsFlags & CLONE_NEWPID) != 0) {
            // Always mount procfs via mount -t proc, never bind-mount the
            // outer /proc: it would expose the full process list.
            SANDBOX_LOGD("Template bind %{public}s -> %{public}s skipped: "
                "PID namespace mounts procfs instead",
                entry.source.c_str(), entry.target.c_str());
            continue;
        }

        // Every remaining entry is collected; a "/" target is an ordinary op
        // that binds onto the sandbox root itself and sorts first.
        MountOp op;
        op.origin = origin;
        op.source = entry.source;
        op.target = entry.target;
        op.mountFlags = entry.mountFlags;
        // System entries have always been best-effort: a missing source is
        // absent from the view rather than fatal.
        op.checkExists = origin == MountOrigin::SYSTEM || entry.checkExists;
        op.seq = mountPlan_.size();
        mountPlan_.push_back(std::move(op));
    }
    return SANDBOX_SUCCESS;
}

void SandboxManager::AppendPolicyBindOps()
{
    for (const auto &policyMount : config_.policy.mounts) {
        if (policyMount.source == "/proc" ||
            policyMount.source.compare(0, sizeof("/proc/") - 1, "/proc/") == 0) {
            SANDBOX_LOGD("Policy mount %{public}s skipped: /proc is platform-provided",
                policyMount.source.c_str());
            continue;
        }
        MountOp op;
        op.origin = MountOrigin::POLICY;
        // A policy mount uses one path as both source and target.
        op.source = policyMount.source;
        op.target = policyMount.source;
        op.mode = policyMount.mode;
        op.seq = mountPlan_.size();
        mountPlan_.push_back(std::move(op));
    }
}

/*
 * A policy mount replaces a template bind at the same target - only one can be
 * the mount there. Ancestor or descendant targets are not overrides; the sort
 * orders them parent first.
 */
void SandboxManager::ApplyPolicyOverrides(const std::set<std::string> &policyTargets)
{
    if (policyTargets.empty()) {
        return;
    }

    auto removedBegin = std::remove_if(mountPlan_.begin(), mountPlan_.end(),
        [&policyTargets](const MountOp &op) {
            if (op.origin == MountOrigin::POLICY || policyTargets.count(op.target) == 0) {
                return false;
            }
            SANDBOX_LOGD("Policy mount %{public}s overrides template bind %{public}s",
                op.target.c_str(), op.source.c_str());
            return true;
        });
    mountPlan_.erase(removedBegin, mountPlan_.end());
}

int SandboxManager::ValidateTemplateBindOps() const
{
    for (const auto &op : mountPlan_) {
        if (op.origin == MountOrigin::POLICY) {
            continue;
        }
        if (!IsCanonicalAbsolutePath(op.target)) {
            std::cerr << "Error: Invalid template mount target: " << op.target << std::endl;
            SANDBOX_LOGE("Invalid template mount target: %{public}s", op.target.c_str());
            return SANDBOX_ERR_TEMPLATE_INVALID;
        }
        if (!IsCanonicalAbsolutePath(op.source)) {
            std::cerr << "Error: Invalid template mount source: " << op.source << std::endl;
            SANDBOX_LOGE("Invalid template mount source: %{public}s", op.source.c_str());
            return SANDBOX_ERR_TEMPLATE_INVALID;
        }
        if (!HasOnlyKnownMountFlags(op.mountFlags)) {
            std::cerr << "Error: Unknown mount flag in template entry " << op.target << std::endl;
            SANDBOX_LOGE("Unknown mount flag in template entry %{public}s", op.target.c_str());
            return SANDBOX_ERR_TEMPLATE_INVALID;
        }
        const unsigned long flags = ConvertMountFlags(op.mountFlags);
        if ((flags & MS_BIND) == 0 || (flags & (MS_MOVE | MS_REMOUNT)) != 0) {
            std::cerr << "Error: Template mount " << op.target <<
                         " must be a bind mount" << std::endl;
            SANDBOX_LOGE("Template mount %{public}s must be a bind mount", op.target.c_str());
            return SANDBOX_ERR_TEMPLATE_INVALID;
        }
    }
    return SANDBOX_SUCCESS;
}

/*
 * Policy targets are checked for their own legality only. Nesting either way
 * is fine because the sort mounts the parent first; exact targets are
 * overrides, not nesting. Symbol links are not compared - they are created
 * after the binds, and writing through a bind is accepted. policyTargets is
 * filled here so ApplyPolicyOverrides does not scan the plan again.
 */
int SandboxManager::ValidatePolicyBindOps(std::set<std::string> &policyTargets) const
{
    for (const auto &op : mountPlan_) {
        if (op.origin != MountOrigin::POLICY) {
            continue;
        }
        // "/" is legal: the policy source is also "/", so the bind carries the
        // whole filesystem to the sandbox root and the mode applies to that
        // mount.
        if (!IsCanonicalAbsolutePath(op.target)) {
            std::cerr << "Error: Invalid policy mount target: " << op.target << std::endl;
            SANDBOX_LOGE("Invalid policy mount target: %{public}s", op.target.c_str());
            return SANDBOX_ERR_PATH_INVALID;
        }
        if (!policyTargets.insert(op.target).second) {
            std::cerr << "Error: Duplicate policy mount target: " << op.target << std::endl;
            SANDBOX_LOGE("Duplicate policy mount target: %{public}s", op.target.c_str());
            return SANDBOX_ERR_CONFIG_INVALID;
        }
    }
    return SANDBOX_SUCCESS;
}

void SandboxManager::SortMountPlan(std::vector<MountOp> &ops)
{
    std::stable_sort(ops.begin(), ops.end(),
        [](const MountOp &lhs, const MountOp &rhs) {
            /*
             * Parents before children: a parent must attach first or it would
             * cover its children. Same-depth targets are never ancestors, so
             * seq just keeps the order deterministic.
             */
            const auto lhsDepth = TargetDepth(lhs.target);
            const auto rhsDepth = TargetDepth(rhs.target);
            if (lhsDepth != rhsDepth) {
                return lhsDepth < rhsDepth;
            }
            return lhs.seq < rhs.seq;
        });
}

std::string SandboxManager::GetMountTargetPath(const MountOp &op) const
{
    const std::string &root = GetMountRootPath();
    if (root.empty()) {
        return op.target;
    }
    // The root itself, not the root plus a trailing slash: mountinfo compares
    // the mount point by name, and cleanup unmounts by this path.
    if (op.target == "/") {
        return NormalizeRootPath(root);
    }
    return JoinViewPath(root, op.target);
}

void SandboxManager::DumpMountPlan() const
{
    SANDBOX_LOGD("Executing mount plan under %{public}s: %{public}zu bind(s)",
        GetMountRootPath().c_str(), mountPlan_.size());
    for (size_t i = 0; i < mountPlan_.size(); ++i) {
        const MountOp &op = mountPlan_[i];
        std::string flags;
        for (const auto &flag : op.mountFlags) {
            flags += flags.empty() ? "" : ",";
            flags += flag;
        }
        const char *originName = "unknown";
        switch (op.origin) {
            case MountOrigin::SYSTEM:
                originName = "system";
                break;
            case MountOrigin::APP:
                originName = "app";
                break;
            case MountOrigin::POLICY:
                originName = "policy";
                break;
            default:
                break;
        }
        SANDBOX_LOGD("Mount plan[%{public}zu]: %{public}s bind %{public}s -> %{public}s "
            "flags=[%{public}s] mode=%{public}s", i, originName,
            op.source.c_str(), op.target.c_str(), flags.c_str(), PolicyMountModeName(op.mode));
    }
}

int SandboxManager::ExecuteMountPlan()
{
    if (mountPlan_.empty()) {
        return SANDBOX_SUCCESS;
    }

    DumpMountPlan();

    for (const auto &op : mountPlan_) {
        int ret = ExecuteBindOp(op);
        if (ret != SANDBOX_SUCCESS) {
            std::cerr << "Error: Mount plan failed on " << op.source << " -> " << op.target <<
                         ", ret=" << ret << std::endl;
            SANDBOX_LOGE("Mount plan failed on %{public}s -> %{public}s, ret=%{public}d",
                op.source.c_str(), op.target.c_str(), ret);
            return ret;
        }
    }
    SANDBOX_LOGD("Mount plan executed: %{public}zu bind(s)", mountPlan_.size());
    return SANDBOX_SUCCESS;
}

/*
 * A policy bind always recurses into a directory source and carries no
 * template flags; a template bind keeps whatever the entry declared.
 */
unsigned long SandboxManager::BindOpFlags(const MountOp &op, bool sourceIsDirectory)
{
    if (op.origin == MountOrigin::POLICY) {
        return MS_BIND | (sourceIsDirectory ? MS_REC : 0);
    }
    return ConvertMountFlags(op.mountFlags);
}

/*
 * Attach the bind itself, naming both sides through their pinned fds so
 * neither can be swapped between validation and the mount.
 */
int SandboxManager::AttachBind(const MountOp &op, const std::string &mountTarget,
                               int srcFd, const std::string &procTargetPath,
                               unsigned long allFlags)
{
    const std::string procSourcePath = "/proc/self/fd/" + std::to_string(srcFd);
    if (mount(procSourcePath.c_str(), procTargetPath.c_str(), nullptr,
              allFlags & ~PROPAGATION_MASK, nullptr) < 0) {
        std::cerr << "Error: Failed to bind " << op.source << " -> " << mountTarget <<
                     ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to bind %{public}s -> %{public}s: %{public}s",
            op.source.c_str(), mountTarget.c_str(), strerror(errno));
        return SANDBOX_ERR_MOUNT_FAILED;
    }
    return SANDBOX_SUCCESS;
}

/*
 * Open the target and attach the bind there. The target fd is only good for
 * the mount call, so it is closed right after.
 */
int SandboxManager::AttachBindAtTarget(const MountOp &op, const std::string &root,
                                       const std::string &mountTarget, int srcFd,
                                       bool sourceIsDirectory, unsigned long allFlags)
{
    int targetFd = -1;
    std::string procTargetPath;
    int ret = OpenMountTarget(root, op.target, sourceIsDirectory, targetFd, procTargetPath);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    ret = AttachBind(op, mountTarget, srcFd, procTargetPath, allFlags);
    SANDBOX_FDSAN_CLOSE(targetFd, SANDBOX_FDSAN_SITE_POLICY_TARGET);
    return ret;
}

/*
 * Force the bind readonly when the template's rdonly flag or a policy ro asks
 * for it. "rw" and "none" change nothing here: the bind already carries the
 * source's mode. The fd used for the bind names the mount that existed when it
 * was opened, so the target is opened again now that the bind is attached.
 */
int SandboxManager::ApplyBindMode(const MountOp &op, const std::string &root,
                                  const std::string &mountTarget, bool sourceIsDirectory,
                                  unsigned long allFlags)
{
    const bool templateWantsReadOnly = (allFlags & MS_RDONLY) != 0;
    const bool policyForcesReadOnly = op.origin == MountOrigin::POLICY &&
        op.mode == SandboxConfig::PolicyMountMode::RO;
    if (!templateWantsReadOnly && !policyForcesReadOnly) {
        return SANDBOX_SUCCESS;
    }

    int targetFd = -1;
    std::string procTargetPath;
    int ret = OpenMountTarget(root, op.target, sourceIsDirectory, targetFd, procTargetPath);
    if (ret != SANDBOX_SUCCESS) {
        umount2(mountTarget.c_str(), MNT_DETACH);
        return ret;
    }
    ret = RemountBindReadOnly(mountTarget, procTargetPath, sourceIsDirectory);
    SANDBOX_FDSAN_CLOSE(targetFd, SANDBOX_FDSAN_SITE_POLICY_TARGET);
    return ret;
}

int SandboxManager::ApplyBindPropagation(const std::string &mountTarget, unsigned long propFlags)
{
    if (propFlags == 0) {
        return SANDBOX_SUCCESS;
    }
    if (mount(nullptr, mountTarget.c_str(), nullptr, propFlags, nullptr) < 0) {
        std::cerr << "Error: Failed to set propagation on " << mountTarget <<
                     ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to set propagation on %{public}s: %{public}s",
            mountTarget.c_str(), strerror(errno));
        umount2(mountTarget.c_str(), MNT_DETACH);
        return SANDBOX_ERR_MOUNT_FAILED;
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::ExecuteBindOp(const MountOp &op)
{
    const std::string root = GetMountRootPath();
    if (root.empty()) {
        std::cerr << "Error: Refusing to bind " << op.target << " without a sandbox root" << std::endl;
        SANDBOX_LOGE("Refusing to bind %{public}s without a sandbox root", op.target.c_str());
        return SANDBOX_ERR_PATH_INVALID;
    }
    const std::string mountTarget = GetMountTargetPath(op);

    bool sourceIsDirectory = false;
    int srcFd = OpenBindSource(op.source, sourceIsDirectory);
    if (srcFd < 0) {
        if (op.checkExists && errno == ENOENT) {
            SANDBOX_LOGD("Bind source %{public}s is absent, skipping", op.source.c_str());
            return SANDBOX_SUCCESS;
        }
        std::cerr << "Error: Failed to open bind source " << op.source <<
                     ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to open bind source %{public}s: %{public}s",
            op.source.c_str(), strerror(errno));
        return op.origin == MountOrigin::POLICY ? SANDBOX_ERR_PATH_INVALID :
                                                  SANDBOX_ERR_MOUNT_FAILED;
    }

    const unsigned long allFlags = BindOpFlags(op, sourceIsDirectory);
    int ret = AttachBindAtTarget(op, root, mountTarget, srcFd, sourceIsDirectory, allFlags);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_FDSAN_CLOSE(srcFd, SANDBOX_FDSAN_SITE_MOUNT_SRC);
        return ret;
    }

    ret = ApplyBindMode(op, root, mountTarget, sourceIsDirectory, allFlags);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_FDSAN_CLOSE(srcFd, SANDBOX_FDSAN_SITE_MOUNT_SRC);
        return ret;
    }

    ret = ApplyBindPropagation(mountTarget, allFlags & PROPAGATION_MASK);
    SANDBOX_FDSAN_CLOSE(srcFd, SANDBOX_FDSAN_SITE_MOUNT_SRC);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    mountTargets_.push_back(mountTarget);
    SANDBOX_LOGD("Bind mounted source=%{public}s, target=%{public}s, origin=%{public}d, mode=%{public}s",
        op.source.c_str(), mountTarget.c_str(), static_cast<int>(op.origin),
        PolicyMountModeName(op.mode));
    return SANDBOX_SUCCESS;
}

/*
 * ============================ Symbol links ============================
 *
 * Created after the binds: a link's source only exists in the view once the
 * mounts it lives behind are attached.
 */

int SandboxManager::CreateTemplateSymlinks()
{
    if (templateConfig_.symLinks.empty()) {
        return SANDBOX_SUCCESS;
    }

    SANDBOX_LOGD("Creating %{public}zu template symbol link(s) under %{public}s",
        templateConfig_.symLinks.size(), GetMountRootPath().c_str());
    for (const auto &entry : templateConfig_.symLinks) {
        int ret = CreateSymlink(entry);
        if (ret != SANDBOX_SUCCESS) {
            SANDBOX_LOGE("Template symbol link failed on %{public}s -> %{public}s, ret=%{public}d",
                entry.target.c_str(), entry.source.c_str(), ret);
            return ret;
        }
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::ValidateSymLinkEntry(const SymLinkEntry &entry)
{
    if (!IsCanonicalAbsolutePath(entry.target) || entry.target == "/") {
        std::cerr << "Error: Invalid template symbol-link target: " << entry.target << std::endl;
        SANDBOX_LOGE("Invalid template symbol-link target: %{public}s", entry.target.c_str());
        return SANDBOX_ERR_TEMPLATE_INVALID;
    }
    if (!IsCanonicalAbsolutePath(entry.source)) {
        std::cerr << "Error: Invalid template symbol-link source: " << entry.source << std::endl;
        SANDBOX_LOGE("Invalid template symbol-link source: %{public}s", entry.source.c_str());
        return SANDBOX_ERR_TEMPLATE_INVALID;
    }
    return SANDBOX_SUCCESS;
}

/*
 * Whatever already occupies the link path wins: a node carried in by the "/"
 * bind, a mount attached by the plan, or an earlier link. The source only
 * matters when the link would actually be created; then a missing one fails
 * the launch because the template link and the mounts it depends on disagree.
 */
int SandboxManager::CheckSymLinkPreconditions(const SymLinkEntry &entry,
                                              const std::string &linkPath,
                                              const std::string &viewSource, bool &proceed)
{
    proceed = false;
    struct stat st = {};
    if (lstat(linkPath.c_str(), &st) == 0) {
        SANDBOX_LOGD("Symlink target %{public}s already exists, skipping", linkPath.c_str());
        return SANDBOX_SUCCESS;
    }
    // Any other lstat failure is left to symlink(), which resolves the same
    // path and reports the same errno.
    if (access(viewSource.c_str(), F_OK) != 0) {
        std::cerr << "Error: Symlink source " << entry.source << " is missing from the sandbox view ("
                  << viewSource << "): " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Symlink source %{public}s is missing from the sandbox view (%{public}s): "
            "%{public}s", entry.source.c_str(), viewSource.c_str(), strerror(errno));
        return SANDBOX_ERR_SYMLINK_FAILED;
    }
    proceed = true;
    return SANDBOX_SUCCESS;
}

int SandboxManager::CreateSymLinkNode(const SymLinkEntry &entry, const std::string &linkPath)
{
    if (symlink(entry.source.c_str(), linkPath.c_str()) < 0) {
        if (errno == EEXIST) {
            SANDBOX_LOGD("Symlink target %{public}s appeared concurrently, skipping",
                linkPath.c_str());
            return SANDBOX_SUCCESS;
        }
        std::cerr << "Error: Failed to symlink " << linkPath << " -> " << entry.source <<
                  ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to symlink %{public}s -> %{public}s: %{public}s",
            linkPath.c_str(), entry.source.c_str(), strerror(errno));
        return SANDBOX_ERR_SYMLINK_FAILED;
    }
    SANDBOX_LOGD("Symlinked %{public}s -> %{public}s", linkPath.c_str(), entry.source.c_str());
    return SANDBOX_SUCCESS;
}

int SandboxManager::CreateSymlink(const SymLinkEntry &entry)
{
    /*
     * Validated here, after the binds, because a link only makes sense against
     * the view they produced. Source is the link's content, target its path.
     */
    int ret = ValidateSymLinkEntry(entry);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    const std::string &root = GetMountRootPath();
    const std::string linkPath = JoinViewPath(root, entry.target);
    const std::string viewSource = JoinViewPath(root, entry.source);
    SANDBOX_LOGD("Executing symlink %{public}s -> %{public}s under %{public}s",
        linkPath.c_str(), entry.source.c_str(), root.c_str());

    bool proceed = false;
    ret = CheckSymLinkPreconditions(entry, linkPath, viewSource, proceed);
    if (ret != SANDBOX_SUCCESS || !proceed) {
        return ret;
    }
    return CreateSymLinkNode(entry, linkPath);
}

/*
 * =========================== Caller entry ===========================
 *
 * Join the caller's mount namespace before the sandbox view is built.
 */

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
    SANDBOX_FDSAN_MARK(procFd, SANDBOX_FDSAN_SITE_PROC_DIR);

    struct stat procStat;
    if (fstat(procFd, &procStat) != 0) {
        std::cerr << "Error: fstat failed for " << procPath << ": " <<
                  strerror(errno) << std::endl;
        SANDBOX_LOGE("fstat failed for %{public}s: %{public}s",
            procPath, strerror(errno));
        SANDBOX_FDSAN_CLOSE(procFd, SANDBOX_FDSAN_SITE_PROC_DIR);
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
        SANDBOX_FDSAN_CLOSE(procFd, SANDBOX_FDSAN_SITE_PROC_DIR);
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
        SANDBOX_FDSAN_CLOSE(procFd, SANDBOX_FDSAN_SITE_PROC_DIR);
        return SANDBOX_ERR_NS_FAILED;
    }
    SANDBOX_FDSAN_MARK(nsFd, SANDBOX_FDSAN_SITE_NS_MNT);
    SANDBOX_FDSAN_CLOSE(procFd, SANDBOX_FDSAN_SITE_PROC_DIR);
    return SANDBOX_SUCCESS;
}

static int ReadNamespaceId(pid_t callerPid, char *nsTarget, size_t nsTargetSize)
{
    char nsPath[NS_PATH_BUF_SIZE] = {0};
    int ret = snprintf_s(nsPath, sizeof(nsPath), sizeof(nsPath) - 1,
                         "/proc/%d/ns/mnt", callerPid);
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

    pid_t callerPid = config_.callerPid;
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
        SANDBOX_FDSAN_CLOSE(nsFd, SANDBOX_FDSAN_SITE_NS_MNT);
        return ret;
    }

    if (setns(nsFd, 0) < 0) {
        std::cerr << "Error: setns failed for pid " << callerPid <<
                  ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("setns failed for pid %{public}d: %{public}s",
            callerPid, strerror(errno));
        SANDBOX_FDSAN_CLOSE(nsFd, SANDBOX_FDSAN_SITE_NS_MNT);
        return SANDBOX_ERR_NS_FAILED;
    }
    SANDBOX_FDSAN_CLOSE(nsFd, SANDBOX_FDSAN_SITE_NS_MNT);

    ret = VerifyNamespaceChanged(callerPid, nsTarget);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    SANDBOX_LOGD("Entered caller sandbox (pid=%{public}d)", callerPid);
    return SANDBOX_SUCCESS;
}

/*
 * ==================== Sandbox root and namespace ====================
 *
 * Create the root the view is built in, enter the new mount namespace, and
 * make the root a mount point for pivot_root.
 */

static std::string GenerateSandboxName(void)
{
    // Calculate required bytes: 1 byte provides 2 hexadecimal characters.
    size_t byteCnt = (HEX_CNT + 1) / 2;
    std::vector<unsigned char> rand_bytes(byteCnt);

    // Fetch cryptographically secure pseudo-random bytes.
    // GRND_NONBLOCK ensures the system call does not block the sandbox process.
    ssize_t ret = getrandom(rand_bytes.data(), rand_bytes.size(), GRND_NONBLOCK);
    if (ret != static_cast<ssize_t>(rand_bytes.size())) {
        // Sandbox security must not be compromised; fail hard if entropy is unavailable.
        return "";
    }

    std::ostringstream oss;
    for (size_t i = 0; i < byteCnt; ++i) {
        // setw(2) and setfill('0') guarantee that values like 0x5 become "05" instead of "5".
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(rand_bytes[i]);
    }

    std::string result = oss.str();

    // Truncate the extra character if HEX_CNT is an odd number.
    return result.substr(0, HEX_CNT);
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
        if (sandboxName.empty()) {
            std::cerr << "Error: Failed to generate secure random sandbox name" << std::endl;
            SANDBOX_LOGE("Failed to generate secure random sandbox name");
            return SANDBOX_ERR_SANDBOX_PATH_EXHAUSTED;
        }

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

const std::string &SandboxManager::GetMountRootPath() const
{
    return newRootPath_;
}

int SandboxManager::CreateNewRoot()
{
    int ret = SANDBOX_SUCCESS;
    if (!config_.name.empty()) {
        ret = CreateSandboxWithName(config_.name);
    } else {
        ret = CreateSandboxAutoName();
    }
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    /*
     * The sandbox directory is the view root: binds attach under it and
     * pivot_root enters it directly. A "/" bind fills it with its source.
     */
    SANDBOX_LOGD("Created new root at %{public}s", newRootPath_.c_str());
    return SANDBOX_SUCCESS;
}

int SandboxManager::UnshareNamespaces()
{
    if (unshare(static_cast<int>(config_.nsFlags)) < 0) {
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
    /*
     * pivot_root needs the sandbox root to be a mount point. A plan "/" bind
     * stacks on top.
     */
    if (mount(newRootPath_.c_str(), newRootPath_.c_str(),
              nullptr, MS_BIND | MS_REC, nullptr) < 0) {
        std::cerr << "Error: mount --bind new root failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("mount --bind new root failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_MOUNT_FAILED;
    }
    mountTargets_.push_back(newRootPath_);

    return SANDBOX_SUCCESS;
}

int SandboxManager::MountProcFs()
{
    if ((config_.nsFlags & CLONE_NEWPID) == 0) {
        return SANDBOX_SUCCESS;
    }

    /*
     * With a PID namespace the plan drops the template's /proc bind, so create
     * the mount point here. Runs after pivot_root, where "/proc" is the view
     * path.
     */
    int ret = CreateDir("/proc");
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, nullptr) < 0) {
        std::cerr << "Error: mount procfs failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("mount procfs failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_MOUNT_FAILED;
    }
    SANDBOX_LOGD("Mounted procfs on /proc for pid namespace");
    return SANDBOX_SUCCESS;
}

int SandboxManager::PivotRoot()
{
    /*
     * "." is both new root and put_old, so no put_old directory is needed - a
     * plan "/" bind would cover one. The kernel stacks the old root on this
     * mount point; the umount below detaches it lazily and leaves the view.
     */
    if (chdir(newRootPath_.c_str()) < 0) {
        std::cerr << "Error: chdir new root failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("chdir new root failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_CHDIR_FAILED;
    }
    if (syscall(SYS_pivot_root, ".", ".") < 0) {
        std::cerr << "Error: pivot_root failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("pivot_root failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_NS_FAILED;
    }
    /*
     * The process root is the new root from here on, so the pre-pivot path no
     * longer names the same directory: cleanup must not run by path.
     */
    pivotRootDone_ = true;
    if (umount2(".", MNT_DETACH) < 0) {
        std::cerr << "Error: umount old root failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("umount old root failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_MOUNT_FAILED;
    }
    if (chdir("/") < 0) {
        std::cerr << "Error: chdir / after pivot_root failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("chdir / after pivot_root failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_CHDIR_FAILED;
    }
    // From here on the sandbox root is "/".
    newRootPath_ = "/";
    SANDBOX_LOGD("pivot_root completed");
    return SANDBOX_SUCCESS;
}

/*
 * ==================== Path helpers and cleanup ====================
 */

int SandboxManager::MountDir(const std::string &source, const std::string &target,
                             const std::vector<std::string> &mountFlags)
{
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
            std::cerr << "Error: Failed to set propagation on " << target <<
                      ": " << strerror(errno) << std::endl;
            SANDBOX_LOGE("Failed to set propagation on %{public}s: %{public}s",
                target.c_str(), strerror(errno));
            // The bind above exists but is not recorded yet: detach it so a
            // failed call cannot leave an untracked mount behind.
            umount2(target.c_str(), MNT_DETACH);
            return SANDBOX_ERR_MOUNT_FAILED;
        }
    }

    mountTargets_.push_back(target);
    return SANDBOX_SUCCESS;
}

static int MkdirIfNotExist(const std::string &dirPath)
{
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

/*
 * Only ever delete a directory this manager created. RemoveAll is used for the
 * sandbox root, and a wrong path here would delete host data.
 */
static bool IsOwnedSandboxRoot(const std::string &path)
{
    const std::string prefix = std::string(SANDBOX_BASE_DIR) + "/";
    return path.size() > prefix.size() && path.compare(0, prefix.size(), prefix) == 0;
}

void SandboxManager::Cleanup()
{
    if (pivotRootDone_) {
        SANDBOX_LOGD("Cleanup: pivot_root was performed, skip manual cleanup");
        SANDBOX_LOGD("Cleanup: namespace will be cleaned up by kernel on process exit");
        return;
    }

    // Unmount mount targets in reverse creation order
    bool unmountedAll = true;
    for (auto it = mountTargets_.rbegin(); it != mountTargets_.rend(); ++it) {
        if (umount2(it->c_str(), MNT_DETACH) < 0) {
            unmountedAll = false;
            SANDBOX_LOGW("umount %{public}s failed: %{public}s",
                it->c_str(), strerror(errno));
        }
    }
    mountTargets_.clear();

    /*
     * The sandbox root holds directories and symlinks now, so rmdir no longer
     * enough. remove_all may only run once every mount is gone: descending into
     * a still-mounted host tree would delete host data.
     */
    if (!newRootPath_.empty() && unmountedAll && IsOwnedSandboxRoot(newRootPath_)) {
        std::error_code ec;
        std::filesystem::remove_all(newRootPath_, ec);
        if (ec) {
            SANDBOX_LOGW("Cleanup: failed to remove %{public}s: %{public}s",
                newRootPath_.c_str(), ec.message().c_str());
        }
    } else if (!newRootPath_.empty() && unmountedAll) {
        SANDBOX_LOGW("Cleanup: %{public}s is not a sandbox root, not removing",
            newRootPath_.c_str());
    }

    newRootPath_.clear();
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS