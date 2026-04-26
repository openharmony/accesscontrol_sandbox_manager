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

#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <random>
#include <iomanip>
#include <algorithm>
#include <sched.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>

#include <securec.h>

#include <linux/securebits.h>

#ifndef pivot_root
#include <linux/version.h>
static inline int pivot_root(const char *new_root, const char *put_old)
{
    return syscall(SYS_pivot_root, new_root, put_old);
}
#endif

#include <selinux/selinux.h>
#ifdef WITH_SECCOMP
#include "seccomp_policy.h"
#endif

#include "sandbox_manager.h"
#include "sandbox_log.h"

#include "json/json.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"
#include "permission_list_state.h"
#include "access_token.h"
#include "ipc_skeleton.h"

#define CAP_NUM 2
#define MAX_TRY_CNT 3
#define UID_BASE 200000
static const mode_t DIR_MODE = 0711;
#define HEX_MAX 15
#define HEX_CNT 16
#define MAX_SANDBOX_NAME_LEN 64

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Sandbox {

int CreateDirRecursive(const std::string &path, mode_t mode = 0711);
bool IsDirectoryExist(const std::string &path);
int CreateDirectory(const std::string &path);
int CreateDirectoryIfNotExist(const std::string &path);

SandboxManager::SandboxManager()
{
    namespaceCreated_ = false;
    mountsCreated_ = false;
    pivotRootDone_ = false;
    ClearEnv();
}

SandboxManager::~SandboxManager()
{
    if (!sandboxCreated_) {
        CleanupAll();
    }
}

static int SetNsFromPid(pid_t pid, int cloneFlags)
{
    if (pid <= 0) {
        SANDBOX_LOGE("SetNsFromPid: Invalid pid: %{public}d", pid);
        return -1;
    }

    struct NsType {
        int flag;
        const char *name;
    };

    static const NsType nsTypes[] = {
        {CLONE_NEWNS, "mnt"},
        {CLONE_NEWNET, "net"},
        {CLONE_NEWUTS, "uts"},
        {CLONE_NEWIPC, "ipc"},
        {CLONE_NEWPID, "pid"},
        {CLONE_NEWUSER, "user"}
    };

    for (const auto &ns : nsTypes) {
        if ((cloneFlags & ns.flag) != 0) {
            std::string nsPath = "/proc/" + std::to_string(pid) + "/ns/" + std::string(ns.name);
            int fd = open(nsPath.c_str(), O_RDONLY);
            if (fd < 0) {
                SANDBOX_LOGE("SetNsFromPid: Failed to open nsPath: %{public}s", strerror(errno));
                return -1;
            }
            if (setns(fd, ns.flag) != 0) {
                SANDBOX_LOGE("SetNsFromPid: setns to nsPath failed: %{public}s", strerror(errno));
                close(fd);
                return -1;
            }
            close(fd);
            SANDBOX_LOGD("SetNsFromPid: successfully setns to nsPath");
        }
    }

    return 0;
}

void SandboxManager::ClearEnv()
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTERM);
    sigprocmask(SIG_UNBLOCK, &mask, nullptr);
}

int SandboxManager::SetAccessToken()
{
    int ret = SetSelfTokenID(config_.tokenId);
    if (ret != 0) {
        SANDBOX_LOGE("set access tokenid failed, ret: %{public}d", ret);
        return -1;
    }

    return 0;
}

void SandboxManager::CleanupAll()
{
    SANDBOX_LOGD("CleanupAll: Starting cleanup of all resources");

    if (pivotRootDone_) {
        SANDBOX_LOGW("CleanupAll: pivot_root was performed, cannot fully resotore");
    }

    if (mountsCreated_) {
        SANDBOX_LOGD("CleanupAll: Cleaning up mounts");
        CleanupSandbox();
    }

    if (namespaceCreated_) {
        SANDBOX_LOGD("CleanupAll: namespace was created, will be cleaned up by kernel on process exit");
    }

    SANDBOX_LOGD("CleanupAll: Cleanup completed");
}

int SandboxManager::CleanupSandbox()
{
    if (pivotRootDone_) {
        SANDBOX_LOGI("CleanupSandbox: pivot_root was performed, skip manual cleanup");
        SANDBOX_LOGI("CleanupSandbox: Namespace will be cleaned up on process exit");
        return 0;
    }

    std::string sandboxRoot = sandboxPath_;
    SANDBOX_LOGD("CleanupSandbox: Starting cleanup for sandboxRoot");

    if (umount2(sandboxRoot.c_str(), MNT_DETACH) != 0) {
        SANDBOX_LOGW("CleanupSandbox: umount2 failed for sandboxRoot: %{public}s", strerror(errno));
    }

    if (rmdir(sandboxRoot.c_str()) != 0) {
        SANDBOX_LOGW("CleanupSandbox: rmdir failed for sandboxRoot: %{public}s", strerror(errno));
    } else {
        SANDBOX_LOGD("CleanupSandbox: Sandbox directory removed");
    }

    SANDBOX_LOGD("CleanupSandbox: Cleanup completed");
    return 0;
}

// Generate Sandbox Name
static std::string GenerateSandboxName()
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

int SandboxManager::CreateSandboxPath()
{
    uint32_t tryCnt = 0;
    bool success = false;
    std::string sandboxPath;
    std::string sandboxName;

    // sandbox path <app-sandbox>/mnt/sandbox/claw/<name>
    if (config_.name.size() != 0) {
        sandboxPath = std::string(SANDBOX_BASE_DIR) + "/" + config_.name;
        if (CreateDirRecursive(sandboxPath, DIR_MODE) != 0) {
            SANDBOX_LOGE("Failed to create sandbox directory, errno: %{public}d %{public}s",
                errno, strerror(errno));
            return -1;
        }
        success = true;
    } else {
        while (tryCnt < MAX_TRY_CNT) {
            sandboxName = GenerateSandboxName();
            sandboxPath = std::string(SANDBOX_BASE_DIR) + "/" + sandboxName;
            if (IsDirectoryExist(sandboxPath)) {
                tryCnt++;
                continue;
            }
            if (CreateDirRecursive(sandboxPath, DIR_MODE) != 0) {
                SANDBOX_LOGE("Failed to create sandbox directory, errno: %{public}d %{public}s",
                    errno, strerror(errno));
                return -1;
            }
            success = true;
            break;
        }
    }

    if (success) {
        config_.name = sandboxName; // 更新配置中的 name 字段
        sandboxPath_ = sandboxPath;
        return 0;
    } else {
        return -1;
    }
}

int SandboxManager::LoadConfigFile(const std::string &configPath)
{
    if (configPath.empty()) {
        SANDBOX_LOGE("Config path is empty");
        return -1;
    }

    configPath_ = configPath;
    std::ifstream configFile(configPath);
    if (!configFile.is_open()) {
        SANDBOX_LOGE("Failed to open config file, errno: %{public}d %{public}s",
            errno, strerror(errno));
        return -1;
    }

    std::stringstream buffer;
    buffer << configFile.rdbuf();
    configFile.close();

    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errs;
    if (!Json::parseFromStream(builder, buffer, &root, &errs)) {
        SANDBOX_LOGE("Failed to parse config JSON: %{public}s", errs.c_str());
        return -1;
    }

    return ParseConfigJson(root);
}

int SandboxManager::LoadConfigJsonStr(const std::string &configJsonStr)
{
    if (configJsonStr.empty()) {
        SANDBOX_LOGE("Config JSON string is empty");
        return -1;
    }

    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errs;
    std::istringstream jsonStream(configJsonStr);
    if (!Json::parseFromStream(builder, jsonStream, &root, &errs)) {
        SANDBOX_LOGE("Parse config json string failed, errs: %{public}s", errs.c_str());
        return -1;
    }

    return ParseConfigJson(root);
}

static int IsHexString(const std::string &str)
{
    if (str.empty()) {
        return false;
    }

    return std::all_of(str.begin(), str.end(), [](char c) {
        return std::isxdigit(static_cast<unsigned char>(c));
    });
}

int SandboxManager::ParseConfigJson(const Json::Value &root)
{
    if (!root.isObject()) {
        SANDBOX_LOGE("Config JSON root is not an object");
        return -1;
    }

    if (root.isMember("callerTokenId") && root["callerTokenId"].isUInt64()) {
        config_.callerTokenId = root["callerTokenId"].asUInt64();
    } else {
        SANDBOX_LOGE("Config JSON missing or invalid callerTokenId");
        return -1;
    }

    if (root.isMember("challenge") && root["challenge"].isString()) {
        config_.challenge = root["challenge"].asString();
    } else {
        SANDBOX_LOGE("Config JSON missing or invalid challenge");
        return -1;
    }

    if (root.isMember("uid") && root["uid"].isUInt()) {
        config_.uid = root["uid"].asUInt();
    } else {
        SANDBOX_LOGE("Config JSON missing or invalid uid");
        return -1;
    }

    if (root.isMember("gid") && root["gid"].isUInt()) {
        config_.gid = root["gid"].asUInt();
    } else {
        SANDBOX_LOGE("Config JSON missing or invalid gid");
        return -1;
    }

    if (root.isMember("callerPid") && root["callerPid"].isInt()) {
        config_.callerPid = static_cast<pid_t>(root["callerPid"].asInt());
    } else {
        SANDBOX_LOGE("Config JSON missing or invalid callerPid");
        return -1;
    }

    // sandbox name 可选，如果存在必须为字符串且只能包含字母、数字、下划线，长度不超过 64
    if (root.isMember("name")) {
        if (root["name"].isString() && IsHexString(root["name"].asString()) &&
            root["name"].asString().length() <= MAX_SANDBOX_NAME_LEN) {
            config_.name = root["name"].asString();
        } else {
            SANDBOX_LOGE("Config JSON name is invalid: must be a hex string up to 64 chars");
            return -1;
        }
    }

    return 0;
}

int SandboxManager::SetUidGid()
{
    if (setresgid(config_.gid, config_.gid, config_.gid) != 0) {
        SANDBOX_LOGE("setresgid failed: %{public}s", strerror(errno));
        return -1;
    }

    if (setresuid(config_.uid, config_.uid, config_.uid) != 0) {
        SANDBOX_LOGE("setresuid failed: %{public}s", strerror(errno));
        return -1;
    }
    return 0;
}

int SandboxManager::SetSelinux()
{
    if (!is_selinux_enabled()) {
        return 0;
    }

    if (setcon(SELINUX_LABEL) != 0) {
        SANDBOX_LOGE("SetSelinux: ERROR: set selinux failed: %{public}s", strerror(errno));
        return -1;
    }

    return 0;
}

int SandboxManager::SetSeccomp()
{
#ifdef WITH_SECCOMP
    const char *filterName = APP_NAME;
    bool ret = SetSeccompPolicyWithName(APP, filterName);
    if (!ret) {
        SANDBOX_LOGE("Failed to set seccomp policy");
        return -1;
    }
    SANDBOX_LOGD("Seccomp policy set successfully: %{public}s", filterName);
#endif
    return 0;
}

unsigned long SandboxManager::ParseMountFlags(const std::vector<std::string> &vec)
{
    const std::map<std::string, mode_t> MountFlagsMap = {
        {"rec", MS_REC}, {"MS_REC", MS_REC},
        {"bind", MS_BIND}, {"MS_BIND", MS_BIND},
        {"slave", MS_SLAVE}, {"MS_SLAVE", MS_SLAVE},
        {"rdonly", MS_RDONLY}, {"MS_RDONLY", MS_RDONLY},
        {"shared", MS_SHARED}, {"MS_SHARED", MS_SHARED},
        {"nosuid", MS_NOSUID}, {"MS_NOSUID", MS_NOSUID},
        {"nodev", MS_NODEV}, {"MS_NODEV", MS_NODEV},
        {"noexec", MS_NOEXEC}, {"MS_NOEXEC", MS_NOEXEC},
        {"noatime", MS_NOATIME}, {"MS_NOATIME", MS_NOATIME}
    };

    unsigned long mountFlags = 0;
    for (unsigned int i = 0; i < vec.size(); i++) {
        if (MountFlagsMap.count(vec[i])) {
            mountFlags |= MountFlagsMap.at(vec[i]);
        }
    }
    return mountFlags;
}

std::string SandboxManager::ReplaceVariable(std::string str, const std::string &from, const std::string &to)
{
    while (true) {
        std::string::size_type pos(0);
        if ((pos = str.find(from)) != std::string::npos) {
            str.replace(pos, from.length(), to);
        } else {
            break;
        }
    }
    return str;
}

int SandboxManager::ParseCommonConfig(const Json::Value &root)
{
    if (root.isMember("common") && root["common"].isObject() && !root["common"].empty()) {
        const Json::Value &common = root["common"];
        if (common.isMember("mount-paths") && common["mount-paths"].isArray() && !common["mount-paths"].empty()) {
            const Json::Value &mountPaths = common["mount-paths"];
            for (unsigned int i = 0; i < mountPaths.size(); ++i) {
                MountEntry entry;
                std::vector<std::string> vec;
                entry.srcPath = mountPaths[i]["src-path"].asString();
                entry.destPath = mountPaths[i]["sandbox-path"].asString();

                const Json::Value &flags = mountPaths[i]["sandbox-flags"];
                for (unsigned int j = 0; j < flags.size(); ++j) {
                    vec.push_back(flags[j].asString());
                }
                entry.flags = ParseMountFlags(vec);
                entry.checkExists = mountPaths[i]["check-action-status"].asBool();
                config_.appDataConfig.mountPaths.push_back(entry);
            }
        }
    }

    return 0;
}

int SandboxManager::LoadAppDataConfig(const std::string &appDataPath)
{
    std::ifstream configFile(appDataPath);
    if (!configFile.is_open()) {
        return -1;
    }

    std::string content((std::istreambuf_iterator<char>(configFile)),
                        std::istreambuf_iterator<char>());
    configFile.close();

    std::string str = ReplaceVariable(content, "<PackageName>", config_.bundleName);
    str = ReplaceVariable(str, "<currentUserId>", config_.currentUserId);
    str = ReplaceVariable(str, "<permissionUserId>", config_.currentUserId);

    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errs;
    std::stringstream buffer;
    buffer << str;
    if (!Json::parseFromStream(builder, buffer, &root, &errs)) {
        return -1;
    }

    if (ParseCommonConfig(root) != 0) {
        return -1;
    }

    return 0;
}

int SandboxManager::SetNamespace()
{
    const std::vector<std::string> &nsFlags = config_.appDataConfig.nsFlags;

    std::string flagsStr;
    for (const auto &flag : nsFlags) {
        flagsStr += flag + " ";
    }

    int cloneFlags = CLONE_NEWNET | CLONE_NEWNS;
    for (const auto &flag : nsFlags) {
        if (flag == "net") {
            cloneFlags |= CLONE_NEWNET;
        } else if (flag == "uts") {
            cloneFlags |= CLONE_NEWUTS;
        } else if (flag == "ipc") {
            cloneFlags |= CLONE_NEWIPC;
        } else if (flag == "pid") {
            cloneFlags |= CLONE_NEWPID;
        } else if (flag == "user") {
            cloneFlags |= CLONE_NEWUSER;
        }
    }

    pid_t callerPid = config_.callerPid;
    if (callerPid > 0) {
        SANDBOX_LOGD("SetNamespace: setns to parent process %{public}d namespace first", callerPid);
        if (SetNsFromPid(callerPid, cloneFlags) != 0) {
            SANDBOX_LOGW("SetNamespace: setns failed");
            return -1;
        }
    } else {
        SANDBOX_LOGW("SetNamespace: invalid callerPid from config");
        return -1;
    }

    if (unshare(cloneFlags) != 0) {
        SANDBOX_LOGE("SetNamespace: ERROR: unshare failed: %{public}s", strerror(errno));
        return -1;
    }

    namespaceCreated_ = true;
    SANDBOX_LOGD("SetNamespace: Namespace set successfully");
    return 0;
}

int SandboxManager::DoBindMount(const std::string &src, const std::string &dest, unsigned long flags)
{
    if (src.empty() || dest.empty()) {
        return -1;
    }

    if (CreateDirectoryIfNotExist(dest) != 0) {
        return -1;
    }

    unsigned long mountFlags = (flags == 0) ? (DEFAULT_MOUNT_FLAGS | DEFAULT_PROPAGATION) : (MS_BIND | flags);
    if (mount(src.c_str(), dest.c_str(), nullptr, mountFlags, nullptr) != 0) {
        return -1;
    }
    return 0;
}

int SandboxManager::MountSinglePath(const MountEntry &entry)
{
    return DoBindMount(entry.srcPath, entry.destPath, entry.flags | entry.propagation);
}

int SandboxManager::MountSystemPaths()
{
    const char *systemPaths[] = {
        "/proc",
        "/sys",
        "/dev",
        "/tmp",
        // "/run",
        "/usr",
        "/etc",
        // "/var",
        "/lib",
        // "lib64",
        "/bin",
        "/sbin",
        // "/usr/bin",
        // "/usr/sbin",
        // "/usr/lib",
        // "/usr/lib64",
        "/sys_prod",
        "/system/fonts",
        "/system/lib",
        "/system/usr",
        "/system/profile",
        "/system/bin",
        "/system/lib64",
        "/system/etc",
        "/system/framework",
        "/system/resource",
        "/vendor/lib",
        "/vendor/lib64",
        "/config",
    };

    int successCount = 0;
    int failCount = 0;

    for (const auto &sysPath : systemPaths) {
        struct stat st;
        if (stat(sysPath, &st) != 0) {
            continue;
        }

        std::string destPath = sandboxPath_ + sysPath;
        MountEntry entry;
        entry.srcPath = sysPath;
        entry.destPath = destPath;

        if (MountSinglePath(entry) != 0) {
            SANDBOX_LOGW("MountSystemPaths: Failed to mount %{public}s", sysPath);
            failCount++;
            continue;
        }
        successCount++;
    }

    if (successCount > 0) {
        mountsCreated_ = true;
    }

    SANDBOX_LOGD("MountSystemPaths: Completed: %{public}d success, %{public}d failed", successCount, failCount);
    return 0;
}

int SandboxManager::MountAppDataPaths()
{
    const std::vector<MountEntry> &mountPaths = config_.appDataConfig.mountPaths;
    if (mountPaths.empty()) {
        return 0;
    }

    for (const auto &entry : mountPaths) {
        if (entry.srcPath.empty() || entry.destPath.empty()) {
            continue;
        }

        std::string destPath;
        if (entry.destPath[0] != '/') {
            SANDBOX_LOGE("Invalid entry %{public}s", entry.destPath.c_str());
            return -1;
        }
        destPath = sandboxPath_ + entry.destPath;
        MountEntry mountEntry = entry;
        mountEntry.destPath = destPath;
        if (MountSinglePath(mountEntry) != 0) {
            continue;
        }
        mountsCreated_ = true;
    }

    return 0;
}

int SandboxManager::PivotRoot()
{
    std::string newRoot = sandboxPath_;

    std::string putOld = newRoot + "/.old_root";
    if (mkdir(putOld.c_str(), DIR_MODE) != 0) {
        if (errno != EEXIST) {
            SANDBOX_LOGE("PivotRoot: ERROR: Failed to create put_old: %{public}s", strerror(errno));
            return -1;
        }
    }

    if (pivot_root(newRoot.c_str(), putOld.c_str()) != 0) {
        SANDBOX_LOGE("PivotRoot: ERROR: pivot_root failed: %{public}s", strerror(errno));
        return -1;
    }

    if (chdir("/") != 0) {
        SANDBOX_LOGE("PivotRoot: ERROR: chdir failed: %{public}s", strerror(errno));
        return -1;
    }

    if (umount2(".old_root", MNT_DETACH) != 0) {
        SANDBOX_LOGW("PivotRoot: Warning: Failed to unmount old root: %{public}s", strerror(errno));
    }

    if (rmdir(".old_root") != 0) {
        SANDBOX_LOGW("PivotRoot: Warning: Failed to remove old root: %{public}s", strerror(errno));
    }
    pivotRootDone_ = true;
    return 0;
}

#ifndef SANDBOX_NO_EXECUTE
int SandboxManager::Execute()
{
    SANDBOX_LOGD("Execute: Using stub implementation (ExecuteCommand)");
    return ExecuteCommand();
}

int SandboxManager::ExecuteCommand()
{
    if (!cmdArgs_.empty() && cmdArgs_[0] != nullptr) {
        execvp(cmdArgs_[0], &cmdArgs_[0]);
        SANDBOX_LOGE("ExecuteCommand: ERROR: Failed to execute %{public}s: %{public}s", cmdArgs_[0], strerror(errno));
        return -1;
    }

#ifdef SANDBOX_STUB_MAINTHREAD
    execl("/system/bin/sh", "sh", "-i", nullptr);
    SANDBOX_LOGE("ExecuteCommand: ERROR: Failed to execute shell: %{public}s", strerror(errno));
#endif
    return -1;
}
#endif

int SandboxManager::CreateSymbolLink(const std::string &target, const std::string &link)
{
    if (target.empty() || link.empty()) {
        return -1;
    }

    struct stat st;
    if (stat(target.c_str(), &st) != 0) {
        return -1;
    }

    if (lstat(link.c_str(), &st) == 0) {
        if (unlink(link.c_str()) != 0) {
            return -1;
        }
    }

    if (symlink(target.c_str(), link.c_str()) != 0) {
        return -1;
    }

    return 0;
}

int SandboxManager::RemountRootSlave()
{
    std::string newRoot = sandboxPath_;

    if (mount(newRoot.c_str(), newRoot.c_str(), nullptr, MS_BIND | MS_REC, nullptr) != 0) {
        SANDBOX_LOGE("RemountRootSlave: Failed to remount root as slave: %{public}s", strerror(errno));
        return -1;
    }
    SANDBOX_LOGD("RemountRootSlave: Root remounted as slave successfully");
    return 0;
}

int SandboxManager::DropCapabilities()
{
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
    if (capset(&capHeader, caps) != 0) {
        SANDBOX_LOGE("[appspawn] capset failed, errL %{public}d.", errno);
        return -1;
    }
    return 0;
}

void SandboxManager::SetCommand(int argc, char *argv[])
{
    cmdArgs_.clear();
    for (int i = 0; i < argc; ++i) {
        cmdArgs_.push_back(argv[i]);
    }
    cmdArgs_.push_back(nullptr);

    for (size_t i = 0; i < cmdArgs_.size() - 1; ++i) {
        SANDBOX_LOGD("SetCommand: argv[%{public}zu] = %{public}s", i, cmdArgs_[i]);
    }
}

int CreateDirectory(const std::string &path)
{
    return CreateDirRecursive(path, 0);
}

int CreateDirectoryIfNotExist(const std::string &path)
{
    if (access(path.c_str(), F_OK) == 0) {
        struct stat info;
        if (stat(path.c_str(), &info) == 0 && S_ISDIR(info.st_mode)) {
            return 0;
        }
        return -1;
    } else {
        return CreateDirRecursive(path, DIR_MODE);
    }
}

int CreateDirRecursive(const std::string &path, mode_t mode)
{
    if (path.empty()) {
        return -1;
    }

    std::string copy = path;
    const char *path_ = copy.c_str();
    char buffer[PATH_MAX] = {0};
    const char slash = '/';
    const char *p = path_;
    const char *curPos = strchr(path_, slash);
    while (curPos != nullptr) {
        int len = curPos - p;
        p = curPos + 1;
        if (len == 0) {
            curPos = strchr(p, slash);
            continue;
        }
        int ret = memcpy_s(buffer, PATH_MAX, path_, p - path_ - 1);
        if (ret != 0) {
            SANDBOX_LOGE("Failed to copy path");
            return -1;
        }
        ret = mkdir(buffer, mode);
        if (ret == -1 && errno != EEXIST) {
            return errno;
        }
        curPos = strchr(p, slash);
    }
    if (mkdir(path_, mode) == -1 && errno != EEXIST) {
        return errno;
    }
    return 0;
}

bool IsDirectoryExist(const std::string &path)
{
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return false;
    }

    if (S_ISDIR(st.st_mode)) {
        return true;
    }
    return false;
}

}
}