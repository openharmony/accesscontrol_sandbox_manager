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

#include <algorithm>
#include <cctype>
#include <ctime>
#include <cstring>
#include <map>
#include <fstream>
#include <sstream>
#include <iostream>
#include <random>
#include <utility>
#include <grp.h>
#include <filesystem>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <linux/securebits.h>
#include <linux/capability.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#ifdef WITH_SECCOMP
#include "seccomp_policy.h"
#endif
#include <selinux/context.h>
#include <selinux/selinux.h>
#include <access_token.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <cstdlib>
#include <climits>

#include "securec.h"
#include "token_setproc.h"
#include "spm_setproc.h"
#include "accesstoken_kit.h"
#include "permission_list_state.h"
#include "access_token.h"
#include "ipc_skeleton.h"

using namespace OHOS::Security::AccessToken;

extern "C" {
extern char **environ;
}

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

// Number of capability data structures (CAP_NUM = 2 for _LINUX_CAPABILITY_VERSION_3)
constexpr int CAP_NUM = 2;

// Sandbox base directory
constexpr const char *SANDBOX_BASE_DIR = "/mnt/sandbox/claw";

constexpr int UID_BASE = 200000;

#ifdef MCS_ENABLE
// User ID base for MCS level calculation (same as UID_BASE in hap_restorecon.cpp)
constexpr uint32_t MCS_UID_BASE = 200000;

// Minimum user ID threshold for MCS level calculation
constexpr uint32_t MCS_USER_BASE = 100;

// MCS category segment offsets (matching hap_restorecon.cpp)
constexpr int CATEGORY_SEG0_OFFSET = 0;
constexpr int CATEGORY_SEG1_OFFSET = 256;
constexpr int CATEGORY_SEG2_OFFSET = 512;
constexpr int CATEGORY_SEG3_OFFSET = 768;
constexpr int CATEGORY_SEG4_OFFSET = 1024;

// MCS category mask and shift values
constexpr int CATEGORY_MASK = 0xff;
constexpr int SHIFT_8 = 8;
constexpr int SHIFT_16 = 16;
#endif

// Minimum UID allowed by seccomp filter (20000000 = 20 million).
// Any attempt to setuid/setreuid/setresuid/setfsuid to a UID below this
// value will be blocked by the seccomp filter, returning EACCES.
constexpr unsigned int UID_MIN_LIMIT = 20000000;

// DEC device policy ABI, aligned with startup_appspawn/modules/sandbox/sandbox_dec.h
constexpr const char *DEC_DEVICE_PATH = "/dev/dec";
constexpr int HM_DEC_IOCTL_BASE = 's';
constexpr int HM_SET_POLICY_ID = 1;
constexpr size_t DEC_MAX_POLICY_NUM = 64;
constexpr uint32_t DEC_KERNEL_BATCH_SIZE = 8;
constexpr uint32_t DEC_SANDBOX_MODE_READ = 0x00000001;
constexpr uint32_t DEC_SANDBOX_MODE_WRITE = (DEC_SANDBOX_MODE_READ << 1);
constexpr uint32_t DEC_POLICY_HEADER_RESERVED = 64;
constexpr uint64_t SEC_TO_NSEC = 1000000000ULL;

// IOCTL command for delivering AgentLock policy to kernel
constexpr int HM_POLICY_ADD_ID = 104;
constexpr int HM_AGENTLOCK_CURRENT_EXECUTER_INIT_ID = 112;

// Marker added to the final child process environment after sanitization.
// It is only used to identify that the process was launched by claw_sandbox.
constexpr const char *CLAW_SANDBOX_ENV_KEY = "CLAW_SANDBOX";
constexpr const char *CLAW_SANDBOX_ENV_VALUE = "1";
// Environment variables preset for the child process.
const std::map<std::string, std::string> PRESET_ENV_VARS = {
#ifdef CONFIG_PC_PLATFORM
    {"PATH", "/data/service/hnp/bin"}
#endif
};

// Buffer sizes used to query caller SPM entry from kernel.
constexpr uint32_t CLAW_SPM_PERM_BUF_SIZE = 64 * sizeof(uint32_t);
constexpr uint32_t CLAW_SPM_EXTEND_PERM_BUF_SIZE = 4096;
constexpr uint32_t CLAW_SPM_NAME_BUF_SIZE = 256;

static std::string BlobToString(const SpmBlob &blob)
{
    if (blob.buf == nullptr || blob.bufSize == 0) {
        return "";
    }

    size_t len = 0;
    while (len < blob.bufSize && blob.buf[len] != '\0') {
        len++;
    }
    return std::string(blob.buf, len);
}

struct DecPathInfo {
    char *path;
    uint32_t pathLen;
    uint32_t mode;
    bool flag;
};

struct DecPolicyInfo {
    uint64_t tokenId;
    uint64_t timestamp;
    DecPathInfo path[DEC_KERNEL_BATCH_SIZE];
    uint32_t pathNum;
    int32_t userId;
    uint64_t reserved[DEC_POLICY_HEADER_RESERVED];
    bool flag;
};

constexpr unsigned long SET_DEC_POLICY_CMD = _IOWR(HM_DEC_IOCTL_BASE, HM_SET_POLICY_ID, DecPolicyInfo);

constexpr unsigned long DEC_CMD_POLICY_ADD = _IOWR(HM_DEC_IOCTL_BASE, HM_POLICY_ADD_ID, struct AgentLockAddPolicyArg);
constexpr unsigned long DEC_CMD_AGENTLOCK_CURR_EXECUTER_INIT =
    _IOWR(HM_DEC_IOCTL_BASE, HM_AGENTLOCK_CURRENT_EXECUTER_INIT_ID, struct DecConfig);

static std::string TrimEnvKey(const std::string &rawKey)
{
    size_t begin = 0;
    while (begin < rawKey.size() && std::isspace(static_cast<unsigned char>(rawKey[begin])) != 0) {
        begin++;
    }
    size_t end = rawKey.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(rawKey[end - 1])) != 0) {
        end--;
    }
    return rawKey.substr(begin, end - begin);
}

static std::string ToUpperAscii(const std::string &value)
{
    std::string upper = value;
    std::transform(upper.begin(), upper.end(), upper.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return upper;
}

static bool IsPortableEnvVarKey(const std::string &key)
{
    if (key.empty() || !(std::isalpha(static_cast<unsigned char>(key[0])) != 0 || key[0] == '_')) {
        return false;
    }
    for (char ch : key) {
        if (!(std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '_')) {
            return false;
        }
    }
    return true;
}

static bool IsWindowsCompatOverrideEnvVarKey(const std::string &key)
{
    if (key.empty() || !(std::isalpha(static_cast<unsigned char>(key[0])) != 0 || key[0] == '_')) {
        return false;
    }
    for (char ch : key) {
        if (!(std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '_' || ch == '(' || ch == ')')) {
            return false;
        }
    }
    return true;
}

static bool ContainsEnvKey(const std::vector<std::string> &keys, const std::string &upperKey)
{
    for (const auto &key : keys) {
        if (upperKey == key) {
            return true;
        }
    }
    return false;
}

static bool HasEnvPrefix(const std::vector<std::string> &prefixes, const std::string &upperKey)
{
    for (const auto &prefix : prefixes) {
        if (upperKey.compare(0, prefix.size(), prefix) == 0) {
            return true;
        }
    }
    return false;
}

static bool NormalizeHostOverrideEnvVarKey(const std::string &rawKey, std::string &normalizedKey)
{
    normalizedKey = TrimEnvKey(rawKey);
    if (normalizedKey.empty()) {
        return false;
    }
    return IsPortableEnvVarKey(normalizedKey) || IsWindowsCompatOverrideEnvVarKey(normalizedKey);
}

static std::string AppendEnvPathValue(const std::string &baseValue, const std::string &appendValue)
{
    if (baseValue.empty()) {
        return appendValue;
    }
    if (appendValue.empty()) {
        return baseValue;
    }
    return baseValue + ":" + appendValue;
}

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

// xpm setting
constexpr uint32_t MAX_OWNERID_LEN = 64;
constexpr const char *DEV_XPM_PATH = "/dev/xpm";

struct XpmRegionInfo {
    unsigned long addrBase;
    unsigned long length;

    uint32_t idType;
    char ownerid[MAX_OWNERID_LEN];
    uint32_t apiVersion;
};

constexpr int HM_XPM_REGION_IOCTL_BASE = 'x';
constexpr int HM_SET_XPM_OWNERID_ID = 2;
constexpr uint32_t XPM_ID_TYPE_APPID = 3;
constexpr unsigned long SET_XPM_OWNERID_CMD = _IOW(HM_XPM_REGION_IOCTL_BASE,
    HM_SET_XPM_OWNERID_ID, struct XpmRegionInfo);


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

int SandboxManager::DeleteSandboxDir()
{
    if (!initialized_) {
        std::cerr << "Error: SandboxManager not initialized" << std::endl;
        SANDBOX_LOGE("SandboxManager not initialized");
        return SANDBOX_ERR_GENERIC;
    }

    int ret = ValidateConfig();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    if (config_.name.empty()) {
        std::cerr << "Error: sandbox name is empty" << std::endl;
        SANDBOX_LOGE("sandbox name is empty");
        return SANDBOX_ERR_BAD_PARAMETERS;
    }

    ret = EnterCallerSandbox();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    std::string sandboxPath = std::string(SANDBOX_BASE_DIR) + "/" + config_.name;
    struct stat st;
    if (lstat(sandboxPath.c_str(), &st) != 0) {
        if (errno == ENOENT) {
            std::cerr << "Error: Sandbox directory does not exist: " << sandboxPath << std::endl;
            SANDBOX_LOGE("Sandbox directory does not exist: %{public}s", sandboxPath.c_str());
            return SANDBOX_ERR_PATH_INVALID;
        }
        std::cerr << "Error: Failed to stat sandbox directory " << sandboxPath
                  << ": " << strerror(errno) << std::endl;
        SANDBOX_LOGE("Failed to stat sandbox directory %{public}s: %{public}s",
            sandboxPath.c_str(), strerror(errno));
        return SANDBOX_ERR_GENERIC;
    }

    if (!S_ISDIR(st.st_mode)) {
        std::cerr << "Error: Sandbox path is not a directory: " << sandboxPath << std::endl;
        SANDBOX_LOGE("Sandbox path is not a directory: %{public}s", sandboxPath.c_str());
        return SANDBOX_ERR_PATH_INVALID;
    }

    std::error_code ec;
    std::filesystem::remove_all(sandboxPath, ec);
    if (ec) {
        std::cerr << "Error: remove_all " << sandboxPath << " failed: " << ec.message() << std::endl;
        SANDBOX_LOGE("remove_all %{public}s failed: %{public}s", sandboxPath.c_str(), ec.message().c_str());
        return SANDBOX_ERR_GENERIC;
    }

    SANDBOX_LOGD("Deleted sandbox directory %{public}s", sandboxPath.c_str());
    return SANDBOX_SUCCESS;
}

int SandboxManager::Execute()
{
    if (!initialized_) {
        std::cerr << "Error: SandboxManager not initialized" << std::endl;
        SANDBOX_LOGE("SandboxManager not initialized");
        return SANDBOX_ERR_GENERIC;
    }

    // Steps 1-5: Validate, load template, set selinux MCS, generate token, enter caller sandbox
    int ret = ExecuteEarlySteps();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Steps 6-11: Create root, unshare, mount, pivot_root (with cleanup on failure)
    ret = ExecuteMountSteps();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Steps 12-20: Set token, ainfo, uid/gid, DEC policies, workdir, env, seccomp, drop caps, exec
    return ExecuteLateSteps();
}

/**
 * @brief Execute steps 1-5: validate config, load template, set selinux MCS,
 *        generate token, and enter the caller's sandbox namespace.
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

#ifdef MCS_ENABLE
    // Step 3: Set SELinux MCS level for the current process (before GenerateTokenId,
    //         because setcon() must happen before token/uid changes)
    ret = SetSelinuxMCS();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
#endif

    ret = GenerateTokenId();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    ret = ValidateWithSpmEntry();
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
        return ret;
    }

    ret = UnshareNamespaces();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    ret = MountNewRoot();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    ret = MountSystemDirs();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    ret = MountAppDirs();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    ret = MountPermissionDirs();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    ret = PivotRoot();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    ret = ApplyPolicyMounts();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Create a new process group (must be done BEFORE SetSeccomp & Fork,
    // because seccomp blocks setpgid/setsid to prevent process group escape,
    // and the child process must inherit the new process group to avoid being adopted by init)
    ret = SetProcessGroup();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    ret = ForkAfterUnshare();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    ret = MountProcFs();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    return SANDBOX_SUCCESS;
}

/**
 * @brief Execute steps 12-21: set access token, ainfo, uid/gid, DEC policies,
 *        workdir, environment, seccomp filter, drop capabilities, and execute command.
 *        These steps do NOT require cleanup on failure.
 */
int SandboxManager::ExecuteLateSteps()
{
    // Step 12: Set access token.
    int ret = SetAccessToken();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 13: Set xpm owner id.
    ret = SetXpmOwnerId();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 14: Set ainfo.
    ret = SetAinfo();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 15: Set UID/GID (with SECBIT_KEEP_CAPS to preserve capabilities across setuid).
    ret = SetUidGid();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 16: Apply DEC policies after UID/GID and supplementary groups are set.
    ret = ApplyDecPolicies();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 17: Prepare optional workdir before installing seccomp, because seccomp may block chdir.
    ret = PrepareWorkdir();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 18: Apply optional environment after UID/GID switch so exec inherits the final environment.
    ret = ApplyEnvironment();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 19: Set Seccomp (always applied to block setpgid/setsid for process group protection).
    ret = SetSeccomp();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 20: Deliver AgentLock policy if specified in config.
    ret = DeliverNetPolicy();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 21: Drop capabilities after seccomp; capset() is not blocked in block mode
    //          and is expected to be allowlisted in whitelist mode.
    ret = DropCapabilities();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // Step 22: Execute the command.
    return ExecuteCommand();
}

int SandboxManager::SetXpmOwnerId()
{
    if (config_.type != "shell") {
        // only shell need to set xpm ownner id
        return SANDBOX_SUCCESS;
    }

    std::string ownerId = config_.appIdentifier;
    if (ownerId.empty()) {
        std::cerr << "Error: appIdentifier is empty" << std::endl;
        SANDBOX_LOGE("Error: appIdentifier is empty");
        return SANDBOX_ERR_BAD_PARAMETERS;
    }

    int fd = open(DEV_XPM_PATH, O_RDWR);
    if (fd < 0) {
        SANDBOX_LOGW("Open %{public}s failed, err: %{public}s", DEV_XPM_PATH, strerror(errno));
        return SANDBOX_SUCCESS;
    }

    struct XpmRegionInfo info = { 0 };
    info.idType = XPM_ID_TYPE_APPID;
    size_t copyLen = std::min(ownerId.size(), static_cast<size_t>(MAX_OWNERID_LEN - 1));
    int ret = memcpy_s(info.ownerid, MAX_OWNERID_LEN, ownerId.c_str(), copyLen);
    if (ret != SANDBOX_SUCCESS) {
        std::cerr << "Error: failed to copy ownerid to XpmRegionInfo" << std::endl;
        SANDBOX_LOGE("Error: failed to copy ownerid to XpmRegionInfo");
        close(fd);
        return SANDBOX_ERR_BAD_PARAMETERS;
    }
    ret = ioctl(fd, SET_XPM_OWNERID_CMD, &info);
    if (ret < 0) {
        SANDBOX_LOGW("Set xpm ownner id failed, err: %{public}s", strerror(errno));
    } else {
        SANDBOX_LOGD("Set xpm Ownner id success");
    }
    close(fd);
    return SANDBOX_SUCCESS;
}

int SandboxManager::ValidateBasicParams()
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

int SandboxManager::ValidateTokenType()
{
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

int SandboxManager::ValidateWithSpmEntry()
{
    AccessTokenID accessTokenId = static_cast<AccessTokenID>(
        config_.callerTokenId & TOKEN_ID_LOWMASK);
    using SpmDataPtr = std::unique_ptr<SpmData, decltype(&SpmDataFree)>;
    SpmDataPtr entry(SpmDataNew(CLAW_SPM_PERM_BUF_SIZE, CLAW_SPM_EXTEND_PERM_BUF_SIZE, CLAW_SPM_NAME_BUF_SIZE),
        SpmDataFree);
    if (entry == nullptr) {
        std::cerr << "Error: SpmDataNew failed for config validation" << std::endl;
        SANDBOX_LOGE("SpmDataNew failed for config validation");
        return SANDBOX_ERR_SPM_FAILED;
    }

    int ret = SpmGetEntry(static_cast<uint32_t>(accessTokenId), entry.get());
    if (ret != 0) {
        std::cerr << "Error: SpmGetEntry failed, accessTokenId=" << accessTokenId
                  << ", ret=" << ret << std::endl;
        SANDBOX_LOGE("SpmGetEntry failed for config validation, accessTokenId=%{public}u, ret=%{public}d",
            accessTokenId, ret);
        return SANDBOX_ERR_SPM_FAILED;
    }

    // Validate uid and gid against SPM entry uid
    if (config_.uid != entry->uid || config_.gid != entry->uid) {
        std::cerr << "Error: uid/gid mismatch with SPM entry: config uid=" << config_.uid
                  << ", gid=" << config_.gid << ", entry uid=" << entry->uid << std::endl;
        SANDBOX_LOGE("uid/gid mismatch with SPM entry: config uid=%{public}u, gid=%{public}u, entry uid=%{public}u",
            config_.uid, config_.gid, entry->uid);
        return SANDBOX_ERR_SPM_FAILED;
    }

    // Validate appIdentifier against SPM entry ownerid
    std::string owneridStr = std::to_string(static_cast<unsigned long long>(entry->ownerid));
    if (config_.appIdentifier != owneridStr) {
        std::cerr << "Error: appIdentifier mismatch with SPM entry ownerid: config="
                  << config_.appIdentifier << ", entry ownerid=" << owneridStr << std::endl;
        SANDBOX_LOGE("appIdentifier mismatch with SPM entry ownerid");
        return SANDBOX_ERR_SPM_FAILED;
    }
    // Validate bundleName against SPM entry name
    std::string entryName = BlobToString(entry->name);
    if (config_.bundleName != entryName) {
        std::cerr << "Error: bundleName mismatch with SPM entry name: config="
                  << config_.bundleName << ", entry name=" << entryName << std::endl;
        SANDBOX_LOGE("bundleName mismatch with SPM entry name");
        return SANDBOX_ERR_SPM_FAILED;
    }

    return SANDBOX_SUCCESS;
}

int SandboxManager::ValidateConfig()
{
    int ret = ValidateBasicParams();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    ret = ValidateTokenType();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    return SANDBOX_SUCCESS;
}

int SandboxManager::LoadTemplate()
{
    const char *templatePath = "/etc/sandbox/claw_sandbox_template_cli.json";

    if (config_.type == "shell") {
        templatePath = "/etc/sandbox/claw_sandbox_template_shell.json";
    }

    return LoadJsonConfig(templatePath);
}

static bool IsDirectoryExist(const std::string &path)
{
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return false;
    }
    return S_ISDIR(st.st_mode);
}

bool SandboxManager::IsPermissionGranted(const std::string &permissionName) const
{
    AccessTokenID tokenId = static_cast<AccessTokenID>(config_.callerTokenId & TOKEN_ID_LOWMASK);
    SANDBOX_LOGD("[DEBUG INFO] DEC debug permission check, permission=%{public}s, callerTokenId=%{public}u, "
        "targetTokenIdEx=%{public}llu",
        permissionName.c_str(), tokenId, static_cast<unsigned long long>(config_.tokenIdEx.tokenIDEx));
    if (tokenId == 0) {
        SANDBOX_LOGW("Skip DEC permission check for %{public}s: empty tokenId", permissionName.c_str());
        return false;
    }

    int32_t ret = AccessTokenKit::VerifyAccessToken(tokenId, permissionName);
    if (ret == PermissionState::PERMISSION_GRANTED) {
        SANDBOX_LOGD("[DEBUG INFO] DEC debug permission granted, permission=%{public}s", permissionName.c_str());
        return true;
    }
    SANDBOX_LOGD("Permission %{public}s is not granted for token %{public}u", permissionName.c_str(), tokenId);
    return false;
}

std::vector<int> SandboxManager::CollectGrantedPermissionGids() const
{
    std::vector<int> permissionGids;
    for (const auto &permissionItem : templateConfig_.permissions) {
        const std::string &permissionName = permissionItem.first;
        const PermissionConfig &permissionConfig = permissionItem.second;
        if (!permissionConfig.sandboxSwitch || !IsPermissionGranted(permissionName)) {
            continue;
        }
        for (int gid : permissionConfig.gids) {
            if (gid < 0) {
                SANDBOX_LOGW("Skip negative permission gid %{public}d for %{public}s",
                    gid, permissionName.c_str());
                continue;
            }
            if (std::find(permissionGids.begin(), permissionGids.end(), gid) != permissionGids.end()) {
                continue;
            }
            permissionGids.emplace_back(gid);
        }
    }
    SANDBOX_LOGD("Collected granted permission gids, count=%{public}zu", permissionGids.size());
    return permissionGids;
}

int SandboxManager::CollectPermissionDecPaths(const PermissionConfig &config,
                                              std::vector<std::string> &decPaths) const
{
    for (const auto &mountEntry : config.mounts) {
        for (const auto &decPath : mountEntry.decPaths) {
            std::string normalizedDecPath = NormalizeDecPath(decPath);
            if (normalizedDecPath.empty() ||
                std::find(decPaths.begin(), decPaths.end(), normalizedDecPath) != decPaths.end()) {
                continue;
            }
            if (decPaths.size() >= DEC_MAX_POLICY_NUM) {
                SANDBOX_LOGW("DEC policy path count exceeds %{public}zu", DEC_MAX_POLICY_NUM);
                return -1;
            }
            decPaths.emplace_back(normalizedDecPath);
        }
    }
    return 0;
}

std::vector<std::string> SandboxManager::CollectDecPolicyPaths() const
{
    std::vector<std::string> decPaths;
    SANDBOX_LOGD("[DEBUG INFO] DEC debug collect begin, permissionCount=%{public}zu",
        templateConfig_.permissions.size());
    for (const auto &permissionItem : templateConfig_.permissions) {
        const PermissionConfig &permissionConfig = permissionItem.second;
        if (!permissionConfig.sandboxSwitch || !IsPermissionGranted(permissionItem.first)) {
            continue;
        }
        if (CollectPermissionDecPaths(permissionConfig, decPaths) != 0) {
            break;
        }
    }
    SANDBOX_LOGD("[DEBUG INFO] DEC debug collect end, pathCount=%{public}zu", decPaths.size());
    return decPaths;
}

std::string SandboxManager::NormalizeDecPath(const std::string &decPath) const
{
    std::string normalizedPath = decPath;
    normalizedPath = ReplaceVariable(normalizedPath, "<currentUserId>", "currentUser");
    normalizedPath = ReplaceVariable(normalizedPath, "<currentUser>", "currentUser");
    std::string userPrefix = "/storage/Users/" + config_.currentUserId + "/";
    constexpr const char *CURRENT_USER_PREFIX = "/storage/Users/currentUser/";
    if (normalizedPath.compare(0, userPrefix.size(), userPrefix) == 0) {
        normalizedPath.replace(0, userPrefix.size(), CURRENT_USER_PREFIX);
    }
    return normalizedPath;
}

int SandboxManager::SetDecPolicyBatch(int fd, const std::vector<std::string> &paths,
                                      uint64_t tokenId, uint64_t timestamp, size_t start, size_t count)
{
    if (count == 0 || count > DEC_KERNEL_BATCH_SIZE || start + count > paths.size()) {
        SANDBOX_LOGW("Invalid DEC policy batch, start=%{public}zu, count=%{public}zu, total=%{public}zu",
            start, count, paths.size());
        return SANDBOX_ERR_BAD_PARAMETERS;
    }

    DecPolicyInfo batchInfo = {};
    batchInfo.tokenId = tokenId;
    batchInfo.timestamp = timestamp;
    batchInfo.pathNum = static_cast<uint32_t>(count);
    batchInfo.userId = 0;
    batchInfo.flag = false;

    SANDBOX_LOGD("[DEBUG INFO] DEC debug batch prepare, start=%{public}zu, count=%{public}zu, "
        "callerTokenId=%{public}llu",
        start, count, static_cast<unsigned long long>(tokenId));
    for (size_t i = 0; i < count; i++) {
        const std::string &path = paths[start + i];
        batchInfo.path[i].path = const_cast<char *>(path.c_str());
        batchInfo.path[i].pathLen = static_cast<uint32_t>(path.size());
        batchInfo.path[i].mode = DEC_SANDBOX_MODE_READ | DEC_SANDBOX_MODE_WRITE;
        batchInfo.path[i].flag = false;
        SANDBOX_LOGD("[DEBUG INFO] DEC policy path=%{public}s, mode=rw", path.c_str());
    }

    SANDBOX_LOGD("[DEBUG INFO] DEC debug ioctl begin, start=%{public}zu, count=%{public}zu", start, count);
    int ret = ioctl(fd, SET_DEC_POLICY_CMD, &batchInfo);
    if (ret < 0) {
        SANDBOX_LOGW("SET_DEC_POLICY_CMD failed, start=%{public}zu, count=%{public}zu, errno=%{public}d",
            start, count, errno);
    } else {
        SANDBOX_LOGD("[DEBUG INFO] DEC debug ioctl success, start=%{public}zu, count=%{public}zu, ret=%{public}d",
            start, count, ret);
    }
    return ret;
}

int SandboxManager::ApplyDecPolicies()
{
    std::vector<std::string> decPaths = CollectDecPolicyPaths();
    SANDBOX_LOGD("[DEBUG INFO] DEC debug apply begin, collectedPathCount=%{public}zu", decPaths.size());
    if (decPaths.empty()) {
        SANDBOX_LOGD("No DEC paths to apply");
        return SANDBOX_SUCCESS;
    }

    uint64_t tokenId = config_.callerTokenId;
    if (tokenId == 0) {
        SANDBOX_LOGW("Skip DEC policy: empty callerTokenId");
        return SANDBOX_SUCCESS;
    }

    int fd = open(DEC_DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        SANDBOX_LOGW("Open %{public}s failed, errno=%{public}d", DEC_DEVICE_PATH, errno);
        return SANDBOX_SUCCESS;
    }
    SANDBOX_LOGD("[DEBUG INFO] DEC debug device opened, path=%{public}s, fd=%{public}d", DEC_DEVICE_PATH, fd);

    struct timespec ts = {};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        SANDBOX_LOGW("clock_gettime failed for DEC policy, errno=%{public}d", errno);
        close(fd);
        return SANDBOX_SUCCESS;
    }
    uint64_t timestamp = static_cast<uint64_t>(ts.tv_sec) * SEC_TO_NSEC + static_cast<uint64_t>(ts.tv_nsec);

    size_t failedBatches = 0;
    size_t totalBatches = 0;
    for (size_t start = 0; start < decPaths.size(); start += DEC_KERNEL_BATCH_SIZE) {
        size_t count = std::min(decPaths.size() - start, static_cast<size_t>(DEC_KERNEL_BATCH_SIZE));
        totalBatches++;
        SANDBOX_LOGD("[DEBUG INFO] DEC debug apply batch, batchIndex=%{public}zu, start=%{public}zu, count=%{public}zu",
            totalBatches - 1, start, count);
        if (SetDecPolicyBatch(fd, decPaths, tokenId, timestamp, start, count) != 0) {
            failedBatches++;
        }
    }

    close(fd);
    if (failedBatches > 0) {
        SANDBOX_LOGW("Applied DEC policies with failures, pathCount=%{public}zu, failedBatches=%{public}zu/%{public}zu",
            decPaths.size(), failedBatches, totalBatches);
    } else {
        SANDBOX_LOGI("Applied DEC policies, pathCount=%{public}zu", decPaths.size());
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::GenerateTokenId()
{
    if (config_.type == "shell") {
        return SANDBOX_SUCCESS;
    }
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
    uint64_t callerId = 0;
    if (config_.type == "shell") {
        callerId = config_.callerTokenId;
    } else {
        callerId = config_.tokenIdEx.tokenIDEx;
    }

    int ret = SetSelfTokenID(callerId);
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

#ifdef MCS_ENABLE
/**
 * @brief Build MCS level string from uid and apply it to the given context.
 *        Logic matches UserAndMCSRangeSet in hap_restorecon.cpp.
 * @param uid User ID from sandbox config
 * @param con Context to apply the MCS range to
 * @return SANDBOX_SUCCESS on success, error code on failure
 */
static int ApplyMcsLevel(uint32_t uid, context_t con)
{
    if (uid < MCS_UID_BASE) {
        return SANDBOX_SUCCESS;
    }
    uint32_t userId = uid / MCS_UID_BASE;
    uint32_t appId = uid % MCS_UID_BASE;
    if (userId < MCS_USER_BASE) {
        return SANDBOX_SUCCESS;
    }

    // Build MCS level string: "s0:x<seg0>,x<seg1>,x<seg2>,x<seg3>,x<seg4>"
    std::string level = "s0:x" +
        std::to_string(CATEGORY_SEG0_OFFSET + (appId & CATEGORY_MASK)) +
        ",x" + std::to_string(CATEGORY_SEG1_OFFSET + ((appId >> SHIFT_8) & CATEGORY_MASK)) +
        ",x" + std::to_string(CATEGORY_SEG2_OFFSET + ((appId >> SHIFT_16) & CATEGORY_MASK)) +
        ",x" + std::to_string(CATEGORY_SEG3_OFFSET + (userId & CATEGORY_MASK)) +
        ",x" + std::to_string(CATEGORY_SEG4_OFFSET + ((userId >> SHIFT_8) & CATEGORY_MASK));
    int ret = context_range_set(con, level.c_str());
    if (ret != 0) {
        SANDBOX_LOGE("ApplyMcsLevel: context_range_set failed, level=%{public}s",
                     level.c_str());
        return SANDBOX_ERR_SET_SELINUX_FAILED;
    }
    return SANDBOX_SUCCESS;
}

/**
 * @brief Get the current SELinux context, apply MCS level based on uid,
 *        validate, and set the new process context.
 * @param uid User ID for MCS level calculation
 * @return SANDBOX_SUCCESS on success, error code on failure
 */
static int SetSelinuxContext(uint32_t uid)
{
    // Get the current SELinux context
    char *curContext = nullptr;
    if (getcon(&curContext) < 0) {
        SANDBOX_LOGE("SetSelinuxMCS: getcon failed, errno=%{public}d", errno);
        return SANDBOX_ERR_SET_SELINUX_FAILED;
    }

    // Create a new context_t from the current context string
    context_t con = context_new(curContext);
    freecon(curContext);
    curContext = nullptr;
    if (con == nullptr) {
        SANDBOX_LOGE("SetSelinuxMCS: context_new failed");
        return SANDBOX_ERR_SET_SELINUX_FAILED;
    }

    // Apply MCS level based on uid
    int ret = ApplyMcsLevel(uid, con);
    if (ret != SANDBOX_SUCCESS) {
        context_free(con);
        return ret;
    }

    // Get the resulting context string
    const char *newContext = context_str(con);
    if (newContext == nullptr) {
        SANDBOX_LOGE("SetSelinuxMCS: context_str returned null");
        context_free(con);
        return SANDBOX_ERR_SET_SELINUX_FAILED;
    }

    // Validate the context against the SELinux policy
    if (security_check_context(newContext) < 0) {
        SANDBOX_LOGE("SetSelinuxMCS: security_check_context failed for %{public}s",
                     newContext);
        context_free(con);
        return SANDBOX_ERR_SET_SELINUX_FAILED;
    }

    // Apply the new SELinux context
    if (setcon(newContext) < 0) {
        SANDBOX_LOGE("SetSelinuxMCS: setcon failed for %{public}s, errno=%{public}d",
                     newContext, errno);
        context_free(con);
        return SANDBOX_ERR_SET_SELINUX_FAILED;
    }

    SANDBOX_LOGI("SetSelinuxMCS: context set to %{public}s", newContext);
    context_free(con);
    return SANDBOX_SUCCESS;
}

int SandboxManager::SetSelinuxMCS()
{
    // Check if SELinux is enabled; if not, skip context setting
    if (is_selinux_enabled() < 1) {
        SANDBOX_LOGW("SELinux is not enabled, skipping SetSelinuxMCS");
        return SANDBOX_SUCCESS;
    }

    // Get the current SELinux context, apply MCS level based on uid,
    // validate, and set it as the new process context.
    return SetSelinuxContext(config_.uid);
}
#endif

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
    // DropCapabilities() (Step 19) will still zero out permitted and
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

    std::vector<gid_t> gids = {static_cast<gid_t>(config_.gid)};
    for (int permissionGid : CollectGrantedPermissionGids()) {
        gid_t gid = static_cast<gid_t>(permissionGid);
        if (std::find(gids.begin(), gids.end(), gid) != gids.end()) {
            continue;
        }
        gids.emplace_back(gid);
    }
    SANDBOX_LOGD("Set supplementary groups, count=%{public}zu", gids.size());
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
    const char *filterName1 = APP_NAME;
    const char *filterName2 = APP_CUSTOM;
    bool ret = SetSeccompPolicyWithName(APP, filterName1);
    if (!ret) {
        ret = SetSeccompPolicyWithName(APP, filterName2);
        if (!ret) {
            std::cerr << "Error: SetSeccompPolicyWithName failed for filter: " <<
                    filterName1 << " or " << filterName2 << std::endl;
            SANDBOX_LOGE("SetSeccompPolicyWithName failed for filter: %{public}s or %{public}s",
                         filterName1, filterName2);
            return SANDBOX_ERR_SET_SECCOMP_FAILED;
        }
    }
    SANDBOX_LOGD("APP-level seccomp policy set: %{public}s or %{public}s", filterName1, filterName2);
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
    // Note: SECBIT_KEEP_CAPS was already attempted in SetUidGid() (Step 14).
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

int SandboxManager::DeliverNetPolicy()
{
    if (config_.policyArg == nullptr) {
        return SANDBOX_SUCCESS;
    }
    int fd = open(DEC_DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        std::cerr << "Error: open " << DEC_DEVICE_PATH << " failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("open %s failed: %{public}s", DEC_DEVICE_PATH, strerror(errno));
        return SANDBOX_ERR_SET_POLICY_FAILED;
    }
    int ret = ioctl(fd, DEC_CMD_AGENTLOCK_CURR_EXECUTER_INIT, NULL);
    if (ret < 0) {
        std::cerr << "Error: ioctl DEC_CMD_AGENTLOCK_CURR_EXECUTER_INIT failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("ioctl DEC_CMD_AGENTLOCK_CURR_EXECUTER_INIT failed: %{public}s", strerror(errno));
        close(fd);
        return SANDBOX_ERR_SET_POLICY_FAILED;
    }
    ret = ioctl(fd, DEC_CMD_POLICY_ADD, config_.policyArg);
    if (ret < 0) {
        std::cerr << "Error: ioctl DEC_CMD_POLICY_ADD failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("ioctl DEC_CMD_POLICY_ADD failed: %{public}s", strerror(errno));
        close(fd);
        return SANDBOX_ERR_SET_POLICY_FAILED;
    }
    close(fd);
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

int SandboxManager::PrepareWorkdir()
{
    if (config_.workdir.empty()) {
        SANDBOX_LOGD("No workdir configured, skip workdir switch");
        return SANDBOX_SUCCESS;
    }

    SANDBOX_LOGD("Preparing workdir: %{public}s", config_.workdir.c_str());
    if (!IsDirectoryExist(config_.workdir)) {
        std::cerr << "Error: workdir does not exist or is not directory: " <<
                  config_.workdir << std::endl;
        SANDBOX_LOGE("workdir does not exist or is not directory: %{public}s", config_.workdir.c_str());
        return SANDBOX_ERR_PATH_INVALID;
    }
    if (access(config_.workdir.c_str(), R_OK | W_OK) < 0) {
        std::cerr << "Error: workdir is not readable/writable: " << config_.workdir << std::endl;
        SANDBOX_LOGE("workdir is not readable/writable: %{public}s", config_.workdir.c_str());
        return SANDBOX_ERR_PATH_INVALID;
    }
    if (chdir(config_.workdir.c_str()) < 0) {
        std::cerr << "Error: chdir " << config_.workdir << " failed: " <<
                  strerror(errno) << std::endl;
        SANDBOX_LOGE("chdir %{public}s failed: %{public}s",
            config_.workdir.c_str(), strerror(errno));
        return SANDBOX_ERR_CHDIR_FAILED;
    }

    SANDBOX_LOGD("Switched workdir to %{public}s", config_.workdir.c_str());
    return SANDBOX_SUCCESS;
}

bool SandboxManager::IsAllowedInheritedOverrideOnlyEnvKey(const std::string &upperKey) const
{
    return ContainsEnvKey(templateConfig_.envPolicy.allowedInheritedOverrideOnlyKeys, upperKey);
}

bool SandboxManager::IsDangerousHostEnvVarName(const std::string &key) const
{
    std::string upperKey = ToUpperAscii(TrimEnvKey(key));
    if (upperKey.empty()) {
        return false;
    }
    if (ContainsEnvKey(templateConfig_.envPolicy.blockedEverywhereKeys, upperKey)) {
        return true;
    }
    return HasEnvPrefix(templateConfig_.envPolicy.blockedPrefixes, upperKey);
}

bool SandboxManager::IsDangerousHostInheritedEnvVarName(const std::string &key) const
{
    std::string upperKey = ToUpperAscii(TrimEnvKey(key));
    if (upperKey.empty()) {
        return false;
    }
    if (IsDangerousHostEnvVarName(upperKey)) {
        return true;
    }
    if (IsAllowedInheritedOverrideOnlyEnvKey(upperKey)) {
        return false;
    }
    return ContainsEnvKey(templateConfig_.envPolicy.blockedOverrideOnlyKeys, upperKey);
}

bool SandboxManager::IsDangerousHostEnvOverrideVarName(const std::string &key) const
{
    std::string upperKey = ToUpperAscii(TrimEnvKey(key));
    if (upperKey.empty()) {
        return false;
    }
    if (ContainsEnvKey(templateConfig_.envPolicy.blockedOverrideOnlyKeys, upperKey)) {
        return true;
    }
    return HasEnvPrefix(templateConfig_.envPolicy.blockedOverridePrefixes, upperKey);
}

static int ApplySanitizedEnv(const std::map<std::string, std::string> &sanitizedEnv)
{
    if (clearenv() != 0) {
        std::cerr << "Error: clearenv failed: " << strerror(errno) << std::endl;
        SANDBOX_LOGE("clearenv failed: %{public}s", strerror(errno));
        return SANDBOX_ERR_GENERIC;
    }
    for (const auto &item : sanitizedEnv) {
        if (setenv(item.first.c_str(), item.second.c_str(), 1) != 0) {
            std::cerr << "Error: setenv " << item.first << " failed: " <<
                      strerror(errno) << std::endl;
            SANDBOX_LOGE("setenv %{public}s failed: %{public}s",
                item.first.c_str(), strerror(errno));
            return SANDBOX_ERR_GENERIC;
        }
    }
    SANDBOX_LOGD("Applied sanitized environment successfully, count=%{public}zu", sanitizedEnv.size());
    return SANDBOX_SUCCESS;
}

void SandboxManager::SanitizeInheritedEnv(std::map<std::string, std::string> &sanitizedEnv,
                                          size_t &inheritedAccepted, size_t &inheritedRejected)
{
    for (char **env = environ; env != nullptr && *env != nullptr; env++) {
        std::string entry = *env;
        size_t sep = entry.find('=');
        if (sep == std::string::npos) {
            continue;
        }
        std::string key = TrimEnvKey(entry.substr(0, sep));
        if (key.empty()) {
            continue;
        }
        if (IsDangerousHostInheritedEnvVarName(key)) {
            inheritedRejected++;
            SANDBOX_LOGD("[DEBUG INFO] Env debug inherited rejected, key=%{public}s", key.c_str());
            continue;
        }
        sanitizedEnv[key] = entry.substr(sep + 1);
        inheritedAccepted++;
        SANDBOX_LOGD("[DEBUG INFO] Env debug inherited accepted, key=%{public}s, valueLen=%{public}zu",
            key.c_str(), entry.size() - sep - 1);
    }
}

void SandboxManager::SanitizeOverrideEnv(std::map<std::string, std::string> &sanitizedEnv,
                                         size_t &overrideAccepted, size_t &overrideRejectedBlocked,
                                         size_t &overrideRejectedInvalid)
{
    for (const auto &preset : PRESET_ENV_VARS) {
        std::string upperPresetKey = ToUpperAscii(preset.first);
        if (upperPresetKey == "PATH") {
            auto currentPath = sanitizedEnv.find("PATH");
            std::string base = (currentPath != sanitizedEnv.end()) ? currentPath->second : "";
            sanitizedEnv["PATH"] = AppendEnvPathValue(base, preset.second);
        } else {
            sanitizedEnv[preset.first] = preset.second;
        }
    }

    for (const auto &item : config_.env) {
        std::string normalizedKey;
        if (!NormalizeHostOverrideEnvVarKey(item.first, normalizedKey)) {
            overrideRejectedInvalid++;
            SANDBOX_LOGD("[DEBUG INFO] Env debug override rejected invalid, rawKey=%{public}s", item.first.c_str());
            continue;
        }
        std::string upperKey = ToUpperAscii(normalizedKey);
        if (upperKey == "PATH") {
            auto currentPath = sanitizedEnv.find("PATH");
            bool hasCurrentPath = currentPath != sanitizedEnv.end();
            size_t currentPathLen = hasCurrentPath ? currentPath->second.size() : 0;
            std::string mergedPath = AppendEnvPathValue(hasCurrentPath ? currentPath->second : "", item.second);
            sanitizedEnv["PATH"] = mergedPath;
            overrideAccepted++;
            SANDBOX_LOGD("[DEBUG INFO] Env debug path append accepted, configuredLen=%{public}zu, "
                "currentExists=%{public}d, currentLen=%{public}zu, finalLen=%{public}zu",
                item.second.size(), hasCurrentPath ? 1 : 0, currentPathLen, mergedPath.size());
            continue;
        }
        if (IsDangerousHostEnvVarName(upperKey) || IsDangerousHostEnvOverrideVarName(upperKey)) {
            overrideRejectedBlocked++;
            SANDBOX_LOGD("[DEBUG INFO] Env debug override rejected blocked, key=%{public}s", normalizedKey.c_str());
            continue;
        }
        sanitizedEnv[normalizedKey] = item.second;
        overrideAccepted++;
        SANDBOX_LOGD("[DEBUG INFO] Env debug override accepted, key=%{public}s, valueLen=%{public}zu",
            normalizedKey.c_str(), item.second.size());
    }
}

int SandboxManager::ApplyEnvironment()
{
    SANDBOX_LOGD("[DEBUG INFO] Env debug apply begin, count=%{public}zu, uid=%{public}u, gid=%{public}u",
        config_.env.size(), config_.uid, config_.gid);

    std::map<std::string, std::string> sanitizedEnv;
    size_t inheritedAccepted = 0;
    size_t inheritedRejected = 0;
    SanitizeInheritedEnv(sanitizedEnv, inheritedAccepted, inheritedRejected);

    size_t overrideAccepted = 0;
    size_t overrideRejectedBlocked = 0;
    size_t overrideRejectedInvalid = 0;
    SanitizeOverrideEnv(sanitizedEnv, overrideAccepted, overrideRejectedBlocked, overrideRejectedInvalid);

    sanitizedEnv[CLAW_SANDBOX_ENV_KEY] = CLAW_SANDBOX_ENV_VALUE;

    SANDBOX_LOGD("[DEBUG INFO] Env debug sanitize summary, inheritedAccepted=%{public}zu, "
        "inheritedRejected=%{public}zu, overrideAccepted=%{public}zu, "
        "overrideRejectedBlocked=%{public}zu, overrideRejectedInvalid=%{public}zu, "
        "finalCount=%{public}zu",
        inheritedAccepted, inheritedRejected, overrideAccepted, overrideRejectedBlocked,
        overrideRejectedInvalid, sanitizedEnv.size());

    return ApplySanitizedEnv(sanitizedEnv);
}

int SandboxManager::ExecuteCommand()
{
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
} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
