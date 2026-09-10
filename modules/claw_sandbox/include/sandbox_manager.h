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
#include "sandbox_device_ioctl.h"
#include "sandbox_error.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

// Offsets a sandbox user id (config_.uid / UID_BASE). Shared between the
// op-control delivery chain (sandbox_op_control_deliver.cpp) and the remaining
// DEC ioctl code in sandbox_manager.cpp; the ioctl vocabulary itself lives in
// sandbox_device_ioctl.h.
constexpr int UID_BASE = 200000;

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
    int Initialize(const SandboxConfig config, const CmdInfo &cmdInfo);

    /**
     * @brief Execute the sandbox workflow
     * @return SANDBOX_SUCCESS on success (current process replaced by execvp),
     *         error code on failure (e.g. SANDBOX_ERR_NS_FAILED, SANDBOX_ERR_MOUNT_FAILED, etc.)
     */
    int Execute();

    /**
     * @brief Recursively delete the sandbox directory tree named by config.name
     * @return SANDBOX_SUCCESS on success, error code on failure
     */
    int DeleteSandboxDir();

private:
    // Template configuration items (defined before use)
    struct MountEntry {
        std::string source;
        std::string target;
        std::vector<std::string> mountFlags;  // e.g. ["bind", "rec", "rdonly", "slave"]
        bool checkExists = false;
    };

    struct SymLinkEntry {
        std::string source;
        std::string target;
    };

    // Per-permission configuration
    struct PermissionConfig {
        bool sandboxSwitch = false;              // sandbox-switch: "ON"/"OFF"
        std::vector<int> gids;                   // gids array
        std::vector<std::string> decPaths;       // decryption paths (dec-paths)
    };

    // Conditional mount rule: defines a permission-gated mount entry.
    // The mount is performed (or validated) only if at least one permission
    // in the permissions list is granted (OR logic).
    struct ConditionalRule {
        std::string source;                      // host source path
        std::string target;                      // sandbox target path
        std::vector<std::string> mountFlags;     // e.g. ["bind", "rec"]
        bool checkExists = true;                 // check source existence before mount
        std::vector<std::string> permissions;    // required permissions (OR)
    };

    struct EnvPolicy {
        std::vector<std::string> blockedEverywhereKeys;
        std::vector<std::string> blockedOverrideOnlyKeys;
        std::vector<std::string> allowedInheritedOverrideOnlyKeys;
        std::vector<std::string> blockedPrefixes;
        std::vector<std::string> blockedOverridePrefixes;
    };

    struct TemplateConfig {
        std::vector<std::string> execSelinuxTypes;
        std::vector<MountEntry> systemMounts;
        std::vector<SymLinkEntry> symLinks;
        std::vector<MountEntry> appMounts;
        std::vector<std::string> seccompAllowList;
        EnvPolicy envPolicy;
        std::map<std::string, PermissionConfig> permissions;  // permission name -> config
        std::vector<ConditionalRule> conditionalRules;        // conditional mount rules
    };

    // Expose individual steps for testing (not intended for public use)
    int ExecuteEarlySteps();
    int ExecuteMountSteps();
    int ExecuteLateSteps();

    // 15-step workflow (all return int error codes)
    int ValidateConfig();
    int ValidateBasicParams();
    int ValidateTokenType();
    int LoadTemplate();
    int GenerateTokenId();
    int EnterCallerSandbox();
    int CreateNewRoot();
    int UnshareNamespaces();
    int MountNewRoot();
    int MountSystemDirs();
    int MountSymLinks();
    int MountAppDirs();
    int ApplyPolicyMounts();
    int PivotRoot();
#ifdef CONFIG_SHELL_SANDBOX
    void CollectDenyPaths(DecPolicyInfo& decPolicyInfo);
    bool FillPolicyMetadata(DecPolicyInfo& decPolicyInfo);
    int SendDecPolicyIoctl(const DecPolicyInfo& decPolicyInfo);
    int DispatchDecBatches(const std::vector<std::string>& decPaths, uint64_t tokenId, uint64_t timestamp);
    int ApplyDecPolicies();
    int PreDecDenyPaths();
#endif
    int ForkAfterUnshare();
    /*
     * Whether the fork happens at all. It is what puts the sandboxed program
     * into a new pid namespace - unshare(CLONE_NEWPID) leaves the caller in the
     * old one and only its children join the new one - so without that flag a
     * cli sandbox has nothing to fork for and execs in place. A shell sandbox
     * always forks: the parent stays behind as its monitor.
     */
    bool NeedsForkAfterUnshare() const;
    // The two sides of ForkAfterUnshare. ParentAfterFork never returns; the code
    // it would leave with is ParentAfterForkExitCode's, which is where the work
    // actually happens and the only half a test can reach.
    int ParentAfterForkExitCode(pid_t pid);
    void ParentAfterFork(pid_t pid);
    int ChildAfterFork();

    /*
     * The start gate: a socketpair the child blocks on straight after the fork,
     * so that no sandboxed program begins running before the parent knows
     * whether it can watch it.
     *
     * ConnectMonitorSocket is the last step that can fail the launch before the
     * fork; everything that can still go wrong afterwards - SandboxMonitor::Init
     * - happens with a child already running. The gate closes that window
     * without a signal: the parent either releases it or drops it, and the child
     * sees a byte or an EOF.
     *
     * NeedsStartGate is the same condition RunMonitorForChild uses to decide
     * whether to build a monitor. Both sides of the fork ask it rather than
     * inspecting the fds, so they cannot disagree about whether a gate exists: a
     * cli sandbox has no monitor to wait for and is never held up by one.
     */
    bool NeedsStartGate() const;
    int CreateStartGate();
    // Parent, monitor ready: let the child through.
    void ReleaseStartGate();
    // Parent, monitor wanted but unavailable: drop the write end so the child's
    // read returns EOF. Also the no-op that covers an already released gate.
    void CloseStartGate();
    // Child, only when NeedsStartGate(): block until released, or
    // _exit(EXIT_MONITOR_UNAVAILABLE) on EOF.
    void WaitForStartGate();
    // Child exit code, or negative when this sandbox has no monitor or the
    // monitor never took over - both mean the caller falls back to waitpid.
    int RunMonitorForChild(pid_t pid);
#ifdef CONFIG_SHELL_SANDBOX
    int OpenDecDeviceBeforeFork();
#endif
    int MountProcFs();
    int SetAccessToken();
#ifdef CONFIG_SHELL_SANDBOX
    int SetParentHapTokenId(uint64_t tokenId);
#endif
    int SetAinfo();
    int SetXpmOwnerId();
#ifdef MCS_ENABLE
    int SetSelinuxMCS();
#endif
    int SetUidGid();
    int SetGroups();
    int SetProcessGroup();
    int SetSeccomp();
    int DropCapabilities();
    int PrepareWorkdir();
    int ApplyEnvironment();
#ifdef CONFIG_SHELL_SANDBOX
    int DeliverDaemonSidePolicies();
    int DeliverExecuterInit();
    int SetEncapsProcFlag();
    int SetSandboxPathMark();
#endif
    // Open the executable and vet its SELinux type, returning the fd so that the
    // file checked is the file executed. Returns -1 when it must not run.
    int OpenAllowedExecutable(const char *path);
    int ParseExecSelinuxTypesJson(cJSON *root);
    int ExecuteCommand();

    // Helper methods
    int MountDir(const std::string &source, const std::string &target,
                 const std::vector<std::string> &mountFlags);
    int CreateDir(const std::string &path);
    void Cleanup();
    int LoadJsonConfig(const std::string &jsonPath);

    // Mount a single system entry (simple bind mount, no remount readonly or propagation)
    int MountSystemEntry(const MountEntry &entry, const std::string &targetPrefix);

    // symlink a signle entry
    int DoMountSequence(const std::string &source, const std::string &target,
                        unsigned long allFlags);
    int SymlinkSingleEntry(const SymLinkEntry &entry, const std::string &targetPrefix);

    // Mount a single entry (extracted from MountAppDirs for 50-line limit)
    int MountSingleEntry(const MountEntry &entry, const std::string &targetPrefix);

    enum ConditionalMatchResult {
        CONDITIONAL_MATCHED,
        CONDITIONAL_BLOCKED,
        CONDITIONAL_NOMATCH
    };

    int MountPolicyPath(const SandboxConfig::PolicyMount &policyMount);
    int RemountPolicyMount(const SandboxConfig::PolicyMount &policyMount,
                           const std::string &target);
    int BindMountConditionalPath(const SandboxConfig::PolicyMount &policyMount,
                                  const std::string &mountTarget,
                                  const std::string &physicalSource);
    ConditionalMatchResult MatchConditionalSource(const std::string &target,
                                                   std::string &physicalSource) const;
public:
    static bool IsPolicyWriteEscalation(bool policyReadOnly, bool existingReadOnly);
    std::vector<int> CollectGrantedPermissionGids() const;
    std::vector<std::string> CollectDecPolicyPaths() const;
    int CollectPermissionDecPaths(const PermissionConfig &config, std::vector<std::string> &decPaths) const;
    bool IsPermissionGranted(const std::string &permissionName) const;
    int SetDecPolicyBatch(int fd, const std::vector<std::string> &paths,
                          uint64_t tokenId, uint64_t timestamp, size_t start, size_t count);

    // LoadJsonConfig sub-helpers (each under 50 lines)
    int ParseSystemMountsJson(cJSON *root);
    int ParseSymLinkJson(cJSON *root);
    int ParseAppMountsJson(cJSON *root);
    int ParseEnvPolicyJson(cJSON *root);
    int ParseSeccompJson(cJSON *root);
    int ParsePermissionJson(cJSON *root);
    int ParsePermissionSectionJson(cJSON *perm);
    int ParsePermissionObjectJson(cJSON *perm);
    int ParsePermissionArrayJson(cJSON *perm);
    void ParsePermissionSwitch(cJSON *obj, PermissionConfig &pc);
    void ParsePermissionSwitch(cJSON *obj, PermissionConfig &pc, bool defaultSwitch);
    void ParsePermissionGids(cJSON *obj, PermissionConfig &pc);
    void ParsePermissionDecPaths(cJSON *obj, PermissionConfig &pc);
    int ParseConditionalJson(cJSON *root);
    int ParseConditionalRule(cJSON *item, ConditionalRule &rule, const std::string &path);
    int LoadDefaultConfig();
    static void ParseMountEntry(cJSON *entry, MountEntry &me);
    static void ParseSymLinkEntry(cJSON *entry, SymLinkEntry &me);

    // ParsePermissionJson sub-helpers (extracted to reduce nesting depth)
    int ParseSinglePermissionItem(cJSON *permItem);
    int ParseSinglePermissionArrayItem(cJSON *permItem);
    int ParseSinglePermissionConfig(cJSON *obj, const std::string &permName);
    int ParseSinglePermissionConfig(cJSON *obj, const std::string &permName, bool defaultSwitch);

    // Environment policy helpers
    bool IsAllowedInheritedOverrideOnlyEnvKey(const std::string &upperKey) const;
    bool IsDangerousHostEnvVarName(const std::string &key) const;
    bool IsDangerousHostInheritedEnvVarName(const std::string &key) const;
    bool IsDangerousHostEnvOverrideVarName(const std::string &key) const;

    // ApplyEnvironment sub-helpers
    void SanitizeInheritedEnv(std::map<std::string, std::string> &sanitizedEnv,
                              size_t &inheritedAccepted, size_t &inheritedRejected);
    void SanitizeOverrideEnv(std::map<std::string, std::string> &sanitizedEnv,
                             size_t &overrideAccepted, size_t &overrideRejectedBlocked,
                             size_t &overrideRejectedInvalid);

    // Seccomp sub-helpers
    int BuildSeccompFilter(struct sock_fprog &prog);
    int InstallCustomSeccompFilter();

    // CreateNewRoot sub-helpers
    int CreateSandboxWithName(const std::string &name);
    int CreateSandboxAutoName();

    /**
     * @brief Convert string mount flag array to unsigned long bitmask
     * @param mountFlags String array, e.g. ["bind", "rec", "rdonly", "slave"]
     * @return Combined mount flags bitmask
     */
    static unsigned long ConvertMountFlags(const std::vector<std::string> &mountFlags);

    std::string NormalizeDecPath(const std::string &decPath) const;

    // Move the "SANDBOX_SOCKET_PATH" entry out of config_.env into monitorSocketPath_,
    int ExtractMonitorSocketPath();

#ifdef CONFIG_SHELL_SANDBOX
    // Connect to the app's monitor socket before the fork, so that a bad path or
    // a refused connection still fails the sandbox launch. A caller that passed
    // no path at all opted out and is not an error.
    int ConnectMonitorSocket();
    bool IsMonitorSocketPathAllowed() const;
#endif

    SandboxConfig config_;
    CmdInfo cmdInfo_;
    TemplateConfig templateConfig_;
    std::string newRootPath_;
    std::string putOldPath_;
    std::vector<std::string> mountedDirs_;
    std::vector<struct sock_filter> seccompFilter_;  // Persists filter data for PR_SET_SECCOMP
    // UDS path the calling app listens on, taken from the "SANDBOX_SOCKET_PATH" policy
    // env entry in Initialize. Empty when the caller supplied none, which leaves
    // SandboxMonitor unable to forward DEC events.
    std::string monitorSocketPath_;
    /*
     * Connected monitor socket, opened before the fork by ConnectMonitorSocket
     * and handed to SandboxMonitor in the parent. -1 when the caller passed no
     * path, and always -1 off PC where nothing ever connects.
     */
    int monitorSocketFd_ = -1;
    // Parent's daemon-initialized /dev/dec fd, opened with O_CLOEXEC by
    // DeliverDaemonSidePolicies and held across the fork. Ownership passes to
    // SandboxMonitor, which closes it; the monitor never reopens an
    // uninitialized fallback fd. The child closes its own inherited copy in
    // ForkAfterUnshare and reopens its own in DeliverExecuterInit.
    int decFd_ = -1;
    // Start gate ends: the child keeps the read end, the parent the write end,
    // and each closes the other's copy right after the fork. Both stay -1 for a
    // sandbox that NeedsStartGate() says needs none.
    int startGateReadFd_ = -1;
    int startGateWriteFd_ = -1;
    bool initialized_ = false;
    bool pivotRootDone_ = false;
};

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS

#endif // CLAW_SANDBOX_SANDBOX_MANAGER_H
