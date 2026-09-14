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

#include "sandbox_op_control_deliver_test.h"
#include "sandbox_cmd_parser.h"
#include "sandbox_error.h"
#include "sandbox_mock_state.h"
#include <sys/mount.h>
#include <sys/syscall.h>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <selinux/context.h>
#include <selinux/selinux.h>
#include <string>
#include <unistd.h>
#include <sys/stat.h>
#include <utility>
#include <vector>
#include <cstring>
#include <securec.h>
#define private public
#include "sandbox_manager.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

// The high half of an AccessTokenIDEx. It gates nothing - ValidateTokenType
// masks it off - so it is here only to keep the test tokens shaped like real ones.
static constexpr uint64_t TEST_TOKEN_ID_HIGH_BIT = (static_cast<uint64_t>(1) << 32);

// A callerTokenId with a non-zero low 32-bit token ID.
// The low 32 bits (AccessTokenID) will be passed to AccessTokenKit::GetTokenTypeFlag.
// In the real device test environment, this requires a properly initialized token system.
static constexpr uint64_t TEST_HAP_TOKEN_ID = TEST_TOKEN_ID_HIGH_BIT | 0x200D000D;

static constexpr int32_t TEST_IOCTL_FD = 100;

// RAII guard that resets the global IoctlMockState to defaults on destruction.
class IoctlMockGuard {
public:
    IoctlMockGuard()
    {
        // Save current state and reset for a clean test
        saved_ = g_ioctlMockState;
        g_ioctlMockState.mockEnabled = false;
        g_ioctlMockState.openFail = true;
        g_ioctlMockState.openErrno = ENOENT;
        g_ioctlMockState.mockFd = TEST_IOCTL_FD;
        g_ioctlMockState.failOnCallIndex = -1;
        g_ioctlMockState.ioctlErrno = EINVAL;
        g_ioctlMockState.ioctlCallCount = 0;
    }

    ~IoctlMockGuard()
    {
        g_ioctlMockState = saved_;
    }

private:
    IoctlMockState saved_;
};

void ClawSandboxOpControlDeliverTest::SetUpTestCase() {}
void ClawSandboxOpControlDeliverTest::TearDownTestCase() {}
void ClawSandboxOpControlDeliverTest::SetUp() {}
void ClawSandboxOpControlDeliverTest::TearDown() {}

// ==================== DeliverExecuterInit tests ====================

// Helper: add network rule group(s) so DeliverExecuterInit has a policy to deliver.
// Stored in config.policy.addOperationControlRuleGroups (auto-managed vector).
static void AddMinimalNetworkRuleGroup(SandboxConfig &config, uint32_t count = 1)
{
    for (uint32_t i = 0; i < count; ++i) {
        SandboxPolicyRuleGroup group;
        group.hasNetwork = true;
        group.networkRules.defaultAction = DEC_POLICY_ACTION_DENY;
        config.policy.addOperationControlRuleGroups.push_back(group);
    }
}

/**
 * @tc.name: DeliverExecuterInit001
 * @tc.desc: DeliverExecuterInit runs the executer-init ioctl even with no policy rule
 *           groups (executer init is not gated on rules): open succeeds, one ioctl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverExecuterInit001, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;
    g_ioctlMockState.failOnCallIndex = -1;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverExecuterInit();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    // child side: only the executer-init ioctl, even without rule groups
    EXPECT_EQ(1, g_ioctlMockState.ioctlCallCount);
}

/**
 * @tc.name: DeliverExecuterInit003
 * @tc.desc: DeliverExecuterInit returns SET_POLICY_FAILED when open("/dev/dec") fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverExecuterInit003, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = true;
    g_ioctlMockState.openErrno = ENOENT;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    AddMinimalNetworkRuleGroup(config);
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverExecuterInit();
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_FAILED, ret);
}

/**
 * @tc.name: DeliverExecuterInit004
 * @tc.desc: DeliverExecuterInit (child side) returns SET_POLICY_FAILED when the
 *           executer-init ioctl (DEC_CMD_AGENTLOCK_CURR_EXECUTER_INIT, call
 *           index 0) fails. Verifies fd is closed on the error path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverExecuterInit004, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;     // open succeeds → mockFd
    g_ioctlMockState.failOnCallIndex = 0;  // executer-init ioctl (call index 0) fails
    g_ioctlMockState.ioctlErrno = EINVAL;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    AddMinimalNetworkRuleGroup(config);
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverExecuterInit();
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_FAILED, ret);
    EXPECT_EQ(1, g_ioctlMockState.ioctlCallCount);
}

/**
 * @tc.name: DeliverExecuterInit006
 * @tc.desc: DeliverExecuterInit (child side) full success path: open succeeds, then
 *           the executer-init ioctl runs and returns SANDBOX_SUCCESS (the
 *           daemon-side daemon init / config get / add policy ran earlier in the
 *           parent via DeliverDaemonSidePolicies). Verifies fd is closed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverExecuterInit006, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;
    g_ioctlMockState.failOnCallIndex = -1;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    AddMinimalNetworkRuleGroup(config);
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverExecuterInit();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    // child side: only the executer-init ioctl
    EXPECT_EQ(1, g_ioctlMockState.ioctlCallCount);
}

/**
 * @tc.name: DeliverExecuterInit007
 * @tc.desc: DeliverExecuterInit with open returning EACCES verifies the error code
 *           is propagated as SANDBOX_ERR_SET_POLICY_FAILED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverExecuterInit007, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = true;
    g_ioctlMockState.openErrno = EACCES;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    AddMinimalNetworkRuleGroup(config);
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverExecuterInit();
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_FAILED, ret);
}

/**
 * @tc.name: DeliverExecuterInit008
 * @tc.desc: DeliverExecuterInit (child side) with the executer-init ioctl failing with
 *           ENOTTY verifies that different errno values are handled (function
 *           returns SET_POLICY_FAILED regardless of the specific errno)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverExecuterInit008, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;
    g_ioctlMockState.failOnCallIndex = 0;
    g_ioctlMockState.ioctlErrno = ENOTTY;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    AddMinimalNetworkRuleGroup(config);
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverExecuterInit();
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_FAILED, ret);
}

/**
 * @tc.name: DeliverExecuterInit009
 * @tc.desc: DeliverExecuterInit (child side) with multiple network rule groups verifies
 *           the executer-init still issues exactly one ioctl (the per-module add
 *           policy delivery happens in the parent's DeliverDaemonSidePolicies)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverExecuterInit009, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;
    g_ioctlMockState.failOnCallIndex = -1;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    AddMinimalNetworkRuleGroup(config, 3);
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverExecuterInit();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    // child side: only the executer-init ioctl
    EXPECT_EQ(1, g_ioctlMockState.ioctlCallCount);
}

// ==================== DeliverDaemonSidePolicies tests ====================
// Parent-side DEC/AgentLock delivery, run before ForkAfterUnshare: opens /dev/dec
// with O_CLOEXEC (kept in decFd_ across the fork), issues daemon init, then
// exactly one policy config set (also when rule groups are empty -- an empty
// config still config-sets the sole self_session scope), then one add policy per
// (group, module) when rule groups exist.

/**
 * @tc.name: DeliverDaemonSidePolicies001
 * @tc.desc: Empty operation-control rule groups still run daemon init, the ASK
 *           subscription and one self_session config set (3 ioctls) and hold
 *           decFd_ open across the fork; no add-policy ioctl follows. The
 *           monitor socket rule is attempted regardless of rule groups, but
 *           this config names no socket, so it no-ops before any ioctl.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverDaemonSidePolicies001, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;
    g_ioctlMockState.failOnCallIndex = -1;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    config.appIdentifierU64 = 20020026;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverDaemonSidePolicies();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    // daemon init (call 0) + self_session config set (call 1); no rule groups → no ADD
    EXPECT_EQ(3, g_ioctlMockState.ioctlCallCount);
    EXPECT_GE(manager.decFd_, 0);
    if (manager.decFd_ >= 0) {
        close(manager.decFd_);
    }
}

/**
 * @tc.name: DeliverDaemonSidePolicies002
 * @tc.desc: open("/dev/dec") failure returns SANDBOX_ERR_SET_POLICY_FAILED, decFd_
 *           stays -1 and no ioctl is issued.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverDaemonSidePolicies002, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = true;
    g_ioctlMockState.openErrno = ENOENT;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    AddMinimalNetworkRuleGroup(config);
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverDaemonSidePolicies();
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_FAILED, ret);
    EXPECT_EQ(0, g_ioctlMockState.ioctlCallCount);
    EXPECT_EQ(-1, manager.decFd_);
}

/**
 * @tc.name: DeliverDaemonSidePolicies003
 * @tc.desc: DEC_CMD_AGENTLOCK_CURRENT_DAEMON_INIT (call index 0) failing returns
 *           SANDBOX_ERR_SET_POLICY_FAILED after 1 ioctl and closes decFd_.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverDaemonSidePolicies003, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;
    g_ioctlMockState.failOnCallIndex = 0;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    config.appIdentifierU64 = 20020026;
    AddMinimalNetworkRuleGroup(config);
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverDaemonSidePolicies();
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_FAILED, ret);
    EXPECT_EQ(1, g_ioctlMockState.ioctlCallCount);
    EXPECT_EQ(-1, manager.decFd_);
}

/**
 * @tc.name: DeliverDaemonSidePolicies004
 * @tc.desc: DEC_CMD_POLICY_CONFIG_SET (call index 2) failing returns
 *           SANDBOX_ERR_SET_POLICY_FAILED after 3 ioctls and closes decFd_.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverDaemonSidePolicies004, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;
    g_ioctlMockState.failOnCallIndex = 2;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    config.appIdentifierU64 = 20020026;
    AddMinimalNetworkRuleGroup(config);
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverDaemonSidePolicies();
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_FAILED, ret);
    EXPECT_EQ(3, g_ioctlMockState.ioctlCallCount);
    EXPECT_EQ(-1, manager.decFd_);
}

/**
 * @tc.name: DeliverDaemonSidePolicies005
 * @tc.desc: DEC_CMD_POLICY_ADD for the network module (call index 3) failing
 *           returns SANDBOX_ERR_SET_POLICY_FAILED after 4 ioctls and closes decFd_.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverDaemonSidePolicies005, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;
    g_ioctlMockState.failOnCallIndex = 3;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    config.appIdentifierU64 = 20020026;
    AddMinimalNetworkRuleGroup(config);
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverDaemonSidePolicies();
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_FAILED, ret);
    EXPECT_EQ(4, g_ioctlMockState.ioctlCallCount);
    EXPECT_EQ(-1, manager.decFd_);
}

/**
 * @tc.name: DeliverDaemonSidePolicies006
 * @tc.desc: Full success path: daemon init + ASK subscription + config set +
 *           add policy (network) succeed (4 ioctls), SANDBOX_SUCCESS returned,
 *           and decFd_ is held open for the fork (closed manually here to keep
 *           the test clean).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverDaemonSidePolicies006, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;
    g_ioctlMockState.failOnCallIndex = -1;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    config.appIdentifierU64 = 20020026;
    AddMinimalNetworkRuleGroup(config);
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverDaemonSidePolicies();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(4, g_ioctlMockState.ioctlCallCount);
    // fd is intentionally left open (it would be closed by ForkAfterUnshare);
    // close it here so the test does not leak an fd.
    EXPECT_GE(manager.decFd_, 0);
    if (manager.decFd_ >= 0) {
        close(manager.decFd_);
    }
}

/**
 * @tc.name: DeliverDaemonSidePolicies007
 * @tc.desc: Two Network rule groups each deliver their own DEC_CMD_POLICY_ADD:
 *           daemon init + one DEC_CMD_POLICY_CONFIG_SET + two ADDs = 4 ioctls
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverDaemonSidePolicies007, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;
    g_ioctlMockState.failOnCallIndex = -1;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    config.appIdentifierU64 = 20020026;
    AddMinimalNetworkRuleGroup(config, 2);
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverDaemonSidePolicies();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(5, g_ioctlMockState.ioctlCallCount);
    // fd is intentionally left open (it would be closed by ForkAfterUnshare);
    // close it here so the test does not leak an fd.
    EXPECT_GE(manager.decFd_, 0);
    if (manager.decFd_ >= 0) {
        close(manager.decFd_);
    }
}

// Return a directory the test process can actually create files in, probed once at
// first call. /tmp is not guaranteed writable for a non-root unit-test process on
// every target, so fall back through TMPDIR / cwd / /data/local/tmp before /tmp.
static std::string GetWritableTempDir()
{
    static const std::string dir = []() -> std::string {
        std::vector<std::string> candidates;
        const char *envDir = getenv("TMPDIR");
        if (envDir != nullptr && envDir[0] != '\0') {
            candidates.push_back(envDir);
        }
        char cwdBuf[4096];
        if (getcwd(cwdBuf, sizeof(cwdBuf)) != nullptr) {
            candidates.push_back(cwdBuf);
        }
        candidates.push_back("/data/local/tmp");
        candidates.push_back("/tmp");
        for (const auto &cand : candidates) {
            std::string tmpl = cand + "/claw_sandbox_writable_probe_XXXXXX";
            if (tmpl.size() + 1 > sizeof(cwdBuf)) {
                continue;  // path too long for mkstemp
            }
            std::vector<char> buf(tmpl.begin(), tmpl.end());
            buf.push_back('\0');
            int fd = mkstemp(buf.data());
            if (fd >= 0) {
                close(fd);
                unlink(buf.data());
                return cand;
            }
        }
        return std::string("/tmp");  // last resort: keeps the same failure signal if none writable
    }();
    return dir;
}

// Build a mkstemp path under the writable temp dir (pattern must end in XXXXXX).
static std::string MakeTempFilePath(const char *pattern)
{
    std::string tmpl = GetWritableTempDir() + "/" + pattern;
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    int fd = mkstemp(buf.data());
    if (fd >= 0) {
        close(fd);
    }
    return std::string(buf.data());
}

// Create a real regular temp file and return its path (caller unlink()s it).
// OpenFileFds fails -- rather than tolerates -- paths it cannot open, so file
// rules in a delivered group must point at an openable file.
static std::string CreateTempRuleFile()
{
    return MakeTempFilePath("claw_sandbox_rule_XXXXXX");
}

// Helper: add a File rule group with one deny-delete path.
static void AddMinimalFileRuleGroup(SandboxConfig &config, const std::string &path)
{
    SandboxPolicyRuleGroup group;
    group.hasFile = true;
    group.fileRules.denyDelete.push_back(path);
    config.policy.addOperationControlRuleGroups.push_back(group);
}

// Helper: add a Process rule group with one deny-exec cmd.
static void AddMinimalProcessRuleGroup(SandboxConfig &config, const std::string &cmd)
{
    SandboxPolicyRuleGroup group;
    group.hasProcess = true;
    group.processRules.denyExecCmd.push_back(cmd);
    config.policy.addOperationControlRuleGroups.push_back(group);
}

/**
 * @tc.name: ForkAfterUnshare001
 * @tc.desc: OpenDecDeviceBeforeFork returns -1 (non-fatal) when the /dev/dec open
 *           fails. DeliverDaemonSidePolicies uses it as the parent-side
 *           pre-fork open (storing the fd in decFd_); the open must not hard-fail
 *           because the child reopens its own fd in DeliverExecuterInit when DEC policy
 *           is configured.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, ForkAfterUnshare001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // Split rather than OR'd: with the left side a uint32_t, each |= is an
    // unsigned operation, while CLONE_NEWNS | CLONE_NEWUTS on its own is not.
    config.nsFlags = CLONE_NEWNS;
    config.nsFlags |= CLONE_NEWUTS;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    // Force the /dev/dec open to fail; the probe must report -1 without erroring.
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = true;
    g_ioctlMockState.openErrno = ENOENT;

    int fd = manager.OpenDecDeviceBeforeFork();
    EXPECT_EQ(-1, fd);

    g_ioctlMockState.mockEnabled = false;
    g_ioctlMockState.openFail = true;
}

/**
 * @tc.name: ForkAfterUnshare002
 * @tc.desc: OpenDecDeviceBeforeFork returns the opened fd when /dev/dec opens
 *           successfully (O_CLOEXEC open issued by DeliverDaemonSidePolicies
 *           and held across the fork)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, ForkAfterUnshare002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.nsFlags = 0;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    // Simulate a successful /dev/dec open (returns the mock fd).
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;
    g_ioctlMockState.mockFd = 100;

    int fd = manager.OpenDecDeviceBeforeFork();
    EXPECT_EQ(100, fd);
    if (fd >= 0) {
        close(fd);
    }

    g_ioctlMockState.mockEnabled = false;
    g_ioctlMockState.openFail = true;
}

// ==================== per-group / per-module coverage ====================

/**
 * @tc.name: DeliverDaemonSidePolicies008
 * @tc.desc: A rule group that carries no module is skipped (no ADD ioctl):
 *           daemon init + one scope config set still run = 2 ioctls
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverDaemonSidePolicies008, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;
    g_ioctlMockState.failOnCallIndex = -1;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    config.appIdentifierU64 = 20020026;
    SandboxPolicyRuleGroup emptyGroup;  // hasFile/hasProcess/hasNetwork all false
    config.policy.addOperationControlRuleGroups.push_back(emptyGroup);
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverDaemonSidePolicies();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(3, g_ioctlMockState.ioctlCallCount);  // no ADD for the module-less group
    if (manager.decFd_ >= 0) {
        close(manager.decFd_);
    }
}

/**
 * @tc.name: DeliverDaemonSidePolicies009
 * @tc.desc: A File rule group (openable deny path) delivers through the parent
 *           flow: daemon init + scope config set + one File ADD = 3 ioctls
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverDaemonSidePolicies009, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;
    g_ioctlMockState.failOnCallIndex = -1;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    config.appIdentifierU64 = 20020026;
    const std::string ruleFile = CreateTempRuleFile();
    AddMinimalFileRuleGroup(config, ruleFile);
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverDaemonSidePolicies();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(4, g_ioctlMockState.ioctlCallCount);
    if (manager.decFd_ >= 0) {
        close(manager.decFd_);
    }
    unlink(ruleFile.c_str());
}

/**
 * @tc.name: DeliverDaemonSidePolicies010
 * @tc.desc: A File rule whose path cannot be opened aborts delivery before any
 *           ADD ioctl: returns SANDBOX_ERR_PATH_INVALID after init + config set
 *           (2 ioctls) and closes decFd_
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverDaemonSidePolicies010, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;
    g_ioctlMockState.failOnCallIndex = -1;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    config.appIdentifierU64 = 20020026;
    AddMinimalFileRuleGroup(config, "/nonexistent/definitely/missing");
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverDaemonSidePolicies();
    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, ret);
    EXPECT_EQ(3, g_ioctlMockState.ioctlCallCount);  // no ADD reached
    EXPECT_EQ(-1, manager.decFd_);
}

/**
 * @tc.name: DeliverDaemonSidePolicies011
 * @tc.desc: A failure after one successful group reports the per-group tally:
 *           group 1 (Network) delivers, then group 2 (File, unopenable path)
 *           aborts → returns SANDBOX_ERR_PATH_INVALID after 3 ioctls
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverDaemonSidePolicies011, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;
    g_ioctlMockState.failOnCallIndex = -1;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    config.appIdentifierU64 = 20020026;
    AddMinimalNetworkRuleGroup(config);
    AddMinimalFileRuleGroup(config, "/nonexistent/definitely/missing");
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverDaemonSidePolicies();
    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, ret);
    EXPECT_EQ(4, g_ioctlMockState.ioctlCallCount);  // init + config set + group1 ADD
    EXPECT_EQ(-1, manager.decFd_);
}

/**
 * @tc.name: DeliverDaemonSidePolicies012
 * @tc.desc: An action-conflicting File rule group is rejected before any ADD: the
 *           conflict is caught during TLV conversion inside the group's delivery,
 *           so daemon init + scope config set (2 ioctls) run, then
 *           SANDBOX_ERR_CONFIG_INVALID is returned and decFd_ is closed -- no
 *           partial policy reaches the kernel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverDaemonSidePolicies012, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;
    g_ioctlMockState.failOnCallIndex = -1;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    config.appIdentifierU64 = 20020026;
    SandboxPolicyRuleGroup group;
    group.hasFile = true;
    group.fileRules.denyDelete.push_back("/conflict");
    group.fileRules.allowDelete.push_back("/conflict");
    config.policy.addOperationControlRuleGroups.push_back(group);
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverDaemonSidePolicies();
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
    EXPECT_EQ(3, g_ioctlMockState.ioctlCallCount);  // init + config set; no ADD reached
    EXPECT_EQ(-1, manager.decFd_);
}

/**
 * @tc.name: DeliverDaemonSidePolicies013
 * @tc.desc: A File rule group and a Process rule group each deliver their own ADD
 *           (groups never merge): daemon init + one scope config set + File ADD +
 *           Process ADD = 4 ioctls
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverDaemonSidePolicies013, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;
    g_ioctlMockState.failOnCallIndex = -1;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    config.appIdentifierU64 = 20020026;
    const std::string ruleFile = CreateTempRuleFile();
    AddMinimalFileRuleGroup(config, ruleFile);
    AddMinimalProcessRuleGroup(config, "ls");
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverDaemonSidePolicies();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(5, g_ioctlMockState.ioctlCallCount);  // init + config set + File ADD + Process ADD
    if (manager.decFd_ >= 0) {
        close(manager.decFd_);
    }
    unlink(ruleFile.c_str());
}

/**
 * @tc.name: DeliverDaemonSidePolicies014
 * @tc.desc: The ASK event subscription DaemonInit issues right after the daemon
 *           init (call index 1) failing returns SANDBOX_ERR_SET_POLICY_FAILED
 *           after 2 ioctls and closes decFd_. Without the subscription the
 *           kernel never reports an ASK, so there is no point going on.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverDaemonSidePolicies014, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;
    g_ioctlMockState.failOnCallIndex = 1;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // The DEC handshake is a shell-sandbox feature; cli skips it entirely.
    config.type = "shell";
    AddMinimalNetworkRuleGroup(config);
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.DeliverDaemonSidePolicies();
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_FAILED, ret);
    EXPECT_EQ(2, g_ioctlMockState.ioctlCallCount);
    EXPECT_EQ(-1, manager.decFd_);
}

/**
 * @tc.name: DeliverDaemonSidePolicies015
 * @tc.desc: A cli sandbox skips the whole daemon-side handshake: no device is
 *           opened and no ioctl is issued, so decFd_ stays -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlDeliverTest, DeliverDaemonSidePolicies015, TestSize.Level0)
{
    IoctlMockGuard guard;
    /*
     * Armed to fail rather than left off. The guard disables the mock, which
     * would send the open at the real /dev/dec and make the result depend on
     * whether the machine has one. With the mock on and openFail set, reaching
     * the device at all turns into SET_POLICY_FAILED, so success here is proof
     * the early return was taken.
     */
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = true;
    g_ioctlMockState.openErrno = ENOENT;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.type = "cli";
    AddMinimalNetworkRuleGroup(config);
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    EXPECT_EQ(SANDBOX_SUCCESS, manager.DeliverDaemonSidePolicies());
    EXPECT_EQ(0, g_ioctlMockState.ioctlCallCount);
    EXPECT_EQ(-1, manager.decFd_);
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
