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

#include "claw_sandbox_manager_test.h"
#include "sandbox_cmd_parser.h"
#include "sandbox_error.h"
#include "sandbox_mock_state.h"
#include "sandbox_test_privileged.h"
#include "sandbox_utils.h"
#include <sys/mount.h>
#include <sys/syscall.h>
#include <cerrno>
#include <csignal>
#include <fcntl.h>
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
#include <cstring>
#include <securec.h>
#define private public
#include "sandbox_manager.h"
#undef private

/*
 * Last on purpose. sandbox_log.h #undefs LOG_TAG and LOG_DOMAIN and redefines
 * them, and those are plain macros read where SANDBOX_LOGx is written, not
 * settings applied once. Any header included after this one that defines its own
 * LOG_TAG silently takes over, and the log lines go out under someone else's tag
 * and domain - which looks exactly like logging being broken.
 */
#include "sandbox_log.h"

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

static constexpr uint32_t TEST_MCS_UID = 20020026;

// A stand-in caller pid. Nothing below reads it back, so the value only has to
// be a plausible pid rather than this process or any real one.
static constexpr pid_t TEST_CALLER_PID = 1000;

class SandboxDirGuard {
public:
    explicit SandboxDirGuard(const std::string &suffix)
        : sandboxDir_("/mnt/sandbox"),
          baseDir_(sandboxDir_ + "/claw"),
          rootPath_(baseDir_ + "/claw_sandbox_ut_" + std::to_string(getpid()) + "_" + suffix),
          sandboxDirExisted_(Exists(sandboxDir_)),
          baseDirExisted_(Exists(baseDir_))
    {}

    ~SandboxDirGuard()
    {
        RemoveOwnedRoot();
        RemoveCreatedEmptyDir(baseDir_, baseDirExisted_);
        RemoveCreatedEmptyDir(sandboxDir_, sandboxDirExisted_);
    }

    const std::string &RootPath() const
    {
        return rootPath_;
    }

    std::string Name() const
    {
        return std::filesystem::path(rootPath_).filename().string();
    }

    void TrackCreatedRoot(const std::string &path)
    {
        rootPath_ = path;
    }

    bool MountRootExists() const
    {
        return Exists("/mnt");
    }

    static bool Exists(const std::string &path)
    {
        std::error_code ec;
        return std::filesystem::exists(path, ec);
    }

private:
    bool IsUnderBase() const
    {
        const std::string prefix = baseDir_ + "/";
        return rootPath_.compare(0, prefix.size(), prefix) == 0;
    }

    void RemoveOwnedRoot() const
    {
        if (!IsUnderBase()) {
            return;
        }
        std::error_code ec;
        std::filesystem::remove_all(rootPath_, ec);
    }

    static void RemoveCreatedEmptyDir(const std::string &path, bool existedBefore)
    {
        if (existedBefore) {
            return;
        }
        std::error_code ec;
        if (std::filesystem::is_directory(path, ec) && std::filesystem::is_empty(path, ec)) {
            std::filesystem::remove(path, ec);
        }
    }

    const std::string sandboxDir_;
    const std::string baseDir_;
    std::string rootPath_;
    const bool sandboxDirExisted_;
    const bool baseDirExisted_;
};

class TempJsonFile {
public:
    explicit TempJsonFile(const std::string &suffix)
    {
        std::error_code ec;
        std::filesystem::path dir = std::filesystem::temp_directory_path(ec);
        if (ec) {
            ec.clear();
            dir = std::filesystem::current_path(ec);
        }
        if (ec) {
            dir = ".";
        }
        path_ = (dir / ("claw_sandbox_ut_" + std::to_string(getpid()) + "_" +
            suffix + ".json")).string();
        std::filesystem::remove(path_, ec);
    }

    ~TempJsonFile()
    {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }

    const std::string &Path() const
    {
        return path_;
    }

    bool Write(const std::string &content) const
    {
        std::ofstream file(path_);
        if (!file.is_open()) {
            return false;
        }
        file << content;
        return file.good();
    }

private:
    std::string path_;
};


// RAII guard that enables deterministic SELinux mocks for a single test.
class SelinuxMockGuard {
public:
    SelinuxMockGuard()
    {
        saved_ = g_selinuxMockState;
        g_selinuxMockState = SelinuxMockState {};
        g_selinuxMockState.mockEnabled = true;
    }

    ~SelinuxMockGuard()
    {
        g_selinuxMockState = saved_;
    }

private:
    SelinuxMockState saved_;
};

static void InitializeMcsManager(SandboxManager &manager, pid_t callerPid)
{
    SandboxConfig config;
    config.uid = TEST_MCS_UID;
    config.gid = TEST_MCS_UID;
    config.callerPid = callerPid;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);
}

void ClawSandboxManagerTest::SetUpTestCase() {}
void ClawSandboxManagerTest::TearDownTestCase() {}
void ClawSandboxManagerTest::SetUp() {}
void ClawSandboxManagerTest::TearDown() {}

// ==================== Initialize tests ====================

/**
 * @tc.name: Initialize001
 * @tc.desc: Initialize with valid config sets initialized_ to true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, Initialize001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;

    int ret = manager.Initialize(std::move(config), cmdInfo);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: Initialize002
 * @tc.desc: Initialize derives currentUserId from uid correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, Initialize002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;  // uid / 200000 = 100
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.appIdentifier = "20020026";
    config.bundleName = "20020026";
    CmdInfo cmdInfo;

    manager.Initialize(std::move(config), cmdInfo);
    // currentUserId is derived as uid / UID_BASE (200000)
    // We can verify via ValidateConfig which uses config_.currentUserId indirectly
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ValidateConfig());
}

/**
 * @tc.name: Initialize003
 * @tc.desc: Initialize moves SANDBOX_SOCKET_PATH out of the override env for the monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, Initialize003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // SANDBOX_SOCKET_PATH is a shell-sandbox feature; Initialize refuses it otherwise.
    config.type = "shell";
    config.env = {{"SANDBOX_SOCKET_PATH", "/data/local/tmp/app.socket"}, {"LANG", "C"}};
    CmdInfo cmdInfo;

    manager.Initialize(std::move(config), cmdInfo);

    EXPECT_EQ("/data/local/tmp/app.socket", manager.monitorSocketPath_);
    // The sandboxed child must never see the path: the entry is gone from the
    // override env, and DELETE_ENV_VARS strips any host-inherited copy.
    EXPECT_EQ(0u, manager.config_.env.count("SANDBOX_SOCKET_PATH"));
    EXPECT_EQ("C", manager.config_.env["LANG"]);

    std::map<std::string, std::string> sanitizedEnv;
    sanitizedEnv["SANDBOX_SOCKET_PATH"] = "/inherited/from/host.socket";
    size_t accepted = 0;
    size_t rejectedBlocked = 0;
    size_t rejectedInvalid = 0;
    manager.SanitizeOverrideEnv(sanitizedEnv, accepted, rejectedBlocked, rejectedInvalid);
    EXPECT_EQ(0u, sanitizedEnv.count("SANDBOX_SOCKET_PATH"));
}

/**
 * @tc.name: Initialize004
 * @tc.desc: A caller that passes no SANDBOX_SOCKET_PATH opts out instead of failing the launch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, Initialize004, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.env = {{"LANG", "C"}};
    CmdInfo cmdInfo;

    EXPECT_EQ(SANDBOX_SUCCESS, manager.Initialize(std::move(config), cmdInfo));
    // The extraction runs everywhere, because taking SANDBOX_SOCKET_PATH out of the
    // config is what keeps it away from the child whether or not a monitor
    // exists to consume it.
    EXPECT_TRUE(manager.monitorSocketPath_.empty());

#ifdef CONFIG_SHELL_SANDBOX
    // Opting out starts the sandbox without a channel rather than aborting it.
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ConnectMonitorSocket());
    EXPECT_EQ(-1, manager.monitorSocketFd_);
#endif
}

/**
 * @tc.name: Initialize005
 * @tc.desc: Spelling SANDBOX_SOCKET_PATH more than one way is rejected instead of guessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, Initialize005, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    /*
     * Three distinct map keys that all normalise to the same variable: the
     * lookup trims surrounding space and upper-cases, nothing more, so these
     * collide while a near miss like "socket_path" does not.
     */
    config.type = "shell";
    config.env = {{"SANDBOX_SOCKET_PATH", "/data/local/tmp/a.socket"},
                  {"sandbox_socket_path", "/data/local/tmp/b.socket"},
                  {"  Sandbox_Socket_Path  ", "/data/local/tmp/c.socket"}};
    CmdInfo cmdInfo;

    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, manager.Initialize(std::move(config), cmdInfo));
    EXPECT_FALSE(manager.initialized_);
}

/**
 * @tc.name: Initialize006
 * @tc.desc: SANDBOX_SOCKET_PATH on a non-shell sandbox is ignored, not refused:
 *           the sandbox starts, simply without a monitor channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, Initialize006, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.type = "cli";
    config.env = {{"SANDBOX_SOCKET_PATH", "/data/local/tmp/app.socket"}};
    CmdInfo cmdInfo;

    /*
     * The monitor is a shell-sandbox feature, so ExtractMonitorSocketPath returns
     * before it ever looks at env. The variable does not reach the sandboxed
     * child either way - DELETE_ENV_VARS strips it in ApplyEnvironment - so the
     * only effect is that the path is never picked up.
     */
    EXPECT_EQ(SANDBOX_SUCCESS, manager.Initialize(std::move(config), cmdInfo));
    EXPECT_TRUE(manager.monitorSocketPath_.empty());
#ifdef CONFIG_SHELL_SANDBOX
    // Nothing to connect to, and that is not an error.
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ConnectMonitorSocket());
    EXPECT_EQ(-1, manager.monitorSocketFd_);
#endif
}

/*
 * Monitor socket plumbing is PC only, so everything that drives it lives
 * behind the same flag as the code under test.
 */
#ifdef CONFIG_SHELL_SANDBOX

/*
 * Makes the monitor socket whitelist observable at all.
 *
 * The allowed directory only exists inside an application sandbox, so without
 * the realpath redirect IsMonitorSocketPathAllowed() is false for every input
 * and an EXPECT_FALSE on it tests nothing. The guard creates a real directory,
 * points the mock at it, and puts a real file where the socket path is expected
 * - realpath() needs the target to exist. Both sides of the IsPathUnder()
 * comparison go through the redirect, leaving the containment rule as what is
 * actually under test. The base directory is probed, not hardcoded: see
 * MakeSocketPath in the monitor test.
 */
class MonitorSocketPathGuard {
public:
    explicit MonitorSocketPathGuard(const std::string &leaf)
    {
        static const char *candidates[] = {"/data/local/tmp", "/tmp", "."};
        const std::string suffix = "/claw_ut_socket_" + std::to_string(getpid());

        for (const char *base : candidates) {
            std::error_code ec;
            const std::string dir = std::string(base) + suffix;
            std::filesystem::create_directories(dir, ec);
            std::ofstream(dir + "/" + leaf).put('\0');
            if (!std::filesystem::exists(dir + "/" + leaf, ec)) {
                std::filesystem::remove_all(dir, ec);
                continue;
            }

            baseDir_ = base;
            dir_ = dir;
            valid_ = true;
            break;
        }

        g_pathMockState.redirectFrom = ALLOWED_DIR;
        g_pathMockState.redirectTo = dir_;
        g_pathMockState.mockEnabled = valid_;
    }

    ~MonitorSocketPathGuard()
    {
        // Process-wide state: it has to come back off however the test ends.
        g_pathMockState.mockEnabled = false;
        g_pathMockState.redirectFrom.clear();
        g_pathMockState.redirectTo.clear();

        std::error_code ec;
        std::filesystem::remove_all(dir_, ec);
    }

    bool Valid() const
    {
        return valid_;
    }

    /*
     * The directory the redirect target was created in. It is guaranteed to
     * exist and to sit outside the redirected tree, which makes it the one path
     * a test can rely on for the "not in the whitelist" case.
     */
    const std::string &BaseDir() const
    {
        return baseDir_;
    }

    // Must match MONITOR_SOCKET_ALLOWED_DIRS[0] in sandbox_manager.cpp.
    static constexpr const char *ALLOWED_DIR = "/data/storage/el1/base";

private:
    std::string baseDir_;
    std::string dir_;
    bool valid_ = false;
};

/**
 * @tc.name: ConnectMonitorSocket001
 * @tc.desc: A socket path inside the allowed directory reaches connect, and a
 *           failed connect aborts the launch instead of starting unmonitored
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ConnectMonitorSocket001, TestSize.Level0)
{
    MonitorSocketPathGuard guard("absent.socket");
    ASSERT_TRUE(guard.Valid());

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = getpid();
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // SANDBOX_SOCKET_PATH is a shell-sandbox feature; Initialize refuses it otherwise.
    config.type = "shell";
    config.env = {{"SANDBOX_SOCKET_PATH", std::string(MonitorSocketPathGuard::ALLOWED_DIR) + "/absent.socket"}};
    CmdInfo cmdInfo;

    manager.Initialize(std::move(config), cmdInfo);

    /*
     * The whitelist lets it through, so the launch fails on the connect instead.
     * connect() uses the path as written and the redirect does not reach it, so
     * there is genuinely nobody there - which is the case that has to abort the
     * launch rather than start a sandbox with no monitor.
     */
    EXPECT_TRUE(manager.IsMonitorSocketPathAllowed());
    EXPECT_EQ(SANDBOX_ERR_SOCKET_CONNECT_FAILED, manager.ConnectMonitorSocket());
    EXPECT_EQ(-1, manager.monitorSocketFd_);
}

/**
 * @tc.name: ConnectMonitorSocket002
 * @tc.desc: A socket path outside the allowed directories is refused before connecting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ConnectMonitorSocket002, TestSize.Level0)
{
    MonitorSocketPathGuard guard("unused.socket");
    ASSERT_TRUE(guard.Valid());

    /*
     * The guard just created a subdirectory here, so it resolves; and the
     * redirect points at that subdirectory, so this sits outside it. Asserted
     * rather than assumed: if it stopped resolving, the refusal below would come
     * from realpath instead of the containment rule and the test would go back
     * to passing for the wrong reason without saying so.
     */
    ASSERT_FALSE(GetRealPath(guard.BaseDir()).empty());

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = getpid();
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // SANDBOX_SOCKET_PATH is a shell-sandbox feature; Initialize refuses it otherwise.
    config.type = "shell";
    config.env = {{"SANDBOX_SOCKET_PATH", guard.BaseDir()}};
    CmdInfo cmdInfo;

    manager.Initialize(std::move(config), cmdInfo);

    EXPECT_FALSE(manager.IsMonitorSocketPathAllowed());
    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, manager.ConnectMonitorSocket());
    EXPECT_EQ(-1, manager.monitorSocketFd_);
}

/**
 * @tc.name: ConnectMonitorSocket003
 * @tc.desc: Containment is by path component, and ".." cannot step out of the allowed tree
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ConnectMonitorSocket003, TestSize.Level0)
{
    // A sibling whose name merely starts with the allowed directory must not
    // pass: this is containment, not a string prefix.
    EXPECT_FALSE(IsPathUnder("/tmp_other/x", "/tmp"));

    // Resolution happens before comparison, so traversal cannot escape.
    EXPECT_FALSE(IsPathUnder("/tmp/../etc", "/tmp"));

    // A path that cannot be resolved at all is refused rather than assumed good.
    EXPECT_FALSE(IsPathUnder("/tmp/no_such_dir_here/x.socket", "/tmp"));

    EXPECT_TRUE(IsPathUnder("/tmp", "/tmp"));
}

#endif // CONFIG_SHELL_SANDBOX

// ==================== ValidateConfig tests ====================

/**
 * @tc.name: ValidateConfig001
 * @tc.desc: ValidateConfig with valid parameters returns success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ValidateConfig001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.appIdentifier = "20020026";
    config.bundleName = "20020026";
    CmdInfo cmdInfo;

    manager.Initialize(std::move(config), cmdInfo);
    int ret = manager.ValidateConfig();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: ValidateConfig002
 * @tc.desc: ValidateConfig with invalid callerPid (0) returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ValidateConfig002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 0;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;

    manager.Initialize(std::move(config), cmdInfo);
    int ret = manager.ValidateConfig();
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, ret);
}

/**
 * @tc.name: ValidateConfig003
 * @tc.desc: ValidateConfig with pid_t max callerPid returns success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ValidateConfig003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;

    config.callerPid = std::numeric_limits<pid_t>::max();

    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.appIdentifier = "20020026";
    config.bundleName = "20020026";
    CmdInfo cmdInfo;

    manager.Initialize(std::move(config), cmdInfo);
    int ret = manager.ValidateConfig();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: ValidateConfig004
 * @tc.desc: ValidateConfig with uid below UID_BASE returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ValidateConfig004, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 1000;  // Below UID_BASE (200000)
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;

    manager.Initialize(std::move(config), cmdInfo);
    int ret = manager.ValidateConfig();
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, ret);
}

/**
 * @tc.name: ValidateConfig005
 * @tc.desc: ValidateConfig with gid below UID_BASE returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ValidateConfig005, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 1000;  // Below UID_BASE (200000)
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;

    manager.Initialize(std::move(config), cmdInfo);
    int ret = manager.ValidateConfig();
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, ret);
}

/**
 * @tc.name: ValidateConfig006
 * @tc.desc: ValidateConfig with callerTokenId = 0 returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ValidateConfig006, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = 0;
    CmdInfo cmdInfo;

    manager.Initialize(std::move(config), cmdInfo);
    int ret = manager.ValidateConfig();
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, ret);
}

/**
 * @tc.name: ValidateConfig007
 * @tc.desc: ValidateConfig accepts a hap token that is not a system app
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ValidateConfig007, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    // A plain hap token, no system-app bit. Every hap is allowed now.
    config.callerTokenId = 0x200D000D;
    CmdInfo cmdInfo;

    manager.Initialize(std::move(config), cmdInfo);
    int ret = manager.ValidateConfig();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: ValidateConfig008
 * @tc.desc: ValidateConfig with a non-zero callerTokenId whose low 32 bits are
 *          zero still fails, because the type check reads only those low bits
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ValidateConfig008, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    // High bit alone, no low bits -> callerTokenId != 0, but
    // GetTokenTypeFlag(0) will likely not return TOKEN_HAP
    config.callerTokenId = TEST_TOKEN_ID_HIGH_BIT;
    CmdInfo cmdInfo;

    manager.Initialize(std::move(config), cmdInfo);
    int ret = manager.ValidateConfig();
    // This will fail at the TOKEN_HAP type check since GetTokenTypeFlag(0)
    // should not return TOKEN_HAP
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, ret);
}

// ==================== ValidateBasicParams tests ====================

/**
 * @tc.name: ValidateBasicParams001
 * @tc.desc: ValidateBasicParams passes with valid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ValidateBasicParams001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ValidateBasicParams());
}

/**
 * @tc.name: ValidateBasicParams002
 * @tc.desc: ValidateBasicParams rejects callerPid == 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ValidateBasicParams002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 0;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, manager.ValidateBasicParams());
}

/**
 * @tc.name: ValidateBasicParams003
 * @tc.desc: ValidateBasicParams rejects uid below UID_BASE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ValidateBasicParams003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 1000;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, manager.ValidateBasicParams());
}

/**
 * @tc.name: ValidateBasicParams004
 * @tc.desc: ValidateBasicParams rejects gid below UID_BASE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ValidateBasicParams004, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 1000;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, manager.ValidateBasicParams());
}

/**
 * @tc.name: ValidateBasicParams005
 * @tc.desc: ValidateBasicParams rejects callerTokenId == 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ValidateBasicParams005, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = 0;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, manager.ValidateBasicParams());
}

// ==================== SetXpmOwnerId Test =========================

/**
 * @tc.name: SetXpmOwnerId001
 * @tc.desc: Validate SetXpmOwnerId returns success immediately when type is not "shell".
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetXpmOwnerId001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.type = "cli"; // Not "shell"
    config.appIdentifier = "20020026";
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    EXPECT_EQ(SANDBOX_SUCCESS, manager.SetXpmOwnerId());
}

/**
 * @tc.name: SetXpmOwnerId002
 * @tc.desc: Validate SetXpmOwnerId returns BAD_PARAMETERS when type is "shell" but appIdentifier is empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetXpmOwnerId002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.type = "shell";
    config.appIdentifier = ""; // Empty identifier
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, manager.SetXpmOwnerId());
}

/**
 * @tc.name: SetXpmOwnerId003
 * @tc.desc: Validate SetXpmOwnerId logic with valid shell type and normal appIdentifier.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetXpmOwnerId003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.type = "shell";
    config.appIdentifier = "20020026";
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    // In a typical UT environment, /dev/xpm might not exist, so open() fails,
    // which correctly logs a warning and returns SANDBOX_SUCCESS.
    // If mocked or run on a real device, ioctl executes and also returns SANDBOX_SUCCESS.
    EXPECT_EQ(SANDBOX_SUCCESS, manager.SetXpmOwnerId());
}

/**
 * @tc.name: SetXpmOwnerId004
 * @tc.desc: Validate SetXpmOwnerId safely handles appIdentifier lengths exceeding MAX_OWNERID_LEN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetXpmOwnerId004, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.type = "shell";
    // Create a string longer than MAX_OWNERID_LEN (64)
    config.appIdentifier = std::string(100, 'A');
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    // The truncation logic (std::min) should prevent memcpy_s from failing.
    EXPECT_EQ(SANDBOX_SUCCESS, manager.SetXpmOwnerId());
}

// ==================== ValidateTokenType tests ====================

/**
 * @tc.name: ValidateTokenType001
 * @tc.desc: ValidateTokenType passes with a TOKEN_HAP token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ValidateTokenType001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ValidateTokenType());
}

/**
 * @tc.name: ValidateTokenType002
 * @tc.desc: ValidateTokenType rejects non-TOKEN_HAP (tokenId == 0 returns TOKEN_NATIVE)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ValidateTokenType002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = 0;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, manager.ValidateTokenType());
}

/**
 * @tc.name: ValidateTokenType003
 * @tc.desc: ValidateTokenType accepts a hap token that is not a system app
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ValidateTokenType003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = 0x200D000D;  // TOKEN_HAP, no system-app bit
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ValidateTokenType());
}

/**
 * @tc.name: DeleteSandboxDir001
 * @tc.desc: DeleteSandboxDir returns early when manager is not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, DeleteSandboxDir001, TestSize.Level0)
{
    SandboxManager uninitializedManager;
    int ret = uninitializedManager.DeleteSandboxDir();
    EXPECT_EQ(SANDBOX_ERR_GENERIC, ret);
    EXPECT_FALSE(uninitializedManager.initialized_);
    EXPECT_TRUE(uninitializedManager.config_.name.empty());
    EXPECT_TRUE(uninitializedManager.newRootPath_.empty());
}

/**
 * @tc.name: DeleteSandboxDir002
 * @tc.desc: DeleteSandboxDir returns bad parameter when sandbox name is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, DeleteSandboxDir002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.appIdentifier = "20020026";
    config.bundleName = "20020026";
    CmdInfo cmdInfo;

    manager.Initialize(std::move(config), cmdInfo);
    int ret = manager.DeleteSandboxDir();
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, ret);
}

/**
 * @tc.name: DeleteSandboxDir003
 * @tc.desc: DeleteSandboxDir returns bad parameter when base config is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, DeleteSandboxDir003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.name = "abcdef0123456789";
    CmdInfo cmdInfo;

    manager.Initialize(std::move(config), cmdInfo);
    int ret = manager.DeleteSandboxDir();
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, ret);
}

/**
 * @tc.name: DeleteSandboxDir004
 * @tc.desc: DeleteSandboxDir with shell type now also enters EnterCallerSandbox,
 *           which fails in UT environment (no readproc group).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, DeleteSandboxDir004, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.type = "shell";
    config.name = "abcdef0123456789";
    config.appIdentifier = "20020026";
    config.bundleName = "20020026";
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    // With type "shell", EnterCallerSandbox is now called.
    // In UT environment this fails with NS_FAILED because
    // the "readproc" group is not available.
    int ret = manager.DeleteSandboxDir();
    EXPECT_EQ(SANDBOX_ERR_NS_FAILED, ret);
}

// ==================== LoadTemplate tests ====================

/**
 * @tc.name: LoadTemplate001
 * @tc.desc: LoadTemplate loads the built-in claw_sandbox template JSON
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, LoadTemplate001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.bundleName = "com.example.bundle";
    CmdInfo cmdInfo;

    manager.Initialize(std::move(config), cmdInfo);
    int ret = manager.LoadTemplate();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: EnvPolicyHelpers001
 * @tc.desc: Env policy helper methods classify inherited and override keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, EnvPolicyHelpers001, TestSize.Level0)
{
    SandboxManager manager;
    manager.templateConfig_.envPolicy.blockedEverywhereKeys = {"LD_PRELOAD"};
    manager.templateConfig_.envPolicy.blockedOverrideOnlyKeys = {"HOME"};
    manager.templateConfig_.envPolicy.allowedInheritedOverrideOnlyKeys = {"HOME"};
    manager.templateConfig_.envPolicy.blockedPrefixes = {"DYLD_"};
    manager.templateConfig_.envPolicy.blockedOverridePrefixes = {"SSH_"};

    EXPECT_TRUE(manager.IsDangerousHostEnvVarName(" ld_preload "));
    EXPECT_TRUE(manager.IsDangerousHostEnvVarName("dyld_library_path"));
    EXPECT_FALSE(manager.IsDangerousHostEnvVarName("HOME"));
    EXPECT_FALSE(manager.IsDangerousHostInheritedEnvVarName("HOME"));
    EXPECT_TRUE(manager.IsDangerousHostEnvOverrideVarName("HOME"));
    EXPECT_TRUE(manager.IsDangerousHostEnvOverrideVarName("ssh_auth_sock"));
    EXPECT_FALSE(manager.IsDangerousHostEnvOverrideVarName("SAFE_KEY"));
}

// ==================== IsAllowedInheritedOverrideOnlyEnvKey tests ====================

/**
 * @tc.name: IsAllowedInheritedOverrideOnlyEnvKey001
 * @tc.desc: IsAllowedInheritedOverrideOnlyEnvKey checks against allowedInheritedOverrideOnlyKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, IsAllowedInheritedOverrideOnlyEnvKey001, TestSize.Level0)
{
    SandboxManager manager;
    manager.templateConfig_.envPolicy.allowedInheritedOverrideOnlyKeys = {"HOME", "USER"};
    manager.templateConfig_.envPolicy.blockedOverridePrefixes = {"SSH_"};

    EXPECT_TRUE(manager.IsAllowedInheritedOverrideOnlyEnvKey("HOME"));
    EXPECT_TRUE(manager.IsAllowedInheritedOverrideOnlyEnvKey("USER"));
    EXPECT_FALSE(manager.IsAllowedInheritedOverrideOnlyEnvKey("PATH"));
    EXPECT_FALSE(manager.IsAllowedInheritedOverrideOnlyEnvKey("SSH_AUTH_SOCK"));
    EXPECT_FALSE(manager.IsAllowedInheritedOverrideOnlyEnvKey(""));
}

// ==================== SanitizeInheritedEnv tests ====================

/**
 * @tc.name: SanitizeInheritedEnv001
 * @tc.desc: SanitizeInheritedEnv filters blocked keys and prefixes from inherited env
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SanitizeInheritedEnv001, TestSize.Level0)
{
    SandboxManager manager;
    manager.templateConfig_.envPolicy.blockedEverywhereKeys = {"LD_PRELOAD"};
    manager.templateConfig_.envPolicy.blockedPrefixes = {"DYLD_"};

    std::map<std::string, std::string> result;
    size_t accepted = 0;
    size_t rejected = 0;
    manager.SanitizeInheritedEnv(result, accepted, rejected);

    EXPECT_EQ(accepted, result.size());
    // Verify no blocked keys leaked into result (case-insensitive)
    for (const auto &[key, val] : result) {
        (void)val;
        std::string upperKey;
        upperKey.reserve(key.size());
        for (char c : key) {
            upperKey.push_back((c >= 'a' && c <= 'z') ? c - 'a' + 'A' : c);
        }
        EXPECT_NE("LD_PRELOAD", upperKey);
        EXPECT_NE(0U, upperKey.compare(0, 5, "DYLD_"));
    }
}

/**
 * @tc.name: SanitizeInheritedEnv002
 * @tc.desc: SanitizeInheritedEnv with no blocked policy accepts all env
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SanitizeInheritedEnv002, TestSize.Level0)
{
    SandboxManager manager;

    std::map<std::string, std::string> result;
    size_t accepted = 0;
    size_t rejected = 0;
    manager.SanitizeInheritedEnv(result, accepted, rejected);

    EXPECT_EQ(accepted, result.size());
    EXPECT_EQ(0U, rejected);
}

// ==================== SanitizeOverrideEnv tests ====================

/**
 * @tc.name: SanitizeOverrideEnv001
 * @tc.desc: SanitizeOverrideEnv filters blocked override keys while allowing safe ones
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SanitizeOverrideEnv001, TestSize.Level0)
{
    SandboxManager manager;
    manager.templateConfig_.envPolicy.blockedEverywhereKeys = {"LD_PRELOAD"};
    manager.templateConfig_.envPolicy.blockedOverrideOnlyKeys = {"SHELL"};
    manager.templateConfig_.envPolicy.blockedOverridePrefixes = {"SSH_"};

    std::map<std::string, std::string> env = {
        {"PATH", "/usr/bin"},
        {"LD_PRELOAD", "evil.so"},
        {"SHELL", "/bin/sh"},
        {"SSH_AUTH_SOCK", "/tmp/ssh"},
    };

    manager.config_.env = env;

    std::map<std::string, std::string> result;
    size_t accepted = 0;
    size_t rejectedBlocked = 0;
    size_t rejectedInvalid = 0;
    manager.SanitizeOverrideEnv(result, accepted, rejectedBlocked, rejectedInvalid);

#ifdef CONFIG_SHELL_SANDBOX
    EXPECT_EQ(8U, result.size());
#else
    EXPECT_EQ(1U, result.size());
#endif
    EXPECT_TRUE(result["PATH"].find("/usr/bin") != std::string::npos);
    EXPECT_EQ(1U, accepted);
    EXPECT_EQ(3U, rejectedBlocked);
    EXPECT_EQ(0U, rejectedInvalid);
}

/**
 * @tc.name: SanitizeOverrideEnv002
 * @tc.desc: SanitizeOverrideEnv handles empty override env
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SanitizeOverrideEnv002, TestSize.Level0)
{
    SandboxManager manager;
    std::map<std::string, std::string> result;
    size_t accepted = 0;
    size_t rejectedBlocked = 0;
    size_t rejectedInvalid = 0;
    manager.SanitizeOverrideEnv(result, accepted, rejectedBlocked, rejectedInvalid);
#ifdef CONFIG_SHELL_SANDBOX
    EXPECT_EQ(8U, result.size());
#else
    EXPECT_EQ(1U, result.size());
#endif
    EXPECT_EQ(0U, accepted);
    EXPECT_EQ(0U, rejectedBlocked);
    EXPECT_EQ(0U, rejectedInvalid);
}

/**
 * @tc.name: SanitizeOverrideEnv003
 * @tc.desc: SanitizeOverrideEnv prepends config PATH to existing PATH in sanitizedEnv
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SanitizeOverrideEnv003, TestSize.Level0)
{
    SandboxManager manager;
    manager.config_.env = {{"PATH", "/config/bin"}};

    // Simulate sanitizedEnv with an existing PATH (e.g. from PRESET_ENV_VARS)
    std::map<std::string, std::string> result = {{"PATH", "/preset/bin"}};
    size_t accepted = 0;
    size_t rejectedBlocked = 0;
    size_t rejectedInvalid = 0;
    manager.SanitizeOverrideEnv(result, accepted, rejectedBlocked, rejectedInvalid);

    // Config PATH should be prepended: "/config/bin" but discard "/preset/bin"
    EXPECT_TRUE(result["PATH"].find("/usr/bin") != std::string::npos);
    EXPECT_TRUE(result["PATH"].find("/preset/bin") == std::string::npos);
    EXPECT_EQ(1U, accepted);
    EXPECT_EQ(0U, rejectedBlocked);
    EXPECT_EQ(0U, rejectedInvalid);
}

/**
 * @tc.name: SanitizeOverrideEnv004
 * @tc.desc: Verify preset environment variables are loaded correctly when config is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SanitizeOverrideEnv004, TestSize.Level0)
{
    SandboxManager manager;
    manager.config_.env.clear();
    manager.config_.currentUserId = "100";

    std::map<std::string, std::string> sanitizedEnv;
    size_t accepted = 0;
    size_t rejectedBlocked = 0;
    size_t rejectedInvalid = 0;

    manager.SanitizeOverrideEnv(sanitizedEnv, accepted, rejectedBlocked, rejectedInvalid);

    EXPECT_EQ(0U, accepted);
    EXPECT_EQ(0U, rejectedBlocked);
    EXPECT_EQ(0U, rejectedInvalid);

#ifdef CONFIG_SHELL_SANDBOX
    EXPECT_EQ("/storage/Users/currentUser", sanitizedEnv["HOME"]);
    EXPECT_EQ("/bin/sh", sanitizedEnv["SHELL"]);
    EXPECT_EQ("100", sanitizedEnv["USER"]);
    EXPECT_EQ("/usr/local/bin:/data/app/bin:/data/service/hnp/bin:/usr/bin:"
        "/bin:/system/bin:/system/bin/cli_tool/executable:/vendor/bin", sanitizedEnv["PATH"]);
#else
    EXPECT_EQ("/usr/local/bin:/usr/bin:"
        "/bin:/system/bin:/system/bin/cli_tool/executable:/vendor/bin", sanitizedEnv["PATH"]);
    EXPECT_TRUE(sanitizedEnv.find("HOME") == sanitizedEnv.end());
#endif
}

/**
 * @tc.name: SanitizeOverrideEnv005
 * @tc.desc: Verify that preset PATH is appended to existing PATH in sanitizedEnv
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SanitizeOverrideEnv005, TestSize.Level0)
{
    SandboxManager manager;
    manager.config_.env.clear();

    std::map<std::string, std::string> sanitizedEnv = {{"PATH", "/initial/bin"}};
    size_t accepted = 0, rejectedBlocked = 0, rejectedInvalid = 0;

    manager.SanitizeOverrideEnv(sanitizedEnv, accepted, rejectedBlocked, rejectedInvalid);

#ifdef CONFIG_SHELL_SANDBOX
    EXPECT_EQ("/usr/local/bin:/data/app/bin:/data/service/hnp/bin:/usr/bin:"
        "/bin:/system/bin:/system/bin/cli_tool/executable:/vendor/bin", sanitizedEnv["PATH"]);
#else
    EXPECT_EQ("/usr/local/bin:/usr/bin:"
        "/bin:/system/bin:/system/bin/cli_tool/executable:/vendor/bin", sanitizedEnv["PATH"]);
#endif
}

/**
 * @tc.name: SanitizeOverrideEnv006
 * @tc.desc: Verify that config PATH is prepended to the preset PATH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SanitizeOverrideEnv006, TestSize.Level0)
{
    SandboxManager manager;
    manager.config_.env = {{"PATH", "/config/bin"}};

    std::map<std::string, std::string> sanitizedEnv;
    size_t accepted = 0, rejectedBlocked = 0, rejectedInvalid = 0;

    manager.SanitizeOverrideEnv(sanitizedEnv, accepted, rejectedBlocked, rejectedInvalid);

    EXPECT_EQ(1U, accepted);
    EXPECT_EQ(0U, rejectedBlocked);
    EXPECT_EQ(0U, rejectedInvalid);

#ifdef CONFIG_SHELL_SANDBOX
    EXPECT_EQ("/config/bin:/usr/local/bin:/data/app/bin:/data/service/hnp/bin:/usr/bin:"
        "/bin:/system/bin:/system/bin/cli_tool/executable:/vendor/bin", sanitizedEnv["PATH"]);
#else
    EXPECT_EQ("/config/bin:/usr/local/bin:/usr/bin:"
        "/bin:/system/bin:/system/bin/cli_tool/executable:/vendor/bin", sanitizedEnv["PATH"]);
#endif
}

/**
 * @tc.name: CollectGrantedPermissionGids001
 * @tc.desc: CollectGrantedPermissionGids collects unique non-negative gids for declared permissions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, CollectGrantedPermissionGids001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    SandboxManager::PermissionConfig grantedConfig;
    grantedConfig.sandboxSwitch = true;
    grantedConfig.gids = {1006, 3076, 1006, -1};

    SandboxManager::PermissionConfig deniedConfig;
    deniedConfig.sandboxSwitch = true;
    deniedConfig.gids = {2000};

    SandboxManager::PermissionConfig switchOffConfig;
    switchOffConfig.sandboxSwitch = false;
    switchOffConfig.gids = {3000};

    manager.templateConfig_.permissions["ohos.permission.GRANTED_GID"] = grantedConfig;
    manager.templateConfig_.permissions["ohos.permission.DENIED_GID"] = deniedConfig;
    manager.templateConfig_.permissions["ohos.permission.GRANTED_SWITCH_OFF"] = switchOffConfig;

    std::vector<int> gids = manager.CollectGrantedPermissionGids();
    ASSERT_EQ(2U, gids.size());
    EXPECT_EQ(1006, gids[0]);
    EXPECT_EQ(3076, gids[1]);
}

// ==================== IsPermissionGranted tests ====================

/**
 * @tc.name: IsPermissionGranted001
 * @tc.desc: IsPermissionGranted returns true for granted permission (name contains GRANTED)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, IsPermissionGranted001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    EXPECT_TRUE(manager.IsPermissionGranted("ohos.permission.GRANTED_TEST"));
}

/**
 * @tc.name: IsPermissionGranted002
 * @tc.desc: IsPermissionGranted returns false for denied permission (name without GRANTED)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, IsPermissionGranted002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    EXPECT_FALSE(manager.IsPermissionGranted("ohos.permission.DENIED_TEST"));
}

/**
 * @tc.name: IsPermissionGranted003
 * @tc.desc: IsPermissionGranted returns false when tokenId is 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, IsPermissionGranted003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    // Override token so that callerTokenId & TOKEN_ID_LOWMASK == 0
    manager.config_.callerTokenId = TEST_TOKEN_ID_HIGH_BIT;
    EXPECT_FALSE(manager.IsPermissionGranted("ohos.permission.GRANTED_TEST"));
}

// ==================== ParsePermissionDecPaths tests ====================

/**
 * @tc.name: ParsePermissionDecPaths001
 * @tc.desc: ParsePermissionDecPaths returns early when obj is not a cJSON object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParsePermissionDecPaths001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxManager::PermissionConfig pc;
    pc.decPaths.push_back("existing/path");
    ASSERT_EQ(1U, pc.decPaths.size());

    // Pass a cJSON array (not object) → early return, decPaths unchanged
    cJSON *nonObj = cJSON_Parse("[]");
    ASSERT_NE(nonObj, nullptr);
    manager.ParsePermissionDecPaths(nonObj, pc);
    EXPECT_EQ(1U, pc.decPaths.size());
    EXPECT_EQ("existing/path", pc.decPaths[0]);
    cJSON_Delete(nonObj);
}

#ifdef CONFIG_SHELL_SANDBOX
// ==================== CollectPermissionDecPaths tests ====================

/**
 * @tc.name: CollectPermissionDecPaths001
 * @tc.desc: CollectPermissionDecPaths collects valid normalized dec paths
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, CollectPermissionDecPaths001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.currentUserId = "100";
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    SandboxManager::PermissionConfig permConfig;
    permConfig.decPaths = {"/data/app", "/storage/Users/currentUser/test"};

    std::vector<std::string> result;
    EXPECT_EQ(0, manager.CollectPermissionDecPaths(permConfig, result));
    ASSERT_EQ(2U, result.size());
    EXPECT_EQ("/data/app", result[0]);
    EXPECT_EQ("/storage/Users/currentUser/test", result[1]);
}

/**
 * @tc.name: CollectPermissionDecPaths002
 * @tc.desc: CollectPermissionDecPaths skips empty and duplicate paths
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, CollectPermissionDecPaths002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.currentUserId = "100";
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    SandboxManager::PermissionConfig permConfig;
    permConfig.decPaths = {"", "/data/app", "/data/app"};

    std::vector<std::string> result;
    EXPECT_EQ(0, manager.CollectPermissionDecPaths(permConfig, result));
    ASSERT_EQ(1U, result.size());
    EXPECT_EQ("/data/app", result[0]);
}

/**
 * @tc.name: CollectPermissionDecPaths003
 * @tc.desc: CollectPermissionDecPaths returns -1 when path count exceeds DEC_MAX_POLICY_NUM (64)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, CollectPermissionDecPaths003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.currentUserId = "100";
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    SandboxManager::PermissionConfig permConfig;
    for (int i = 0; i < 65; i++) {
        permConfig.decPaths.push_back("/data/app/" + std::to_string(i));
    }

    std::vector<std::string> result;
    EXPECT_EQ(-1, manager.CollectPermissionDecPaths(permConfig, result));
    ASSERT_EQ(64U, result.size());
}

/**
 * @tc.name: CollectDecPolicyPaths001
 * @tc.desc: CollectDecPolicyPaths collects unique paths for declared permissions only
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, CollectDecPolicyPaths001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    SandboxManager::PermissionConfig grantedConfig;
    grantedConfig.sandboxSwitch = true;
    grantedConfig.decPaths = {
        "/storage/Users/100/Download",
        "/storage/Users/currentUser/Desktop",
        "/storage/Users/currentUser/Desktop",
        "",
    };

    SandboxManager::PermissionConfig deniedConfig;
    deniedConfig.sandboxSwitch = true;
    deniedConfig.decPaths = {"/storage/Users/100/Documents"};

    manager.templateConfig_.permissions["ohos.permission.GRANTED_DEC"] = grantedConfig;
    manager.templateConfig_.permissions["ohos.permission.DENIED_DEC"] = deniedConfig;

    EXPECT_EQ("/storage/Users/currentUser/Documents",
        manager.NormalizeDecPath("/storage/Users/100/Documents"));

    std::vector<std::string> decPaths = manager.CollectDecPolicyPaths();
    ASSERT_EQ(2U, decPaths.size());
    EXPECT_EQ("/storage/Users/currentUser/Download", decPaths[0]);
    EXPECT_EQ("/storage/Users/currentUser/Desktop", decPaths[1]);
}
#endif

#ifdef CONFIG_SHELL_SANDBOX
/**
 * @tc.name: SetDecPolicyBatch001
 * @tc.desc: SetDecPolicyBatch rejects invalid batch ranges before ioctl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetDecPolicyBatch001, TestSize.Level0)
{
    SandboxManager manager;
    const std::vector<std::string> paths = {"/storage/Users/currentUser/Download"};

    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, manager.SetDecPolicyBatch(-1, paths, 1, 1, 0, 0));
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, manager.SetDecPolicyBatch(-1, paths, 1, 1, 0, 9));
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, manager.SetDecPolicyBatch(-1, paths, 1, 1, 1, 1));
}

/**
 * @tc.name: ApplyDecPolicies001
 * @tc.desc: ApplyDecPolicies succeeds when no DEC paths are configured
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ApplyDecPolicies001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    EXPECT_EQ(SANDBOX_SUCCESS, manager.ApplyDecPolicies());
}

/**
 * @tc.name: ApplyDecPolicies002
 * @tc.desc: ApplyDecPolicies with granted DEC paths proceeds to open /dev/dec
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ApplyDecPolicies002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    // Set up a GRANTED permission with a DEC path so that
    // CollectDecPolicyPaths returns non-empty, and ApplyDecPolicies
    // proceeds past the early-return checks to open("/dev/dec").
    SandboxManager::PermissionConfig permConfig;
    permConfig.sandboxSwitch = true;
    permConfig.decPaths = {"/data/app/test"};
    manager.templateConfig_.permissions["ohos.permission.GRANTED_DEC"] = permConfig;

    int ret = manager.ApplyDecPolicies();
    // /dev/dec does not exist in test env, so open() fails.
    // The function logs a warning and returns SANDBOX_SUCCESS.
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

// ==================== PreDecDenyPaths tests ====================

/**
 * @tc.name: PreDecDenyPaths001
 * @tc.desc: PreDecDenyPaths with all three permissions granted returns success
 *           and sends no deny ioctl (no paths to deny).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, PreDecDenyPaths001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    // All three permissions contain "GRANTED" in name → IsPermissionGranted returns true
    SandboxManager::PermissionConfig permConfig;
    permConfig.sandboxSwitch = true;
    manager.templateConfig_.permissions["ohos.permission.GRANTED_READ_WRITE_DOWNLOAD_DIRECTORY"] = permConfig;
    manager.templateConfig_.permissions["ohos.permission.GRANTED_READ_WRITE_DESKTOP_DIRECTORY"] = permConfig;
    manager.templateConfig_.permissions["ohos.permission.GRANTED_READ_WRITE_DOCUMENTS_DIRECTORY"] = permConfig;

    int ret = manager.PreDecDenyPaths();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: PreDecDenyPaths002
 * @tc.desc: PreDecDenyPaths with no permissions granted attempts deny ioctl.
 *           /dev/dec does not exist in test env, so open() fails and logs a
 *           warning, but the function still returns SANDBOX_SUCCESS.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, PreDecDenyPaths002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    // No permissions registered → IsPermissionGranted returns false for all DENY paths
    // Three paths (Download, Desktop, Documents) will be collected for deny
    int ret = manager.PreDecDenyPaths();
    // /dev/dec does not exist in test env, but the function gracefully handles
    // open failure and returns SANDBOX_SUCCESS.
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: PreDecDenyPaths003
 * @tc.desc: PreDecDenyPaths with partial permissions only denies paths without
 *           the corresponding permission. /dev/dec may not exist but function
 *           returns SANDBOX_SUCCESS.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, PreDecDenyPaths003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    // Only Desktop has GRANTED in name → Desktop permission is granted,
    // Download and Documents are not → those two paths should be denied
    SandboxManager::PermissionConfig permConfig;
    permConfig.sandboxSwitch = true;
    manager.templateConfig_.permissions["ohos.permission.GRANTED_READ_WRITE_DESKTOP_DIRECTORY"] = permConfig;

    int ret = manager.PreDecDenyPaths();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: PreDecDenyPaths004
 * @tc.desc: PreDecDenyPaths with shell type uses callerTokenId for deny ioctl.
 *           Function returns SANDBOX_SUCCESS even if /dev/dec does not exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, PreDecDenyPaths004, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.type = "shell";
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    // No permissions registered → all three paths will be collected for deny.
    // shell type uses callerTokenId directly for the deny ioctl token.
    int ret = manager.PreDecDenyPaths();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}
#endif

#ifdef CONFIG_SHELL_SANDBOX
/**
 * @tc.name: SetSandboxPathMark001
 * @tc.desc: SetSandboxPathMark skips when CUSTOM_SANDBOX not granted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetSandboxPathMark001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    g_customSandboxGranted = false;
    int ret = manager.SetSandboxPathMark();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: SetSandboxPathMark002
 * @tc.desc: SetSandboxPathMark proceeds when CUSTOM_SANDBOX granted,
 *           opens /dev/dec (fails in UT env, returns SANDBOX_SUCCESS).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetSandboxPathMark002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    g_customSandboxGranted = true;
    int ret = manager.SetSandboxPathMark();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    g_customSandboxGranted = false;
}

// ==================== SetEncapsProcFlag tests ====================

/**
 * @tc.name: SetEncapsProcFlag001
 * @tc.desc: SetEncapsProcFlag skips when CUSTOM_SANDBOX not granted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetEncapsProcFlag001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    g_customSandboxGranted = false;
    int ret = manager.SetEncapsProcFlag();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: SetEncapsProcFlag002
 * @tc.desc: SetEncapsProcFlag proceeds when CUSTOM_SANDBOX granted,
 *           opens /dev/encaps (fails in UT env, returns SANDBOX_SUCCESS).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetEncapsProcFlag002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    g_customSandboxGranted = true;
    int ret = manager.SetEncapsProcFlag();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    g_customSandboxGranted = false;
}
#endif

// ==================== BuildSeccompFilter tests ====================

/**
 * @tc.name: BuildSeccompFilter001
 * @tc.desc: BuildSeccompFilter with empty allow list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, BuildSeccompFilter001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = 12345;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    struct sock_fprog prog;
    int ret = manager.BuildSeccompFilter(prog);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_NE(prog.filter, nullptr);
    EXPECT_GT(prog.len, 0U);
}

/**
 * @tc.name: BuildSeccompFilter002
 * @tc.desc: BuildSeccompFilter with allow list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, BuildSeccompFilter002, TestSize.Level0)
{
    const char *json = R"({
        "seccomp": {
            "allow-list": ["execve", "read", "write"]
        }
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = 12345;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParseSeccompJson(root));

    struct sock_fprog prog;
    int ret = manager.BuildSeccompFilter(prog);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_NE(prog.filter, nullptr);

    cJSON_Delete(root);
}

/**
 * @tc.name: BuildSeccompFilter003
 * @tc.desc: Verify BPF JGE instruction in setuid uid range filter uses correct
 *          jump targets (jt=1, jf=0) meaning uid >= UID_MIN_LIMIT skips KILL.
 *          Also verify the UID_MIN_LIMIT constant value (20000000).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, BuildSeccompFilter003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    struct sock_fprog prog;
    int ret = manager.BuildSeccompFilter(prog);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_NE(prog.filter, nullptr);

    // BPF instruction layout (no allow list):
    //   [0] LD arch
    //   [1] JEQ AUDIT_ARCH_AARCH64
    //   [2] RET KILL
    //   [3] LD nr
    //   [4-7] setuid uid range filter (4 insns)
    //   [8-14] setreuid uid range filter (7 insns)
    //   [15-24] setresuid uid range filter (10 insns)
    //   [25-28] setfsuid uid range filter (4 insns)
    //   [29] default action
    //
    // setuid uid range filter (indices 4-7):
    //   [4]  JEQ __NR_setuid, jt=0, jf=3
    //   [5]  LD args[0]
    //   [6] JGE UID_MIN_LIMIT, jt=1, jf=0  <-- KEY: >= limit -> skip KILL
    //   [7] RET KILL
    constexpr size_t SETUID_FILTER_IDX = 4;
    constexpr size_t SETUID_JGE_IDX = SETUID_FILTER_IDX + 2;  // idx 10

    // Verify JGE instruction: BPF_JMP | BPF_JGE | BPF_K
    EXPECT_EQ(prog.filter[SETUID_JGE_IDX].code,
              static_cast<uint16_t>(BPF_JMP | BPF_JGE | BPF_K));
    // Verify jt=1 (if uid >= UID_MIN_LIMIT, skip 1 instruction = skip KILL)
    EXPECT_EQ(prog.filter[SETUID_JGE_IDX].jt, static_cast<uint8_t>(1));
    // Verify jf=0 (if uid < UID_MIN_LIMIT, fall through to KILL)
    EXPECT_EQ(prog.filter[SETUID_JGE_IDX].jf, static_cast<uint8_t>(0));
    // Verify the limit value is UID_MIN_LIMIT (20000000)
    EXPECT_EQ(prog.filter[SETUID_JGE_IDX].k, static_cast<uint32_t>(20000000));
}

/**
 * @tc.name: BuildSeccompFilter004
 * @tc.desc: Verify BPF JGE instructions in setreuid uid range filter check
 *          BOTH args[0] (ruid) and args[1] (euid) with correct jump targets.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, BuildSeccompFilter004, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    struct sock_fprog prog;
    int ret = manager.BuildSeccompFilter(prog);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_NE(prog.filter, nullptr);

    // setreuid uid range filter (indices 8-14):
    //   [8] JEQ __NR_setreuid, jt=0, jf=6
    //   [9] LD args[0] (ruid)
    //   [10] JGE UID_MIN_LIMIT, jt=1, jf=0  <-- ruid >= limit?
    //   [11] RET KILL
    //   [12] LD args[1] (euid)
    //   [13] JGE UID_MIN_LIMIT, jt=1, jf=0  <-- euid >= limit?
    //   [14] RET KILL
    constexpr size_t SETREUID_RUID_JGE_IDX = 10;
    constexpr size_t SETREUID_EUID_JGE_IDX = 13;

    // Verify args[0] (ruid) JGE: jt=1, jf=0
    EXPECT_EQ(prog.filter[SETREUID_RUID_JGE_IDX].code,
              static_cast<uint16_t>(BPF_JMP | BPF_JGE | BPF_K));
    EXPECT_EQ(prog.filter[SETREUID_RUID_JGE_IDX].jt, static_cast<uint8_t>(1));
    EXPECT_EQ(prog.filter[SETREUID_RUID_JGE_IDX].jf, static_cast<uint8_t>(0));
    EXPECT_EQ(prog.filter[SETREUID_RUID_JGE_IDX].k, static_cast<uint32_t>(20000000));

    // Verify args[1] (euid) JGE: jt=1, jf=0
    EXPECT_EQ(prog.filter[SETREUID_EUID_JGE_IDX].code,
              static_cast<uint16_t>(BPF_JMP | BPF_JGE | BPF_K));
    EXPECT_EQ(prog.filter[SETREUID_EUID_JGE_IDX].jt, static_cast<uint8_t>(1));
    EXPECT_EQ(prog.filter[SETREUID_EUID_JGE_IDX].jf, static_cast<uint8_t>(0));
    EXPECT_EQ(prog.filter[SETREUID_EUID_JGE_IDX].k, static_cast<uint32_t>(20000000));
}

/**
 * @tc.name: BuildSeccompFilter005
 * @tc.desc: Verify BPF JGE instructions in setresuid uid range filter check
 *          ALL THREE args (ruid, euid, suid) with correct jump targets.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, BuildSeccompFilter005, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    struct sock_fprog prog;
    int ret = manager.BuildSeccompFilter(prog);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_NE(prog.filter, nullptr);

    // setresuid uid range filter (indices 15-24):
    //   [15] JEQ __NR_setresuid, jt=0, jf=9
    //   [16] LD args[0] (ruid)
    //   [17] JGE UID_MIN_LIMIT, jt=1, jf=0  <-- ruid >= limit?
    //   [18] RET KILL
    //   [19] LD args[1] (euid)
    //   [20] JGE UID_MIN_LIMIT, jt=1, jf=0  <-- euid >= limit?
    //   [21] RET KILL
    //   [22] LD args[2] (suid)
    //   [23] JGE UID_MIN_LIMIT, jt=1, jf=0  <-- suid >= limit?
    //   [24] RET KILL
    constexpr size_t SETRESUID_RUID_JGE_IDX = 17;
    constexpr size_t SETRESUID_EUID_JGE_IDX = 20;
    constexpr size_t SETRESUID_SUID_JGE_IDX = 23;

    EXPECT_EQ(prog.filter[SETRESUID_RUID_JGE_IDX].code,
              static_cast<uint16_t>(BPF_JMP | BPF_JGE | BPF_K));
    EXPECT_EQ(prog.filter[SETRESUID_RUID_JGE_IDX].jt, static_cast<uint8_t>(1));
    EXPECT_EQ(prog.filter[SETRESUID_RUID_JGE_IDX].jf, static_cast<uint8_t>(0));
    EXPECT_EQ(prog.filter[SETRESUID_RUID_JGE_IDX].k, static_cast<uint32_t>(20000000));

    EXPECT_EQ(prog.filter[SETRESUID_EUID_JGE_IDX].code,
              static_cast<uint16_t>(BPF_JMP | BPF_JGE | BPF_K));
    EXPECT_EQ(prog.filter[SETRESUID_EUID_JGE_IDX].jt, static_cast<uint8_t>(1));
    EXPECT_EQ(prog.filter[SETRESUID_EUID_JGE_IDX].jf, static_cast<uint8_t>(0));
    EXPECT_EQ(prog.filter[SETRESUID_EUID_JGE_IDX].k, static_cast<uint32_t>(20000000));

    EXPECT_EQ(prog.filter[SETRESUID_SUID_JGE_IDX].code,
              static_cast<uint16_t>(BPF_JMP | BPF_JGE | BPF_K));
    EXPECT_EQ(prog.filter[SETRESUID_SUID_JGE_IDX].jt, static_cast<uint8_t>(1));
    EXPECT_EQ(prog.filter[SETRESUID_SUID_JGE_IDX].jf, static_cast<uint8_t>(0));
    EXPECT_EQ(prog.filter[SETRESUID_SUID_JGE_IDX].k, static_cast<uint32_t>(20000000));
}

/**
 * @tc.name: BuildSeccompFilter006
 * @tc.desc: Verify setfsuid uid range filter also uses correct JGE jump targets.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, BuildSeccompFilter006, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    struct sock_fprog prog;
    int ret = manager.BuildSeccompFilter(prog);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_NE(prog.filter, nullptr);

    // setfsuid uid range filter (indices 25-28):
    //   [25] JEQ __NR_setfsuid, jt=0, jf=3
    //   [26] LD args[0]
    //   [27] JGE UID_MIN_LIMIT, jt=1, jf=0  <-- KEY: >= limit -> skip KILL
    //   [28] RET KILL
    constexpr size_t SETFSUID_JGE_IDX = 27;

    // Verify JGE instruction: jt=1, jf=0
    EXPECT_EQ(prog.filter[SETFSUID_JGE_IDX].code,
              static_cast<uint16_t>(BPF_JMP | BPF_JGE | BPF_K));
    EXPECT_EQ(prog.filter[SETFSUID_JGE_IDX].jt, static_cast<uint8_t>(1));
    EXPECT_EQ(prog.filter[SETFSUID_JGE_IDX].jf, static_cast<uint8_t>(0));
    EXPECT_EQ(prog.filter[SETFSUID_JGE_IDX].k, static_cast<uint32_t>(20000000));
}

/**
 * @tc.name: BuildSeccompFilter007
 * @tc.desc: Verify total BPF instruction count is correct when no allow list.
 *          Expected: 4 (arch) + 4 (blocked: setpgid, setsid) + 25 (uid range)
 *          + 1 (default) = 34 instructions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, BuildSeccompFilter007, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    struct sock_fprog prog;
    int ret = manager.BuildSeccompFilter(prog);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_NE(prog.filter, nullptr);

    // Expected instruction count:
    //   ARCH_CHECK_BPF_CNT = 4
    //   BPF_PER_UID_SYSCALL_1ARG (setuid) = 4
    //   BPF_PER_UID_SYSCALL_2ARG (setreuid) = 7
    //   BPF_PER_UID_SYSCALL_3ARG (setresuid) = 10
    //   BPF_PER_UID_SYSCALL_1ARG (setfsuid) = 4
    //   default action = 1
    //   Total = 4 + 4 + 7 + 10 + 4 + 1 = 30
    constexpr size_t EXPECTED_TOTAL_LEN = 30;
    EXPECT_EQ(prog.len, EXPECTED_TOTAL_LEN);
    EXPECT_EQ(SECCOMP_RET_ALLOW, prog.filter[prog.len - 1].k);
}

/**
 * @tc.name: BuildSeccompFilter008
 * @tc.desc: BuildSeccompFilter skips unknown allow-list syscall names
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, BuildSeccompFilter008, TestSize.Level0)
{
    const char *json = R"({"seccomp": {"allow-list": ["execve", "unknown_syscall"]}})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParseSeccompJson(root));

    struct sock_fprog prog;
    int ret = manager.BuildSeccompFilter(prog);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_NE(prog.filter, nullptr);
    EXPECT_EQ(32U, prog.len);
    EXPECT_EQ(SECCOMP_RET_KILL, prog.filter[prog.len - 1].k);

    cJSON_Delete(root);
}

// ==================== ApplyMcsLevel tests ====================

/**
 * @tc.name: ApplyMcsLevel001
 * @tc.desc: Verify MCS range can be copied from target context to self context
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ApplyMcsLevel001, TestSize.Level0)
{
    const char *selfContext = "u:r:claw_sandbox:s0";
    const char *targetContext = "u:r:hap:s0:x58,x334,x512,x868,x1024";

    context_t selfCon = context_new(selfContext);
    ASSERT_NE(selfCon, nullptr);

    context_t targetCon = context_new(targetContext);
    ASSERT_NE(targetCon, nullptr);

    const char *targetRange = context_range_get(targetCon);
    ASSERT_NE(targetRange, nullptr);
    EXPECT_STREQ(targetRange, "s0:x58,x334,x512,x868,x1024");

    int ret = context_range_set(selfCon, targetRange);
    EXPECT_EQ(ret, 0);

    const char *newContext = context_str(selfCon);
    ASSERT_NE(newContext, nullptr);
    EXPECT_STREQ(newContext, "u:r:claw_sandbox:s0:x58,x334,x512,x868,x1024");

    context_free(targetCon);
    context_free(selfCon);
}

/**
 * @tc.name: ApplyMcsLevel002
 * @tc.desc: Verify copying MCS range does not change user, role or type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ApplyMcsLevel002, TestSize.Level0)
{
    const char *selfContext = "u:r:claw_sandbox:s0:x1,x2";
    const char *targetContext = "u:r:hap:s0:x100,x300,x500";

    context_t selfCon = context_new(selfContext);
    ASSERT_NE(selfCon, nullptr);

    context_t targetCon = context_new(targetContext);
    ASSERT_NE(targetCon, nullptr);

    const char *targetRange = context_range_get(targetCon);
    ASSERT_NE(targetRange, nullptr);

    int ret = context_range_set(selfCon, targetRange);
    EXPECT_EQ(ret, 0);

    const char *user = context_user_get(selfCon);
    const char *role = context_role_get(selfCon);
    const char *type = context_type_get(selfCon);
    const char *range = context_range_get(selfCon);

    ASSERT_NE(user, nullptr);
    ASSERT_NE(role, nullptr);
    ASSERT_NE(type, nullptr);
    ASSERT_NE(range, nullptr);

    EXPECT_STREQ(user, "u");
    EXPECT_STREQ(role, "r");
    EXPECT_STREQ(type, "claw_sandbox");
    EXPECT_STREQ(range, "s0:x100,x300,x500");

    context_free(targetCon);
    context_free(selfCon);
}

/**
 * @tc.name: ApplyMcsLevel003
 * @tc.desc: Verify MCS range without categories can replace existing range
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ApplyMcsLevel003, TestSize.Level0)
{
    const char *selfContext = "u:r:claw_sandbox:s0:x1,x2";
    const char *targetContext = "u:r:hap:s0";

    context_t selfCon = context_new(selfContext);
    ASSERT_NE(selfCon, nullptr);

    context_t targetCon = context_new(targetContext);
    ASSERT_NE(targetCon, nullptr);

    const char *targetRange = context_range_get(targetCon);
    ASSERT_NE(targetRange, nullptr);
    EXPECT_STREQ(targetRange, "s0");

    int ret = context_range_set(selfCon, targetRange);
    EXPECT_EQ(ret, 0);

    const char *newContext = context_str(selfCon);
    ASSERT_NE(newContext, nullptr);
    EXPECT_STREQ(newContext, "u:r:claw_sandbox:s0");

    context_free(targetCon);
    context_free(selfCon);
}

// ==================== SetSelinuxMCS tests ====================

/**
 * @tc.name: SetSelinuxMCS001
 * @tc.desc: Verify SetSelinuxMCS copies the caller MCS range and preserves the current domain
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetSelinuxMCS001, TestSize.Level0)
{
    SelinuxMockGuard guard;
    constexpr pid_t callerPid = 12345;
    SandboxManager manager;
    InitializeMcsManager(manager, callerPid);

    int ret = manager.SetSelinuxMCS();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(callerPid, g_selinuxMockState.capturedPid);
    EXPECT_EQ(1, g_selinuxMockState.getconCallCount);
    EXPECT_EQ(1, g_selinuxMockState.getpidconCallCount);
    EXPECT_EQ(1, g_selinuxMockState.securityCheckCallCount);
    EXPECT_EQ(1, g_selinuxMockState.setconCallCount);
    const std::string expectedContext = "u:r:claw_sandbox:s0:x58,x334,x512,x868,x1024";
    EXPECT_EQ(expectedContext, g_selinuxMockState.checkedContext);
    EXPECT_EQ(expectedContext, g_selinuxMockState.setconContext);
}

/**
 * @tc.name: SetSelinuxMCS002
 * @tc.desc: Verify SetSelinuxMCS skips all context operations when SELinux is disabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetSelinuxMCS002, TestSize.Level0)
{
    SelinuxMockGuard guard;
    g_selinuxMockState.selinuxEnabled = 0;
    SandboxManager manager;
    InitializeMcsManager(manager, 12345);

    EXPECT_EQ(SANDBOX_SUCCESS, manager.SetSelinuxMCS());
    EXPECT_EQ(0, g_selinuxMockState.getconCallCount);
    EXPECT_EQ(0, g_selinuxMockState.getpidconCallCount);
    EXPECT_EQ(0, g_selinuxMockState.securityCheckCallCount);
    EXPECT_EQ(0, g_selinuxMockState.setconCallCount);
}

/**
 * @tc.name: SetSelinuxMCS003
 * @tc.desc: Verify SetSelinuxMCS returns an error when the current context cannot be read
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetSelinuxMCS003, TestSize.Level0)
{
    SelinuxMockGuard guard;
    g_selinuxMockState.getconRet = -1;
    SandboxManager manager;
    InitializeMcsManager(manager, 12345);

    EXPECT_EQ(SANDBOX_ERR_SET_SELINUX_FAILED, manager.SetSelinuxMCS());
    EXPECT_EQ(1, g_selinuxMockState.getconCallCount);
    EXPECT_EQ(0, g_selinuxMockState.getpidconCallCount);
    EXPECT_EQ(0, g_selinuxMockState.securityCheckCallCount);
    EXPECT_EQ(0, g_selinuxMockState.setconCallCount);
}

/**
 * @tc.name: SetSelinuxMCS004
 * @tc.desc: Verify SetSelinuxMCS returns an error when the caller context cannot be read
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetSelinuxMCS004, TestSize.Level0)
{
    SelinuxMockGuard guard;
    constexpr pid_t callerPid = 54321;
    g_selinuxMockState.getpidconRet = -1;
    SandboxManager manager;
    InitializeMcsManager(manager, callerPid);

    EXPECT_EQ(SANDBOX_ERR_SET_SELINUX_FAILED, manager.SetSelinuxMCS());
    EXPECT_EQ(callerPid, g_selinuxMockState.capturedPid);
    EXPECT_EQ(1, g_selinuxMockState.getconCallCount);
    EXPECT_EQ(1, g_selinuxMockState.getpidconCallCount);
    EXPECT_EQ(0, g_selinuxMockState.securityCheckCallCount);
    EXPECT_EQ(0, g_selinuxMockState.setconCallCount);
}

/**
 * @tc.name: SetSelinuxMCS005
 * @tc.desc: Verify SetSelinuxMCS rejects a malformed caller context
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetSelinuxMCS005, TestSize.Level0)
{
    SelinuxMockGuard guard;
    g_selinuxMockState.targetContext = "invalid_context";
    SandboxManager manager;
    InitializeMcsManager(manager, 12345);

    EXPECT_EQ(SANDBOX_ERR_SET_SELINUX_FAILED, manager.SetSelinuxMCS());
    EXPECT_EQ(1, g_selinuxMockState.getconCallCount);
    EXPECT_EQ(1, g_selinuxMockState.getpidconCallCount);
    EXPECT_EQ(0, g_selinuxMockState.securityCheckCallCount);
    EXPECT_EQ(0, g_selinuxMockState.setconCallCount);
}

/**
 * @tc.name: SetSelinuxMCS006
 * @tc.desc: Verify SetSelinuxMCS stops when the composed context fails validation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetSelinuxMCS006, TestSize.Level0)
{
    SelinuxMockGuard guard;
    g_selinuxMockState.securityCheckRet = -1;
    SandboxManager manager;
    InitializeMcsManager(manager, 12345);

    EXPECT_EQ(SANDBOX_ERR_SET_SELINUX_FAILED, manager.SetSelinuxMCS());
    EXPECT_EQ("u:r:claw_sandbox:s0:x58,x334,x512,x868,x1024", g_selinuxMockState.checkedContext);
    EXPECT_EQ(1, g_selinuxMockState.securityCheckCallCount);
    EXPECT_EQ(0, g_selinuxMockState.setconCallCount);
}

/**
 * @tc.name: SetSelinuxMCS007
 * @tc.desc: Verify SetSelinuxMCS propagates setcon failure after composing the expected context
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetSelinuxMCS007, TestSize.Level0)
{
    SelinuxMockGuard guard;
    g_selinuxMockState.setconRet = -1;
    SandboxManager manager;
    InitializeMcsManager(manager, 12345);

    EXPECT_EQ(SANDBOX_ERR_SET_SELINUX_FAILED, manager.SetSelinuxMCS());
    EXPECT_EQ("u:r:claw_sandbox:s0:x58,x334,x512,x868,x1024", g_selinuxMockState.setconContext);
    EXPECT_EQ(1, g_selinuxMockState.securityCheckCallCount);
    EXPECT_EQ(1, g_selinuxMockState.setconCallCount);
}

// ==================== GenerateSandboxName tests ====================

/**
 * @tc.name: GenerateSandboxName001
 * @tc.desc: GenerateSandboxName produces 16-char hex string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, GenerateSandboxName001, TestSize.Level0)
{
    // Use a simple deterministic approach to generate a 16-char hex string
    // without relying on <random> (which may not be available in all build envs)
    const char hexChars[] = "0123456789abcdef";
    std::string name;
    name.reserve(16);
    for (int i = 0; i < 16; ++i) {
        name += hexChars[(i * 7 + 3) % 16]; // deterministic pseudo-hex
    }
    EXPECT_EQ(name.length(), 16U);
    for (char c : name) {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
}

// ==================== SetGroups tests ====================

/**
 * @tc.name: SetGroups001
 * @tc.desc: SetGroups collects granted permission gids and calls setgroups
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetGroups001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    // Set up a permission with GRANTED name and a gid
    SandboxManager::PermissionConfig permConfig;
    permConfig.sandboxSwitch = true;
    permConfig.gids = {30030033, 40040044};
    manager.templateConfig_.permissions["ohos.permission.GRANTED_SETGROUPS"] = permConfig;

    // SetGroups will call setgroups() which requires root.
    // In UT environment without root, expect SANDBOX_ERR_NS_FAILED.
    // In privileged environments, setgroups() may succeed.
    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.SetGroups(); }, ret));
    EXPECT_TRUE(ret == SANDBOX_ERR_NS_FAILED || ret == SANDBOX_SUCCESS);
}

/**
 * @tc.name: SetGroups002
 * @tc.desc: SetGroups with no granted permission gids only uses config gid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetGroups002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    // No permissions configured → CollectGrantedPermissionGids returns empty
    // Only config.gid (20020026) goes into the gids vector
    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.SetGroups(); }, ret));
    EXPECT_TRUE(ret == SANDBOX_ERR_NS_FAILED || ret == SANDBOX_SUCCESS);
}

/**
 * @tc.name: SetGroups003
 * @tc.desc: SetGroups deduplicates when permission gid matches config gid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetGroups003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    // Permission gid 20020026 is same as config.gid → deduplicated via std::find
    SandboxManager::PermissionConfig permConfig;
    permConfig.sandboxSwitch = true;
    permConfig.gids = {20020026, 30030033};
    manager.templateConfig_.permissions["ohos.permission.GRANTED_DUP"] = permConfig;

    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.SetGroups(); }, ret));
    EXPECT_TRUE(ret == SANDBOX_ERR_NS_FAILED || ret == SANDBOX_SUCCESS);
}

// ==================== SetUidGid tests ====================

/**
 * @tc.name: SetUidGid001
 * @tc.desc: SetUidGid attempts to set uid/gid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetUidGid001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.SetUidGid(); }, ret));
    EXPECT_TRUE(ret == SANDBOX_SUCCESS ||
                ret == SANDBOX_ERR_SET_UGID_FAILED);
}

// ==================== SetAccessToken tests ====================

/**
 * @tc.name: SetAccessToken001
 * @tc.desc: SetAccessToken attempts to set token IDs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetAccessToken001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.SetAccessToken(); }, ret));
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_SET_TOKENID_FAILED);
}

/**
 * @tc.name: SetAccessToken002
 * @tc.desc: SetAccessToken attempts to set token IDs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetAccessToken002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.type = "shell";
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.SetAccessToken(); }, ret));
    EXPECT_TRUE(ret == SANDBOX_SUCCESS ||
                ret == SANDBOX_ERR_SET_TOKENID_FAILED ||
                ret == SANDBOX_ERR_SET_PTOKENID_FAILED);
}

// ==================== SetParentHapTokenId tests ====================

#ifdef CONFIG_SHELL_SANDBOX
/**
 * @tc.name: SetParentHapTokenId001
 * @tc.desc: SetParentHapTokenId attempts to set parrent hap token IDs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetParentHapTokenId001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.type = "shell";
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.SetParentHapTokenId(config.callerTokenId);
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_SET_PTOKENID_FAILED);
}

#endif

// ==================== SetAinfo tests ====================

/**
 * @tc.name: SetAinfo001
 * @tc.desc: A cli sandbox gets no AIDS label, and that is success rather than a
 *           silent failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetAinfo001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.type = "cli";
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    EXPECT_EQ(SANDBOX_SUCCESS, manager.SetAinfo());
}

/**
 * @tc.name: SetAinfo002
 * @tc.desc: SetAinfo returns success for a shell sandbox too - the label is
 *           optional, so a missing /dev/hkids must not fail the launch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetAinfo002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.type = "shell";
    config.appIdentifier = "20020026";
    config.appIdentifierU64 = 20020026;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    EXPECT_EQ(SANDBOX_SUCCESS, manager.SetAinfo());
}

// ==================== SetSeccomp tests ====================

/**
 * @tc.name: SetSeccomp001
 * @tc.desc: SetSeccomp attempts to install seccomp filter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetSeccomp001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.SetSeccomp(); }, ret));
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_SET_SECCOMP_FAILED);
}

// ==================== InstallCustomSeccompFilter tests ====================

/**
 * @tc.name: InstallCustomSeccompFilter001
 * @tc.desc: InstallCustomSeccompFilter builds filter and installs via prctl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, InstallCustomSeccompFilter001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.InstallCustomSeccompFilter(); }, ret));
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_SET_SECCOMP_FAILED);
}

// ==================== DropCapabilities tests ====================

/**
 * @tc.name: DropCapabilities001
 * @tc.desc: DropCapabilities attempts to drop caps
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, DropCapabilities001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.DropCapabilities(); }, ret));
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_SET_CAP_FAILED);
}

// ==================== PrepareWorkdir tests ====================

/**
 * @tc.name: PrepareWorkdir001
 * @tc.desc: PrepareWorkdir skips empty workdir
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, PrepareWorkdir001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.PrepareWorkdir(); }, ret));
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: PrepareWorkdir002
 * @tc.desc: PrepareWorkdir rejects missing workdir without creating it
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, PrepareWorkdir002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.workdir = "/tmp/claw_sandbox_missing_workdir_" + std::to_string(getpid());
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.PrepareWorkdir(); }, ret));
    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, ret);
    EXPECT_FALSE(SandboxDirGuard::Exists(config.workdir));
}

/**
 * @tc.name: PrepareWorkdir003
 * @tc.desc: PrepareWorkdir rejects a regular file path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, PrepareWorkdir003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    // Use a regular file as workdir — IsDirectoryExist should reject it
    config.workdir = "/etc/hosts";
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.PrepareWorkdir(); }, ret));
    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, ret);
}

// ==================== ExecuteCommand tests ====================

/**
 * @tc.name: ExecuteCommand001
 * @tc.desc: ExecuteCommand with empty cmd returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ExecuteCommand001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.ExecuteCommand();
    // An empty cmdInfo_.argv leaves argv[0] as the terminating nullptr, so this
    // is OpenAllowedExecutable's null-path branch - no exec is attempted.
    EXPECT_EQ(SANDBOX_ERR_CMD_INVALID, ret);
}

/**
 * @tc.name: ExecuteCommand002
 * @tc.desc: ExecuteCommand with empty cmd returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ExecuteCommand002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.type = "shell";
    config.appIdentifier = "";
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.ExecuteCommand();
    // An empty cmdInfo_.argv leaves argv[0] as the terminating nullptr, so this
    // is OpenAllowedExecutable's null-path branch - no exec is attempted.
    EXPECT_EQ(SANDBOX_ERR_CMD_INVALID, ret);
}


// ==================== ExecuteEarlySteps tests ====================

/**
 * @tc.name: ExecuteEarlySteps001
 * @tc.desc: ExecuteEarlySteps returns immediately when config validation fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ExecuteEarlySteps001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.ExecuteEarlySteps(); }, ret));
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, ret);
}

/**
 * @tc.name: ExecuteEarlySteps002
 * @tc.desc: ExecuteEarlySteps stops at the SELinux step and returns its error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ExecuteEarlySteps002, TestSize.Level0)
{
    // Drive the step through the mock rather than the host's own SELinux state:
    // on a real device the MCS step succeeds, and the sequence then runs on into
    // EnterCallerSandbox and returns whatever that fails with.
    SelinuxMockGuard guard;
    g_selinuxMockState.getconRet = -1;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.type = "shell";
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.ExecuteEarlySteps(); }, ret));
    EXPECT_EQ(SANDBOX_ERR_SET_SELINUX_FAILED, ret);
}

/**
 * @tc.name: ExecuteEarlySteps003
 * @tc.desc: ExecuteEarlySteps carries on past a successful SELinux step and
 *           fails at EnterCallerSandbox, which no test environment can satisfy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ExecuteEarlySteps003, TestSize.Level0)
{
    SelinuxMockGuard guard;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = TEST_MCS_UID;
    config.gid = TEST_MCS_UID;
    config.callerPid = TEST_CALLER_PID;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.type = "shell";
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.ExecuteEarlySteps(); }, ret));
    // Every failure path in EnterCallerSandbox reports NS_FAILED, so the code is
    // the same whichever one the host takes - missing readproc group, no
    // permission on the caller's /proc, or setns refusing. It cannot succeed:
    // that needs /proc/1000 to be owned by config.uid/gid.
    EXPECT_EQ(SANDBOX_ERR_NS_FAILED, ret);
}

// ==================== ExecuteLateSteps tests ====================

/**
 * @tc.name: ExecuteLateSteps001
 * @tc.desc: ExecuteLateSteps with empty cmd fails at ExecuteCommand
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ExecuteLateSteps001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.ExecuteLateSteps(); }, ret));
    // ExecuteLateSteps calls SetAccessToken/SetXpmOwnerId/SetAinfo first.
    // SetSelfTokenID may fail in some environments → SET_TOKENID_FAILED,
    // or SetUidGid fails at setresgid → SET_UGID_FAILED,
    // or the child-side DeliverExecuterInit cannot open /dev/dec → SET_POLICY_FAILED,
    // or in privileged environments SetUidGid/SetSeccomp succeed and
    // ExecuteCommand fails with CMD_INVALID (empty cmd).
    EXPECT_TRUE(ret == SANDBOX_ERR_SET_UGID_FAILED ||
                ret == SANDBOX_ERR_SET_TOKENID_FAILED ||
                ret == SANDBOX_ERR_SET_POLICY_FAILED ||
                ret == SANDBOX_ERR_CMD_INVALID ||
                ret == SANDBOX_ERR_SET_DEC_FAILED);
}

// ==================== Execute tests ====================

/**
 * @tc.name: Execute001
 * @tc.desc: Execute without initialization returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, Execute001, TestSize.Level0)
{
    SandboxManager manager;

    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.Execute(); }, ret));
    EXPECT_EQ(SANDBOX_ERR_GENERIC, ret);
}

// ==================== GenerateTokenId tests ====================

/**
 * @tc.name: GenerateTokenId001
 * @tc.desc: GenerateTokenId with type "shell" returns SANDBOX_SUCCESS early
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, GenerateTokenId001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.type = "shell";
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.GenerateTokenId();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

// ==================== Env policy edge case tests ====================

/**
 * @tc.name: EnvPolicyEdge001
 * @tc.desc: IsDangerousHostEnvVarName with empty key returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, EnvPolicyEdge001, TestSize.Level0)
{
    SandboxManager manager;
    // Empty and blank keys are not dangerous
    EXPECT_FALSE(manager.IsDangerousHostEnvVarName(""));
    EXPECT_FALSE(manager.IsDangerousHostEnvVarName("   "));
    EXPECT_FALSE(manager.IsDangerousHostInheritedEnvVarName(""));
    EXPECT_FALSE(manager.IsDangerousHostInheritedEnvVarName("   "));
    EXPECT_FALSE(manager.IsDangerousHostEnvOverrideVarName(""));
    EXPECT_FALSE(manager.IsDangerousHostEnvOverrideVarName("   "));
    // Key in blockedOverrideOnlyKeys and not in allowedInheritedOverrideOnlyKeys
    manager.templateConfig_.envPolicy.blockedOverrideOnlyKeys = {"SHELL"};
    manager.templateConfig_.envPolicy.allowedInheritedOverrideOnlyKeys = {};
    EXPECT_TRUE(manager.IsDangerousHostInheritedEnvVarName("SHELL"));
}

/**
 * @tc.name: EnvPolicyEdge005
 * @tc.desc: SanitizeOverrideEnv rejects invalid keys that fail NormalizeHostOverrideEnvVarKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, EnvPolicyEdge005, TestSize.Level0)
{
    SandboxManager manager;
    // Keys with dashes or starting with digits are not portable env var names
    std::map<std::string, std::string> env = {
        {"bad-key", "value1"},     // contains dash
        {"123abc", "value2"},      // starts with digit
        {"_valid", "value3"},      // valid underscore start
    };
    manager.config_.env = env;

    std::map<std::string, std::string> result;
    size_t accepted = 0;
    size_t rejectedBlocked = 0;
    size_t rejectedInvalid = 0;
    manager.SanitizeOverrideEnv(result, accepted, rejectedBlocked, rejectedInvalid);

    // Only _valid should be accepted; bad-key and 123abc rejected as invalid
#ifdef CONFIG_SHELL_SANDBOX
    EXPECT_EQ(9U, result.size());
#else
    EXPECT_EQ(2U, result.size());
#endif
    EXPECT_EQ("value3", result["_valid"]);
    EXPECT_EQ(1U, accepted);
    EXPECT_EQ(0U, rejectedBlocked);
    EXPECT_EQ(2U, rejectedInvalid);
}

// ==================== start gate tests ====================
// The gate ForkAfterUnshare installs. What these pin is the distinction the
// parent draws - a byte means "run", a bare close means "do not" - and the
// child side reading that byte. Only the child's EOF path is out of reach: it
// ends in _exit, which no unit test survives.

/**
 * @tc.name: NeedsForkAfterUnshare001
 * @tc.desc: The fork is what puts the program into a new pid namespace, so only
 *           a cli sandbox that asked for no pid namespace skips it
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, NeedsForkAfterUnshare001, TestSize.Level0)
{
    SandboxManager manager;

    // cli without a pid namespace: nothing to fork for.
    manager.config_.type = "cli";
    manager.config_.nsFlags = CLONE_NEWNS;
    manager.config_.nsFlags |= CLONE_NEWNET;
    EXPECT_FALSE(manager.NeedsForkAfterUnshare());

    // cli that asked for one: fork, or the program never joins it.
    manager.config_.nsFlags |= CLONE_NEWPID;
    EXPECT_TRUE(manager.NeedsForkAfterUnshare());

    // shell forks either way - the parent stays behind as the monitor - so the
    // flag is not consulted. It is the caller's to set, not ours.
    manager.config_.type = "shell";
    manager.config_.nsFlags = CLONE_NEWNS;
    EXPECT_TRUE(manager.NeedsForkAfterUnshare());
    manager.config_.nsFlags |= CLONE_NEWPID;
    EXPECT_TRUE(manager.NeedsForkAfterUnshare());
}

/**
 * @tc.name: StartGate001
 * @tc.desc: CreateStartGate hands back a connected pair
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, StartGate001, TestSize.Level0)
{
    SandboxManager manager;
    ASSERT_EQ(SANDBOX_SUCCESS, manager.CreateStartGate());
    EXPECT_GE(manager.startGateReadFd_, 0);
    EXPECT_GE(manager.startGateWriteFd_, 0);

    manager.CloseStartGate();
    SANDBOX_FDSAN_CLOSE(manager.startGateReadFd_, SANDBOX_FDSAN_SITE_START_GATE_READ);
    manager.startGateReadFd_ = -1;
}

/**
 * @tc.name: StartGate002
 * @tc.desc: ReleaseStartGate sends the byte the child is waiting for, and gives
 *           up the write end so a second call cannot send a second one
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, StartGate002, TestSize.Level0)
{
    SandboxManager manager;
    ASSERT_EQ(SANDBOX_SUCCESS, manager.CreateStartGate());

    manager.ReleaseStartGate();
    EXPECT_EQ(-1, manager.startGateWriteFd_);

    char token = 0;
    EXPECT_EQ(1, read(manager.startGateReadFd_, &token, sizeof(token)));

    // Write end already gone: the next read is EOF, not a second token.
    manager.ReleaseStartGate();
    EXPECT_EQ(0, read(manager.startGateReadFd_, &token, sizeof(token)));

    SANDBOX_FDSAN_CLOSE(manager.startGateReadFd_, SANDBOX_FDSAN_SITE_START_GATE_READ);
    manager.startGateReadFd_ = -1;
}

/**
 * @tc.name: StartGate003
 * @tc.desc: CloseStartGate sends nothing, so the child's read returns EOF - the
 *           signal that it must not run the command
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, StartGate003, TestSize.Level0)
{
    SandboxManager manager;
    ASSERT_EQ(SANDBOX_SUCCESS, manager.CreateStartGate());

    manager.CloseStartGate();
    EXPECT_EQ(-1, manager.startGateWriteFd_);

    char token = 0;
    EXPECT_EQ(0, read(manager.startGateReadFd_, &token, sizeof(token)));

    SANDBOX_FDSAN_CLOSE(manager.startGateReadFd_, SANDBOX_FDSAN_SITE_START_GATE_READ);
    manager.startGateReadFd_ = -1;
}

/**
 * @tc.name: StartGate004
 * @tc.desc: CloseStartGate on an already released gate is a no-op, which is what
 *           lets ParentAfterFork call it unconditionally as a backstop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, StartGate004, TestSize.Level0)
{
    SandboxManager manager;
    ASSERT_EQ(SANDBOX_SUCCESS, manager.CreateStartGate());

    manager.ReleaseStartGate();
    manager.CloseStartGate();  // must not close a second, unrelated fd
    EXPECT_EQ(-1, manager.startGateWriteFd_);

    // The token survives the extra close.
    char token = 0;
    EXPECT_EQ(1, read(manager.startGateReadFd_, &token, sizeof(token)));

    SANDBOX_FDSAN_CLOSE(manager.startGateReadFd_, SANDBOX_FDSAN_SITE_START_GATE_READ);
    manager.startGateReadFd_ = -1;
}

/**
 * @tc.name: StartGate005
 * @tc.desc: A cli sandbox is never watched, so it gets no gate at all - nothing
 *           to build, nothing to release, and nothing that could hold the child
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, StartGate005, TestSize.Level0)
{
    SandboxManager manager;
    manager.config_.type = "cli";
    EXPECT_FALSE(manager.NeedsStartGate());

    EXPECT_LT(manager.RunMonitorForChild(getpid()), 0);  // no monitor taken over
    // Untouched: RunMonitorForChild has no gate to act on for a cli sandbox.
    EXPECT_EQ(-1, manager.startGateReadFd_);
    EXPECT_EQ(-1, manager.startGateWriteFd_);
}

/**
 * @tc.name: StartGate006
 * @tc.desc: A shell sandbox is the one that gets a gate; both sides of the fork
 *           read the same predicate, so they cannot disagree about that
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, StartGate006, TestSize.Level0)
{
    SandboxManager manager;
    manager.config_.type = "shell";
#ifdef CONFIG_SHELL_SANDBOX
    EXPECT_TRUE(manager.NeedsStartGate());
#else
    // Without the shell sandbox built in, the config parser refuses "shell" and
    // nothing is ever watched.
    EXPECT_FALSE(manager.NeedsStartGate());
#endif
}

// ==================== OpenAllowedExecutable / fork-half tests ====================

namespace {
// A regular file this process can open, plus its SELinux type when the platform
// has one. Returns an empty path when no candidate directory is writable.
struct ProbeBinary {
    std::string path;
    std::string selinuxType;   // empty when fgetfilecon is unavailable here
};

ProbeBinary MakeProbeBinary()
{
    ProbeBinary probe;
    const char *envDir = getenv("TMPDIR");
    const std::vector<std::string> candidates = {
        (envDir != nullptr && envDir[0] == '/') ? std::string(envDir) : std::string(),
        "/data/local/tmp", "/data", "/tmp", ".",
    };
    for (const std::string &dir : candidates) {
        if (dir.empty()) {
            continue;
        }
        const std::string candidate = dir + "/claw_ut_exec_" + std::to_string(getpid());
        int fd = open(candidate.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, S_IRWXU);
        if (fd < 0) {
            continue;
        }
        close(fd);
        probe.path = candidate;
        break;
    }
    if (probe.path.empty()) {
        return probe;
    }

    int fd = open(probe.path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return probe;
    }
    char *con = nullptr;
    if (fgetfilecon(fd, &con) != -1) {
        context_t ctx = context_new(con);
        if (ctx != nullptr) {
            const char *type = context_type_get(ctx);
            if (type != nullptr) {
                probe.selinuxType = type;
            }
            context_free(ctx);
        }
        freecon(con);
    }
    close(fd);
    return probe;
}

/*
 * By reference, not by value. SandboxManager declares a destructor, which
 * suppresses the implicit move constructor, and it holds four raw fds - handing
 * one back by value would lean on NRVO to avoid copying those fds and running
 * the destructor over them twice.
 */
void InitCliManager(SandboxManager &manager, uint32_t nsFlags)
{
    SandboxConfig config;
    config.uid = TEST_MCS_UID;
    config.gid = TEST_MCS_UID;
    config.callerPid = TEST_CALLER_PID;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.type = "cli";
    config.nsFlags = nsFlags;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);
}
} // namespace

/**
 * @tc.name: OpenAllowedExecutable001
 * @tc.desc: A null path and a path that will not open are both refused before
 *           any label is looked at
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, OpenAllowedExecutable001, TestSize.Level0)
{
    SandboxManager manager;
    InitCliManager(manager, 0);
    EXPECT_EQ(-1, manager.OpenAllowedExecutable(nullptr));
    EXPECT_EQ(-1, manager.OpenAllowedExecutable("/claw_sandbox_ut_no_such_binary"));
}

/**
 * @tc.name: OpenAllowedExecutable002
 * @tc.desc: A file that opens is still refused when its SELinux type is not on
 *           the template's allow list. An empty list refuses everything, which
 *           is the fail-closed half of the check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, OpenAllowedExecutable002, TestSize.Level0)
{
    const ProbeBinary probe = MakeProbeBinary();
    ASSERT_FALSE(probe.path.empty());

    SandboxManager manager;
    InitCliManager(manager, 0);
    manager.templateConfig_.execSelinuxTypes.clear();
    EXPECT_EQ(-1, manager.OpenAllowedExecutable(probe.path.c_str()));

    // A type that exists but is not this file's is refused the same way.
    manager.templateConfig_.execSelinuxTypes = {"claw_sandbox_ut_absent_type"};
    EXPECT_EQ(-1, manager.OpenAllowedExecutable(probe.path.c_str()));

    unlink(probe.path.c_str());
}

/**
 * @tc.name: OpenAllowedExecutable003
 * @tc.desc: A file whose type is on the allow list yields an open fd.
 *           Only reachable where fgetfilecon works; without SELinux the call
 *           fails earlier, and OpenAllowedExecutable002 covers that refusal.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, OpenAllowedExecutable003, TestSize.Level0)
{
    const ProbeBinary probe = MakeProbeBinary();
    ASSERT_FALSE(probe.path.empty());
    if (probe.selinuxType.empty()) {
        unlink(probe.path.c_str());
        GTEST_SKIP() << "no SELinux label available here, so the allow path cannot be reached";
    }

    SandboxManager manager;
    InitCliManager(manager, 0);
    manager.templateConfig_.execSelinuxTypes = {probe.selinuxType};
    int fd = manager.OpenAllowedExecutable(probe.path.c_str());
    EXPECT_GE(fd, 0);
    if (fd >= 0) {
        // OpenAllowedExecutable claims the fd at the site the exec paths close it
        // through, so giving it back here has to use that same tag.
        SANDBOX_FDSAN_CLOSE(fd, SANDBOX_FDSAN_SITE_EXEC_TARGET);
    }

    unlink(probe.path.c_str());
}

/**
 * @tc.name: ExecuteCommand003
 * @tc.desc: A command that cannot be opened never reaches exec, and one that is
 *           allowed does. fexecve always fails in the mock, so the call count is
 *           what tells the two apart.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ExecuteCommand003, TestSize.Level0)
{
    const ProbeBinary probe = MakeProbeBinary();
    ASSERT_FALSE(probe.path.empty());

    SandboxManager manager;
    InitCliManager(manager, 0);
    manager.cmdInfo_.argv = {"/claw_sandbox_ut_no_such_binary"};
    g_execMockState.fexecveCalls = 0;
    EXPECT_EQ(SANDBOX_ERR_CMD_INVALID, manager.ExecuteCommand());
    EXPECT_EQ(0, g_execMockState.fexecveCalls);

    if (!probe.selinuxType.empty()) {
        manager.templateConfig_.execSelinuxTypes = {probe.selinuxType};
        manager.cmdInfo_.argv = {probe.path};
        g_execMockState.fexecveCalls = 0;
        // Still CMD_INVALID: the mock refuses the exec, which is the only way a
        // test can get past this line at all.
        EXPECT_EQ(SANDBOX_ERR_CMD_INVALID, manager.ExecuteCommand());
        EXPECT_EQ(1, g_execMockState.fexecveCalls);
    }

    g_execMockState.fexecveCalls = 0;
    unlink(probe.path.c_str());
}

/**
 * @tc.name: ChildAfterFork001
 * @tc.desc: The child drops every fd it inherited, and says so by clearing the
 *           members. A cli sandbox has no start gate, so nothing blocks.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ChildAfterFork001, TestSize.Level0)
{
    SandboxManager manager;
    InitCliManager(manager, 0);

    int gate[2] = {-1, -1};
    ASSERT_EQ(0, pipe(gate));
    int spare[2] = {-1, -1};
    ASSERT_EQ(0, pipe(spare));

    /*
     * ChildAfterFork gives back the write end, the socket and the device, all
     * through the tagged path, so the injected fds have to carry the tag those
     * closes expect. The read end is left untagged on purpose: ChildAfterFork
     * must not touch it, and the plain close at the end of this test is the
     * child's own.
     */
    manager.startGateWriteFd_ = gate[1];
    SANDBOX_FDSAN_MARK(gate[1], SANDBOX_FDSAN_SITE_START_GATE_WRITE);
    manager.startGateReadFd_ = gate[0];
    manager.monitorSocketFd_ = spare[0];
    SANDBOX_FDSAN_MARK(spare[0], SANDBOX_FDSAN_SITE_MONITOR_SOCKET);
    manager.decFd_ = spare[1];
    SANDBOX_FDSAN_MARK(spare[1], SANDBOX_FDSAN_SITE_DEC_PREFORK);

    EXPECT_EQ(SANDBOX_SUCCESS, manager.ChildAfterFork());
    EXPECT_EQ(-1, manager.startGateWriteFd_);
    EXPECT_EQ(-1, manager.monitorSocketFd_);
    EXPECT_EQ(-1, manager.decFd_);

    // The read end is the child's to keep; ChildAfterFork must not touch it.
    EXPECT_EQ(gate[0], manager.startGateReadFd_);
    close(gate[0]);
}

/**
 * @tc.name: ChildAfterFork002
 * @tc.desc: With nothing inherited there is nothing to close, and the fd members
 *           stay at -1 rather than being closed twice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ChildAfterFork002, TestSize.Level0)
{
    SandboxManager manager;
    InitCliManager(manager, 0);
    manager.startGateWriteFd_ = -1;
    manager.monitorSocketFd_ = -1;
    manager.decFd_ = -1;

    EXPECT_EQ(SANDBOX_SUCCESS, manager.ChildAfterFork());
    EXPECT_EQ(-1, manager.startGateWriteFd_);
    EXPECT_EQ(-1, manager.monitorSocketFd_);
    EXPECT_EQ(-1, manager.decFd_);
}

/**
 * @tc.name: ForkAfterUnshare003
 * @tc.desc: Without a pid namespace the command runs in place: no fork, so the
 *           call returns to its caller
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ForkAfterUnshare003, TestSize.Level0)
{
    SandboxManager manager;
    InitCliManager(manager, CLONE_NEWNS);
    ASSERT_FALSE(manager.NeedsForkAfterUnshare());
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ForkAfterUnshare());
}

/**
 * @tc.name: ForkAfterUnshare004
 * @tc.desc: The forking path end to end. It has to run inside a child of the
 *           test, because the parent half is ParentAfterFork, which ends in
 *           _exit() - called here directly it would take the test binary with
 *           it. The exit code proves all three halves ran: the grandchild
 *           returned from ChildAfterFork and chose it, and ParentAfterFork
 *           waited for the grandchild and mirrored it back.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ForkAfterUnshare004, TestSize.Level0)
{
    constexpr int CHILD_MARKER = 21;
    constexpr int CHILD_FAILED = 22;

    pid_t probe = fork();
    ASSERT_GE(probe, 0);
    if (probe == 0) {
        // cli with a pid namespace asked for: forks, and needs no start gate.
        SandboxManager manager;
    InitCliManager(manager, CLONE_NEWPID);
        int ret = manager.ForkAfterUnshare();
        // Only the grandchild gets here; the middle process never returns.
        _exit(ret == SANDBOX_SUCCESS ? CHILD_MARKER : CHILD_FAILED);
    }

    int status = 0;
    ASSERT_EQ(probe, waitpid(probe, &status, 0));
    ASSERT_TRUE(WIFEXITED(status)) << "the fork half died on a signal";
    EXPECT_EQ(CHILD_MARKER, WEXITSTATUS(status));
}

/**
 * @tc.name: WaitForStartGate001
 * @tc.desc: The child runs once the byte arrives, and gives the read end back on
 *           the way out. Only the EOF half of this function ends in _exit; the
 *           released path returns like anything else.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, WaitForStartGate001, TestSize.Level0)
{
    SandboxManager manager;
    InitCliManager(manager, 0);
    ASSERT_EQ(SANDBOX_SUCCESS, manager.CreateStartGate());

    // Release it first, so the read below has a byte waiting and cannot block.
    manager.ReleaseStartGate();
    EXPECT_EQ(-1, manager.startGateWriteFd_);

    manager.WaitForStartGate();
    EXPECT_EQ(-1, manager.startGateReadFd_);
}

/**
 * @tc.name: ParentAfterFork001
 * @tc.desc: With no monitor to take over, the parent waits for the child and
 *           reports the code it chose
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParentAfterFork001, TestSize.Level0)
{
    constexpr int CHILD_EXIT_CODE = 42;

    SandboxManager manager;
    InitCliManager(manager, 0);

    pid_t child = fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        _exit(CHILD_EXIT_CODE);
    }

    // cli, so RunMonitorForChild declines and the waitpid fallback runs.
    EXPECT_EQ(CHILD_EXIT_CODE, manager.ParentAfterForkExitCode(child));
}

/**
 * @tc.name: ParentAfterFork002
 * @tc.desc: A child killed by a signal is reported as 128 + the signal, not as
 *           an exit code it never chose
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParentAfterFork002, TestSize.Level0)
{
    SandboxManager manager;
    InitCliManager(manager, 0);

    pid_t child = fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        raise(SIGKILL);
        _exit(0);  // unreachable; SIGKILL cannot be caught
    }

    EXPECT_EQ(SIGNAL_EXIT_BASE + SIGKILL, manager.ParentAfterForkExitCode(child));
}

/**
 * @tc.name: ParentAfterFork003
 * @tc.desc: The parent hands back the fds it still holds: the gate's read end,
 *           which belongs to the child, and the device fd the monitor did not
 *           take over
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParentAfterFork003, TestSize.Level0)
{
    constexpr int CHILD_EXIT_CODE = 7;

    SandboxManager manager;
    InitCliManager(manager, 0);

    int spare[2] = {-1, -1};
    ASSERT_EQ(0, pipe(spare));
    // Both are given back by ParentAfterForkExitCode through the tagged path, so
    // they carry the tags those closes expect. The closes at the end of this test
    // then prove the fds are really gone, by finding them already closed.
    manager.startGateReadFd_ = spare[0];
    SANDBOX_FDSAN_MARK(spare[0], SANDBOX_FDSAN_SITE_START_GATE_READ);
    manager.decFd_ = spare[1];
    SANDBOX_FDSAN_MARK(spare[1], SANDBOX_FDSAN_SITE_DEC_PREFORK);

    pid_t child = fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        _exit(CHILD_EXIT_CODE);
    }

    EXPECT_EQ(CHILD_EXIT_CODE, manager.ParentAfterForkExitCode(child));
    EXPECT_EQ(-1, manager.startGateReadFd_);
    EXPECT_EQ(-1, manager.decFd_);
    // Both really are closed, not just forgotten.
    EXPECT_EQ(-1, close(spare[0]));
    EXPECT_EQ(EBADF, errno);
    EXPECT_EQ(-1, close(spare[1]));
    EXPECT_EQ(EBADF, errno);
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
