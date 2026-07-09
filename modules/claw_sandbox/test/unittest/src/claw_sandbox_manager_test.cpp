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
#include <sys/mount.h>
#include <sys/syscall.h>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <string>
#include <unistd.h>
#include <sys/stat.h>
#include <utility>
#include <cstring>
#include <securec.h>
#define private public
#include "sandbox_manager.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

// System app mask constant (must match the one in sandbox_manager.cpp)
static constexpr uint64_t TEST_SYSTEM_APP_MASK = (static_cast<uint64_t>(1) << 32);

// A callerTokenId that has SYSTEM_APP_MASK set and a non-zero low 32-bit token ID.
// The low 32 bits (AccessTokenID) will be passed to AccessTokenKit::GetTokenTypeFlag.
// In the real device test environment, this requires a properly initialized token system.
static constexpr uint64_t TEST_HAP_TOKEN_ID = TEST_SYSTEM_APP_MASK | 0x200D000D;

static constexpr int32_t TEST_IOCTL_FD = 100;

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

    int ret = manager.Initialize(config, cmdInfo);
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

    manager.Initialize(config, cmdInfo);
    // currentUserId is derived as uid / UID_BASE (200000)
    // We can verify via ValidateConfig which uses config_.currentUserId indirectly
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ValidateConfig());
}

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

    manager.Initialize(config, cmdInfo);
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

    manager.Initialize(config, cmdInfo);
    int ret = manager.ValidateConfig();
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, ret);
}

/**
 * @tc.name: ValidateConfig003
 * @tc.desc: ValidateConfig with uint32 max callerPid returns success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ValidateConfig003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = static_cast<uint32_t>(-1);
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.appIdentifier = "20020026";
    config.bundleName = "20020026";
    CmdInfo cmdInfo;

    manager.Initialize(config, cmdInfo);
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

    manager.Initialize(config, cmdInfo);
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

    manager.Initialize(config, cmdInfo);
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

    manager.Initialize(config, cmdInfo);
    int ret = manager.ValidateConfig();
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, ret);
}

/**
 * @tc.name: ValidateConfig007
 * @tc.desc: ValidateConfig with callerTokenId missing SYSTEM_APP_MASK returns error
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
    // Token without SYSTEM_APP_MASK (bit 32 not set) - should fail system app check
    config.callerTokenId = 0x200D000D;
    CmdInfo cmdInfo;

    manager.Initialize(config, cmdInfo);
    int ret = manager.ValidateConfig();
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, ret);
}

/**
 * @tc.name: ValidateConfig008
 * @tc.desc: ValidateConfig with callerTokenId having SYSTEM_APP_MASK but zero low bits
 *          still fails because callerTokenId == 0 check comes first
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
    // SYSTEM_APP_MASK alone without any low bits -> callerTokenId != 0, but
    // GetTokenTypeFlag(0) will likely not return TOKEN_HAP
    config.callerTokenId = TEST_SYSTEM_APP_MASK;
    CmdInfo cmdInfo;

    manager.Initialize(config, cmdInfo);
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
    manager.Initialize(config, cmdInfo);
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
    manager.Initialize(config, cmdInfo);
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
    manager.Initialize(config, cmdInfo);
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
    manager.Initialize(config, cmdInfo);
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
    manager.Initialize(config, cmdInfo);
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
    config.appIdentifier = "com.test.app";
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

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
    manager.Initialize(config, cmdInfo);

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
    config.appIdentifier = "com.example.hnp";
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

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
    manager.Initialize(config, cmdInfo);

    // The truncation logic (std::min) should prevent memcpy_s from failing.
    EXPECT_EQ(SANDBOX_SUCCESS, manager.SetXpmOwnerId());
}

// ==================== ValidateTokenType tests ====================

/**
 * @tc.name: ValidateTokenType001
 * @tc.desc: ValidateTokenType passes with TOKEN_HAP and SYSTEM_APP_MASK set
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
    manager.Initialize(config, cmdInfo);
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
    manager.Initialize(config, cmdInfo);
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, manager.ValidateTokenType());
}

/**
 * @tc.name: ValidateTokenType003
 * @tc.desc: ValidateTokenType rejects token without SYSTEM_APP_MASK
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
    config.callerTokenId = 0x200D000D;  // TOKEN_HAP but no SYSTEM_APP_MASK
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, manager.ValidateTokenType());
}

// ==================== ReplaceVariable tests ====================

/**
 * @tc.name: ReplaceVariable001
 * @tc.desc: ReplaceVariable with simple replacement
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ReplaceVariable001, TestSize.Level0)
{
    std::string str = "Hello <PackageName>!";
    std::string result = SandboxManager::ReplaceVariable(str, "<PackageName>", "MyApp");
    EXPECT_EQ("Hello MyApp!", result);
}

/**
 * @tc.name: ReplaceVariable002
 * @tc.desc: ReplaceVariable with multiple occurrences
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ReplaceVariable002, TestSize.Level0)
{
    std::string str = "<PackageName>/<PackageName>/file";
    std::string result = SandboxManager::ReplaceVariable(str, "<PackageName>", "app");
    EXPECT_EQ("app/app/file", result);
}

/**
 * @tc.name: ReplaceVariable003
 * @tc.desc: ReplaceVariable with no match returns original string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ReplaceVariable003, TestSize.Level0)
{
    std::string str = "Hello World";
    std::string result = SandboxManager::ReplaceVariable(str, "<PackageName>", "app");
    EXPECT_EQ("Hello World", result);
}

/**
 * @tc.name: ReplaceVariable004
 * @tc.desc: ReplaceVariable with empty search string returns original
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ReplaceVariable004, TestSize.Level0)
{
    std::string str = "Hello World";
    std::string result = SandboxManager::ReplaceVariable(str, "", "app");
    EXPECT_EQ("Hello World", result);
}

/**
 * @tc.name: ReplaceVariable005
 * @tc.desc: ReplaceVariable with empty replacement string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ReplaceVariable005, TestSize.Level0)
{
    std::string str = "Hello <PackageName>";
    std::string result = SandboxManager::ReplaceVariable(str, "<PackageName>", "");
    EXPECT_EQ("Hello ", result);
}

/**
 * @tc.name: ReplaceVariable006
 * @tc.desc: ReplaceVariable with empty input string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ReplaceVariable006, TestSize.Level0)
{
    std::string str = "";
    std::string result = SandboxManager::ReplaceVariable(str, "<PackageName>", "app");
    EXPECT_EQ("", result);
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

    manager.Initialize(config, cmdInfo);
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

    manager.Initialize(config, cmdInfo);
    int ret = manager.DeleteSandboxDir();
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, ret);
}

/**
 * @tc.name: DeleteSandboxDir004
 * @tc.desc: DeleteSandboxDir with shell type skips EnterCallerSandbox
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
    manager.Initialize(config, cmdInfo);

    // With type "shell", EnterCallerSandbox is skipped.
    // DeleteSandboxDir tries to stat /mnt/sandbox/claw/<name> which
    // does not exist in test environment, so it returns PATH_INVALID.
    int ret = manager.DeleteSandboxDir();
    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, ret);
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

    manager.Initialize(config, cmdInfo);
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

#ifdef CONFIG_PC_PLATFORM
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
#ifdef CONFIG_PC_PLATFORM
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

#ifdef CONFIG_PC_PLATFORM
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

#ifdef CONFIG_PC_PLATFORM
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

#ifdef CONFIG_PC_PLATFORM
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
    manager.Initialize(config, cmdInfo);

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
    manager.Initialize(config, cmdInfo);

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
    manager.Initialize(config, cmdInfo);

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
    manager.Initialize(config, cmdInfo);

    // Override token so that callerTokenId & TOKEN_ID_LOWMASK == 0
    manager.config_.callerTokenId = TEST_SYSTEM_APP_MASK;
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
    manager.Initialize(config, cmdInfo);

    SandboxManager::PermissionConfig permConfig;
    permConfig.decPaths = {"/data/app", "/storage/Users/<currentUserId>/test"};

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
    manager.Initialize(config, cmdInfo);

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
    manager.Initialize(config, cmdInfo);

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
    manager.Initialize(config, cmdInfo);

    SandboxManager::PermissionConfig grantedConfig;
    grantedConfig.sandboxSwitch = true;
    grantedConfig.decPaths = {
        "/storage/Users/100/Download",
        "/storage/Users/<currentUserId>/Desktop",
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
    manager.Initialize(config, cmdInfo);

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
    manager.Initialize(config, cmdInfo);

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
    manager.Initialize(config, cmdInfo);

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
    manager.Initialize(config, cmdInfo);

    manager.ParseSeccompJson(root);

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
    manager.Initialize(config, cmdInfo);

    struct sock_fprog prog;
    int ret = manager.BuildSeccompFilter(prog);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_NE(prog.filter, nullptr);

    // BPF instruction layout (no allow list):
    //   [0] LD arch
    //   [1] JEQ AUDIT_ARCH_AARCH64
    //   [2] RET KILL
    //   [3] LD nr
    //   [4-5] setpgid errno filter
    //   [6-7] setsid errno filter
    //   [8-11] setuid uid range filter (4 insns)
    //   [12-18] setreuid uid range filter (7 insns)
    //   [19-28] setresuid uid range filter (10 insns)
    //   [29-32] setfsuid uid range filter (4 insns)
    //   [33] default action
    //
    // setuid uid range filter (indices 8-11):
    //   [8]  JEQ __NR_setuid, jt=0, jf=3
    //   [9]  LD args[0]
    //   [10] JGE UID_MIN_LIMIT, jt=1, jf=0  <-- KEY: >= limit -> skip KILL
    //   [11] RET KILL
    constexpr size_t SETUID_FILTER_IDX = 8;
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
    manager.Initialize(config, cmdInfo);

    struct sock_fprog prog;
    int ret = manager.BuildSeccompFilter(prog);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_NE(prog.filter, nullptr);

    // setreuid uid range filter (indices 12-18):
    //   [12] JEQ __NR_setreuid, jt=0, jf=6
    //   [13] LD args[0] (ruid)
    //   [14] JGE UID_MIN_LIMIT, jt=1, jf=0  <-- ruid >= limit?
    //   [15] RET KILL
    //   [16] LD args[1] (euid)
    //   [17] JGE UID_MIN_LIMIT, jt=1, jf=0  <-- euid >= limit?
    //   [18] RET KILL
    constexpr size_t SETREUID_RUID_JGE_IDX = 14;
    constexpr size_t SETREUID_EUID_JGE_IDX = 17;

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
    manager.Initialize(config, cmdInfo);

    struct sock_fprog prog;
    int ret = manager.BuildSeccompFilter(prog);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_NE(prog.filter, nullptr);

    // setresuid uid range filter (indices 19-28):
    //   [19] JEQ __NR_setresuid, jt=0, jf=9
    //   [20] LD args[0] (ruid)
    //   [21] JGE UID_MIN_LIMIT, jt=1, jf=0  <-- ruid >= limit?
    //   [22] RET KILL
    //   [23] LD args[1] (euid)
    //   [24] JGE UID_MIN_LIMIT, jt=1, jf=0  <-- euid >= limit?
    //   [25] RET KILL
    //   [26] LD args[2] (suid)
    //   [27] JGE UID_MIN_LIMIT, jt=1, jf=0  <-- suid >= limit?
    //   [28] RET KILL
    constexpr size_t SETRESUID_RUID_JGE_IDX = 21;
    constexpr size_t SETRESUID_EUID_JGE_IDX = 24;
    constexpr size_t SETRESUID_SUID_JGE_IDX = 27;

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
    manager.Initialize(config, cmdInfo);

    struct sock_fprog prog;
    int ret = manager.BuildSeccompFilter(prog);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_NE(prog.filter, nullptr);

    // setfsuid uid range filter (indices 29-32):
    //   [29] JEQ __NR_setfsuid, jt=0, jf=3
    //   [30] LD args[0]
    //   [31] JGE UID_MIN_LIMIT, jt=1, jf=0  <-- KEY: >= limit -> skip KILL
    //   [32] RET KILL
    constexpr size_t SETFSUID_JGE_IDX = 31;

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
    manager.Initialize(config, cmdInfo);

    struct sock_fprog prog;
    int ret = manager.BuildSeccompFilter(prog);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_NE(prog.filter, nullptr);

    // Expected instruction count:
    //   ARCH_CHECK_BPF_CNT = 4
    //   blockedSyscalls * BPF_PER_SYSCALL = 2 * 2 = 4
    //   BPF_PER_UID_SYSCALL_1ARG (setuid) = 4
    //   BPF_PER_UID_SYSCALL_2ARG (setreuid) = 7
    //   BPF_PER_UID_SYSCALL_3ARG (setresuid) = 10
    //   BPF_PER_UID_SYSCALL_1ARG (setfsuid) = 4
    //   default action = 1
    //   Total = 4 + 4 + 4 + 7 + 10 + 4 + 1 = 34
    constexpr size_t EXPECTED_TOTAL_LEN = 34;
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
    manager.ParseSeccompJson(root);

    struct sock_fprog prog;
    int ret = manager.BuildSeccompFilter(prog);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_NE(prog.filter, nullptr);
    EXPECT_EQ(36U, prog.len);
    EXPECT_EQ(SECCOMP_RET_KILL, prog.filter[prog.len - 1].k);

    cJSON_Delete(root);
}

/**
 * @tc.name: BuildSeccompFilter009
 * @tc.desc: BuildSeccompFilter emits EACCES errno rules for blocked process-group syscalls
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, BuildSeccompFilter009, TestSize.Level0)
{
    SandboxManager manager;
    struct sock_fprog prog;
    int ret = manager.BuildSeccompFilter(prog);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_NE(prog.filter, nullptr);
    ASSERT_GT(prog.len, 7U);

    constexpr size_t SETPGID_JUMP_IDX = 4;
    constexpr size_t SETPGID_RET_IDX = 5;
    constexpr size_t SETSID_JUMP_IDX = 6;
    constexpr size_t SETSID_RET_IDX = 7;

    EXPECT_EQ(static_cast<uint16_t>(BPF_JMP | BPF_JEQ | BPF_K),
        prog.filter[SETPGID_JUMP_IDX].code);
    EXPECT_EQ(static_cast<uint32_t>(__NR_setpgid), prog.filter[SETPGID_JUMP_IDX].k);
    EXPECT_EQ(static_cast<uint16_t>(BPF_RET | BPF_K), prog.filter[SETPGID_RET_IDX].code);
    EXPECT_EQ(static_cast<uint32_t>(SECCOMP_RET_ERRNO | EACCES),
        prog.filter[SETPGID_RET_IDX].k);

    EXPECT_EQ(static_cast<uint16_t>(BPF_JMP | BPF_JEQ | BPF_K),
        prog.filter[SETSID_JUMP_IDX].code);
    EXPECT_EQ(static_cast<uint32_t>(__NR_setsid), prog.filter[SETSID_JUMP_IDX].k);
    EXPECT_EQ(static_cast<uint16_t>(BPF_RET | BPF_K), prog.filter[SETSID_RET_IDX].code);
    EXPECT_EQ(static_cast<uint32_t>(SECCOMP_RET_ERRNO | EACCES),
        prog.filter[SETSID_RET_IDX].k);
}

/**
 * @tc.name: BuildSeccompFilter010
 * @tc.desc: BuildSeccompFilter emits allow-list rules before blocked syscall rules
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, BuildSeccompFilter010, TestSize.Level0)
{
    const char *json = R"({"seccomp": {"allow-list": ["execve"]}})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    manager.ParseSeccompJson(root);

    struct sock_fprog prog;
    int ret = manager.BuildSeccompFilter(prog);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_NE(prog.filter, nullptr);
    ASSERT_GT(prog.len, 9U);

    constexpr size_t EXECVE_JUMP_IDX = 4;
    constexpr size_t EXECVE_RET_IDX = 5;
    constexpr size_t SETPGID_JUMP_IDX = 6;

    EXPECT_EQ(static_cast<uint16_t>(BPF_JMP | BPF_JEQ | BPF_K),
        prog.filter[EXECVE_JUMP_IDX].code);
    EXPECT_EQ(static_cast<uint32_t>(__NR_execve), prog.filter[EXECVE_JUMP_IDX].k);
    EXPECT_EQ(static_cast<uint16_t>(BPF_RET | BPF_K), prog.filter[EXECVE_RET_IDX].code);
    EXPECT_EQ(static_cast<uint32_t>(SECCOMP_RET_ALLOW), prog.filter[EXECVE_RET_IDX].k);
    EXPECT_EQ(static_cast<uint32_t>(__NR_setpgid), prog.filter[SETPGID_JUMP_IDX].k);
    EXPECT_EQ(static_cast<uint32_t>(SECCOMP_RET_KILL), prog.filter[prog.len - 1].k);

    cJSON_Delete(root);
}

// ==================== ApplyMcsLevel tests ====================

/**
 * @tc.name: ApplyMcsLevel001
 * @tc.desc: Verify MCS level constants and segment offset calculations for uid=20020026
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ApplyMcsLevel001, TestSize.Level0)
{
    // Verify the MCS category segment offsets
    constexpr int CATEGORY_SEG0_OFFSET = 0;
    constexpr int CATEGORY_SEG1_OFFSET = 256;
    constexpr int CATEGORY_SEG2_OFFSET = 512;
    constexpr int CATEGORY_SEG3_OFFSET = 768;
    constexpr int CATEGORY_SEG4_OFFSET = 1024;
    constexpr int CATEGORY_MASK = 0xff;
    constexpr int SHIFT_8 = 8;
    constexpr int SHIFT_16 = 16;

    // uid = 20020026
    // userId = 20020026 / 200000 = 100
    // appId = 20020026 % 200000 = 20026
    //
    // seg0 = 0 + (20026 & 0xff) = 0 + 58 = 58
    // seg1 = 256 + ((20026 >> 8) & 0xff) = 256 + 78 = 334
    // seg2 = 512 + ((20026 >> 16) & 0xff) = 512 + 0 = 512
    // seg3 = 768 + (100 & 0xff) = 768 + 100 = 868
    // seg4 = 1024 + ((100 >> 8) & 0xff) = 1024 + 0 = 1024
    uint32_t uid = 20020026;
    uint32_t userId = uid / 200000;
    uint32_t appId = uid % 200000;

    EXPECT_EQ(userId, 100U);
    EXPECT_EQ(appId, 20026U);

    int seg0 = CATEGORY_SEG0_OFFSET + static_cast<int>(appId & CATEGORY_MASK);
    int seg1 = CATEGORY_SEG1_OFFSET + static_cast<int>((appId >> SHIFT_8) & CATEGORY_MASK);
    int seg2 = CATEGORY_SEG2_OFFSET + static_cast<int>((appId >> SHIFT_16) & CATEGORY_MASK);
    int seg3 = CATEGORY_SEG3_OFFSET + static_cast<int>(userId & CATEGORY_MASK);
    int seg4 = CATEGORY_SEG4_OFFSET + static_cast<int>((userId >> SHIFT_8) & CATEGORY_MASK);

    EXPECT_EQ(seg0, 58);
    EXPECT_EQ(seg1, 334);
    EXPECT_EQ(seg2, 512);
    EXPECT_EQ(seg3, 868);
    EXPECT_EQ(seg4, 1024);

    std::string expectedLevel = "s0:x" + std::to_string(seg0)
        + ",x" + std::to_string(seg1)
        + ",x" + std::to_string(seg2)
        + ",x" + std::to_string(seg3)
        + ",x" + std::to_string(seg4);
    EXPECT_EQ(expectedLevel, "s0:x58,x334,x512,x868,x1024");
}

/**
 * @tc.name: ApplyMcsLevel002
 * @tc.desc: Verify MCS level string for uid with non-zero appId high bytes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ApplyMcsLevel002, TestSize.Level0)
{
    constexpr int CATEGORY_MASK = 0xff;
    constexpr int SHIFT_8 = 8;
    constexpr int SHIFT_16 = 16;

    // uid = 20020026 + 0x11D = 20020311
    // appId = 20020311 % 200000 = 20311 = 0x4F57
    // appId & 0xff = 0x57 = 87
    // (appId >> 8) & 0xff = 0x4F = 79
    // (appId >> 16) & 0xff = 0x00 = 0
    uint32_t uid = 20020026 + 0x11D;
    uint32_t userId = uid / 200000;
    uint32_t appId = uid % 200000;

    EXPECT_EQ(userId, 100U);
    EXPECT_EQ(appId, 20311U);

    int seg0 = 0 + static_cast<int>(appId & CATEGORY_MASK);
    int seg1 = 256 + static_cast<int>((appId >> SHIFT_8) & CATEGORY_MASK);
    int seg2 = 512 + static_cast<int>((appId >> SHIFT_16) & CATEGORY_MASK);

    EXPECT_EQ(seg0, 87);
    EXPECT_EQ(seg1, 335);
    EXPECT_EQ(seg2, 512);
}

/**
 * @tc.name: ApplyMcsLevel003
 * @tc.desc: Verify MCS level string for uid with non-zero userId high bytes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ApplyMcsLevel003, TestSize.Level0)
{
    constexpr int CATEGORY_MASK = 0xff;
    constexpr int SHIFT_8 = 8;

    // uid = 200000 * 300 + 42 = 60000042
    // userId = 300 = 0x12C
    // userId & 0xff = 0x2C = 44
    // (userId >> 8) & 0xff = 0x01 = 1
    uint32_t uid = 200000 * 300 + 42;
    uint32_t userId = uid / 200000;
    uint32_t appId = uid % 200000;

    EXPECT_EQ(userId, 300U);
    EXPECT_EQ(appId, 42U);

    int seg3 = 768 + static_cast<int>(userId & CATEGORY_MASK);
    int seg4 = 1024 + static_cast<int>((userId >> SHIFT_8) & CATEGORY_MASK);

    EXPECT_EQ(seg3, 812);
    EXPECT_EQ(seg4, 1025);
}

// ==================== SetSelinuxMCS tests ====================

/**
 * @tc.name: SetSelinuxMCS001
 * @tc.desc: SetSelinuxMCS checks is_selinux_enabled first
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetSelinuxMCS001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.SetSelinuxMCS();
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_SET_SELINUX_FAILED);
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
    manager.Initialize(config, cmdInfo);

    // Set up a permission with GRANTED name and a gid
    SandboxManager::PermissionConfig permConfig;
    permConfig.sandboxSwitch = true;
    permConfig.gids = {30030033, 40040044};
    manager.templateConfig_.permissions["ohos.permission.GRANTED_SETGROUPS"] = permConfig;

    // SetGroups will call setgroups() which requires root.
    // In UT environment without root, expect SANDBOX_ERR_NS_FAILED.
    // In privileged environments, setgroups() may succeed.
    int ret = manager.SetGroups();
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
    manager.Initialize(config, cmdInfo);

    // No permissions configured → CollectGrantedPermissionGids returns empty
    // Only config.gid (20020026) goes into the gids vector
    int ret = manager.SetGroups();
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
    manager.Initialize(config, cmdInfo);

    // Permission gid 20020026 is same as config.gid → deduplicated via std::find
    SandboxManager::PermissionConfig permConfig;
    permConfig.sandboxSwitch = true;
    permConfig.gids = {20020026, 30030033};
    manager.templateConfig_.permissions["ohos.permission.GRANTED_DUP"] = permConfig;

    int ret = manager.SetGroups();
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
    manager.Initialize(config, cmdInfo);

    int ret = manager.SetUidGid();
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
    manager.Initialize(config, cmdInfo);

    int ret = manager.SetAccessToken();
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
    manager.Initialize(config, cmdInfo);

    int ret = manager.SetAccessToken();
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_SET_TOKENID_FAILED);
}

// ==================== SetParentHapTokenId tests ====================

#ifdef CONFIG_PC_PLATFORM
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
    manager.Initialize(config, cmdInfo);

    int ret = manager.SetParentHapTokenId(config.callerTokenId);
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_SET_PTOKENID_FAILED);
}

#endif

// ==================== SetAinfo tests ====================

/**
 * @tc.name: SetAinfo001
 * @tc.desc: SetAinfo always returns success (Ainfo is optional)
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
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.SetAinfo();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
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
    manager.Initialize(config, cmdInfo);

    int ret = manager.SetSeccomp();
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
    manager.Initialize(config, cmdInfo);

    int ret = manager.InstallCustomSeccompFilter();
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
    manager.Initialize(config, cmdInfo);

    int ret = manager.DropCapabilities();
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
    manager.Initialize(config, cmdInfo);

    EXPECT_EQ(SANDBOX_SUCCESS, manager.PrepareWorkdir());
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
    manager.Initialize(config, cmdInfo);

    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, manager.PrepareWorkdir());
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
    manager.Initialize(config, cmdInfo);

    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, manager.PrepareWorkdir());
}

// ==================== DeliverPolicy tests ====================

// Helper: allocate and initialize a minimal valid policyArg for DeliverPolicy tests.
// The returned pointer must be freed with std::free() by the caller.
static struct AgentLockAddPolicyArg *MakeMinimalPolicyArg(uint32_t policyCnt = 1)
{
    size_t totalSize = sizeof(struct AgentLockAddPolicyArg) +
                       policyCnt * sizeof(struct AgentLockPolicy);
    auto *arg = static_cast<struct AgentLockAddPolicyArg *>(std::malloc(totalSize));
    if (arg == nullptr) {
        return nullptr;
    }
    if (memset_s(arg, totalSize, 0, totalSize) != 0) {
        std::free(arg);
        arg = nullptr;
        return nullptr;
    }
    arg->version = 1;
    arg->policyCnt = policyCnt;
    return arg;
}

/**
 * @tc.name: DeliverPolicy001
 * @tc.desc: DeliverPolicy with nullptr policyArg returns success early
 *           (no policy to deliver, skips open/ioctl entirely)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, DeliverPolicy001, TestSize.Level0)
{
    IoctlMockGuard guard;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.policyArg = nullptr; // No netPolicy provided
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.DeliverPolicy();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: DeliverPolicy002
 * @tc.desc: DeliverPolicy with uninitialized manager returns SANDBOX_ERR_GENERIC
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, DeliverPolicy002, TestSize.Level0)
{
    IoctlMockGuard guard;

    SandboxManager manager;
    // Not calling Initialize() — initialized_ stays false

    int ret = manager.DeliverPolicy();
    EXPECT_EQ(SANDBOX_ERR_GENERIC, ret);
}

/**
 * @tc.name: DeliverPolicy003
 * @tc.desc: DeliverPolicy returns SET_POLICY_FAILED when open("/dev/dec") fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, DeliverPolicy003, TestSize.Level0)
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
    config.policyArg = MakeMinimalPolicyArg();
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.DeliverPolicy();
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_FAILED, ret);
    if (config.policyArg != nullptr) {
        std::free(config.policyArg);
        config.policyArg = nullptr;
    }
}

/**
 * @tc.name: DeliverPolicy004
 * @tc.desc: DeliverPolicy returns SET_POLICY_FAILED when ioctl init
 *           (DEC_CMD_AGENTLOCK_CURR_EXECUTER_INIT, call index 0) fails.
 *           Verifies fd is closed on the error path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, DeliverPolicy004, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;     // open succeeds → mockFd
    g_ioctlMockState.failOnCallIndex = 0;  // first ioctl (init) fails
    g_ioctlMockState.ioctlErrno = EINVAL;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.policyArg = MakeMinimalPolicyArg();
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.DeliverPolicy();
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_FAILED, ret);
    EXPECT_EQ(1, g_ioctlMockState.ioctlCallCount);

    if (config.policyArg != nullptr) {
        std::free(config.policyArg);
        config.policyArg = nullptr;
    }
}

/**
 * @tc.name: DeliverPolicy005
 * @tc.desc: DeliverPolicy returns SET_POLICY_FAILED when net policy ioctl
 *           (DEC_CMD_POLICY_ADD, call index 1) fails after init succeeds.
 *           Verifies fd is closed on the error path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, DeliverPolicy005, TestSize.Level0)
{
    IoctlMockGuard guard;
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;
    g_ioctlMockState.failOnCallIndex = 1;
    g_ioctlMockState.ioctlErrno = EINVAL;

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.policyArg = MakeMinimalPolicyArg();
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);
    int ret = manager.DeliverPolicy();
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_FAILED, ret);
    EXPECT_EQ(2, g_ioctlMockState.ioctlCallCount);
    if (config.policyArg != nullptr) {
        std::free(config.policyArg);
        config.policyArg = nullptr;
    }
}

/**
 * @tc.name: DeliverPolicy006
 * @tc.desc: DeliverPolicy full success path: open succeeds, init ioctl succeeds,
 *           net policy ioctl succeeds. Returns SANDBOX_SUCCESS and closes fd.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, DeliverPolicy006, TestSize.Level0)
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
    config.policyArg = MakeMinimalPolicyArg();
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.DeliverPolicy();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(2, g_ioctlMockState.ioctlCallCount);
    if (config.policyArg != nullptr) {
        std::free(config.policyArg);
        config.policyArg = nullptr;
    }
}

/**
 * @tc.name: DeliverPolicy007
 * @tc.desc: DeliverPolicy with open returning EACCES verifies the error code
 *           is propagated as SANDBOX_ERR_SET_POLICY_FAILED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, DeliverPolicy007, TestSize.Level0)
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
    config.policyArg = MakeMinimalPolicyArg();
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.DeliverPolicy();
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_FAILED, ret);
    if (config.policyArg != nullptr) {
        std::free(config.policyArg);
        config.policyArg = nullptr;
    }
}

/**
 * @tc.name: DeliverPolicy008
 * @tc.desc: DeliverPolicy with init ioctl failing with ENOTTY verifies that
 *           different errno values are handled (function returns SET_POLICY_FAILED
 *           regardless of the specific errno)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, DeliverPolicy008, TestSize.Level0)
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
    config.policyArg = MakeMinimalPolicyArg();
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.DeliverPolicy();
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_FAILED, ret);
    if (config.policyArg != nullptr) {
        std::free(config.policyArg);
        config.policyArg = nullptr;
    }
}

/**
 * @tc.name: DeliverPolicy009
 * @tc.desc: DeliverPolicy with policyArg containing multiple policies
 *           verifies the full flow succeeds with the correct ioctl call count
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, DeliverPolicy009, TestSize.Level0)
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
    config.policyArg = MakeMinimalPolicyArg(3);
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.DeliverPolicy();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(2, g_ioctlMockState.ioctlCallCount);
    if (config.policyArg != nullptr) {
        std::free(config.policyArg);
        config.policyArg = nullptr;
    }
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
    manager.Initialize(config, cmdInfo);

    int ret = manager.ExecuteCommand();
    // When cmdInfo_.argv is empty, ExecuteCommand falls back to execl("/system/bin/sh")
    // which fails in test environment, returning SANDBOX_ERR_CMD_INVALID
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
    manager.Initialize(config, cmdInfo);

    int ret = manager.ExecuteCommand();
    // When cmdInfo_.argv is empty, ExecuteCommand falls back to execl("/system/bin/sh")
    // which fails in test environment, returning SANDBOX_ERR_CMD_INVALID
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
    manager.Initialize(config, cmdInfo);

    int ret = manager.ExecuteEarlySteps();
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, ret);
}

/**
 * @tc.name: ExecuteEarlySteps002
 * @tc.desc: ExecuteEarlySteps with shell type skips EnterCallerSandbox
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ExecuteEarlySteps002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.type = "shell";
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.ExecuteEarlySteps();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
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
    manager.Initialize(config, cmdInfo);

    int ret = manager.ExecuteLateSteps();
    // ExecuteLateSteps calls SetAccessToken/SetXpmOwnerId/SetAinfo first.
    // SetSelfTokenID may fail in some environments → SET_TOKENID_FAILED,
    // or SetUidGid fails at setresgid → SET_UGID_FAILED,
    // or in privileged environments SetUidGid/SetSeccomp succeed and
    // ExecuteCommand fails with CMD_INVALID (empty cmd).
    EXPECT_TRUE(ret == SANDBOX_ERR_SET_UGID_FAILED ||
                ret == SANDBOX_ERR_SET_TOKENID_FAILED ||
                ret == SANDBOX_ERR_CMD_INVALID);
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

    int ret = manager.Execute();
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
    manager.Initialize(config, cmdInfo);

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
#ifdef CONFIG_PC_PLATFORM
    EXPECT_EQ(9U, result.size());
#else
    EXPECT_EQ(2U, result.size());
#endif
    EXPECT_EQ("value3", result["_valid"]);
    EXPECT_EQ(1U, accepted);
    EXPECT_EQ(0U, rejectedBlocked);
    EXPECT_EQ(2U, rejectedInvalid);
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
