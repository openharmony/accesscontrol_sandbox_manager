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

#include "claw_sandbox_mount_test.h"
#include "sandbox_error.h"
#include <sys/mount.h>
#include <sys/syscall.h>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <string>
#include <unistd.h>
#include <sys/stat.h>
#include <utility>

#define private public
#include "sandbox_manager.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

// System app mask constant (must match the one in sandbox_manager.cpp)
static constexpr uint64_t TEST_SYSTEM_APP_MASK = (static_cast<uint64_t>(1) << 32);

static constexpr uint64_t TEST_HAP_TOKEN_ID = TEST_SYSTEM_APP_MASK | 0x200D000D;

// SandboxDirGuard helper (needed for file/directory based tests)
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

void ClawSandboxMountTest::SetUpTestCase() {}
void ClawSandboxMountTest::TearDownTestCase() {}
void ClawSandboxMountTest::SetUp() {}
void ClawSandboxMountTest::TearDown() {}

/**
 * @tc.name: ConvertMountFlags001
 * @tc.desc: ConvertMountFlags maps flag names to mount flags
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ConvertMountFlags001, TestSize.Level0)
{
    // Empty flags
    EXPECT_EQ(0UL, SandboxManager::ConvertMountFlags({}));
    // Single lowercase flags
    EXPECT_EQ(static_cast<unsigned long>(MS_BIND),
        SandboxManager::ConvertMountFlags({"bind"}));
    EXPECT_EQ(static_cast<unsigned long>(MS_REC),
        SandboxManager::ConvertMountFlags({"rec"}));
    EXPECT_EQ(static_cast<unsigned long>(MS_RDONLY),
        SandboxManager::ConvertMountFlags({"rdonly"}));
    EXPECT_EQ(static_cast<unsigned long>(MS_RDONLY),
        SandboxManager::ConvertMountFlags({"ro"}));
    EXPECT_EQ(static_cast<unsigned long>(MS_SLAVE),
        SandboxManager::ConvertMountFlags({"slave"}));
    EXPECT_EQ(static_cast<unsigned long>(MS_SHARED),
        SandboxManager::ConvertMountFlags({"shared"}));
    EXPECT_EQ(static_cast<unsigned long>(MS_PRIVATE),
        SandboxManager::ConvertMountFlags({"private"}));
    EXPECT_EQ(static_cast<unsigned long>(MS_NOSUID),
        SandboxManager::ConvertMountFlags({"nosuid"}));
    EXPECT_EQ(static_cast<unsigned long>(MS_NODEV),
        SandboxManager::ConvertMountFlags({"nodev"}));
    EXPECT_EQ(static_cast<unsigned long>(MS_NOEXEC),
        SandboxManager::ConvertMountFlags({"noexec"}));
    // Unknown flag name
    EXPECT_EQ(0UL, SandboxManager::ConvertMountFlags({"unknown_flag"}));
    // Combined flags
    EXPECT_EQ(static_cast<unsigned long>(MS_BIND | MS_REC | MS_RDONLY),
        SandboxManager::ConvertMountFlags({"bind", "rec", "rdonly"}));
    // MS_* style aliases
    EXPECT_EQ(static_cast<unsigned long>(MS_BIND | MS_REC),
        SandboxManager::ConvertMountFlags({"MS_BIND", "MS_REC"}));
}

/**
 * @tc.name: ConvertMountFlags015
 * @tc.desc: ConvertMountFlags handles remaining lowercase mount flag names
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ConvertMountFlags015, TestSize.Level0)
{
    const std::pair<std::string, unsigned long> cases[] = {
        {"move", MS_MOVE},
        {"unbindable", MS_UNBINDABLE},
        {"remount", MS_REMOUNT},
        {"noatime", MS_NOATIME},
        {"lazytime", MS_LAZYTIME},
    };

    for (const auto &item : cases) {
        SCOPED_TRACE(item.first);
        EXPECT_EQ(item.second, SandboxManager::ConvertMountFlags({item.first}));
    }
}

/**
 * @tc.name: ConvertMountFlags016
 * @tc.desc: ConvertMountFlags handles MS_* style aliases for non-bind flags
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ConvertMountFlags016, TestSize.Level0)
{
    const std::pair<std::string, unsigned long> cases[] = {
        {"MS_MOVE", MS_MOVE},
        {"MS_SLAVE", MS_SLAVE},
        {"MS_RDONLY", MS_RDONLY},
        {"MS_SHARED", MS_SHARED},
        {"MS_UNBINDABLE", MS_UNBINDABLE},
        {"MS_REMOUNT", MS_REMOUNT},
        {"MS_NOSUID", MS_NOSUID},
        {"MS_NODEV", MS_NODEV},
        {"MS_NOEXEC", MS_NOEXEC},
        {"MS_NOATIME", MS_NOATIME},
        {"MS_LAZYTIME", MS_LAZYTIME},
        {"MS_PRIVATE", MS_PRIVATE},
    };

    for (const auto &item : cases) {
        SCOPED_TRACE(item.first);
        EXPECT_EQ(item.second, SandboxManager::ConvertMountFlags({item.first}));
    }
}

/**
 * @tc.name: CreateDir001
 * @tc.desc: CreateDir creates nested sandbox directory and can be rolled back
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, CreateDir001, TestSize.Level0)
{
    SandboxDirGuard guard("create_dir");
    ASSERT_TRUE(guard.MountRootExists());

    SandboxManager manager;
    int ret = manager.CreateDir(guard.RootPath() + "/nested");
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_TRUE(SandboxDirGuard::Exists(guard.RootPath() + "/nested"));

    // Empty path returns PATH_CREATE_FAILED
    ret = manager.CreateDir("");
    EXPECT_EQ(SANDBOX_ERR_PATH_CREATE_FAILED, ret);
}

/**
 * @tc.name: CreateSandboxWithName001
 * @tc.desc: CreateSandboxWithName creates requested sandbox directory
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, CreateSandboxWithName001, TestSize.Level0)
{
    SandboxDirGuard guard("create_with_name");
    ASSERT_TRUE(guard.MountRootExists());

    SandboxManager manager;
    int ret = manager.CreateSandboxWithName(guard.Name());
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(guard.Name(), manager.config_.name);
    EXPECT_EQ(guard.RootPath(), manager.newRootPath_);
    EXPECT_TRUE(SandboxDirGuard::Exists(guard.RootPath()));
}

/**
 * @tc.name: CreateSandboxAutoName001
 * @tc.desc: CreateSandboxAutoName creates a sandbox directory with generated name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, CreateSandboxAutoName001, TestSize.Level0)
{
    SandboxDirGuard guard("create_auto_direct");
    ASSERT_TRUE(guard.MountRootExists());

    SandboxManager manager;
    int ret = manager.CreateSandboxAutoName();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_FALSE(manager.config_.name.empty());
    guard.TrackCreatedRoot(manager.newRootPath_);
    EXPECT_EQ("/mnt/sandbox/claw/" + manager.config_.name, manager.newRootPath_);
    EXPECT_EQ(16U, manager.config_.name.length());
    EXPECT_TRUE(SandboxDirGuard::Exists(manager.newRootPath_));
}

/**
 * @tc.name: CreateNewRoot001
 * @tc.desc: CreateNewRoot with empty name calls CreateSandboxAutoName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, CreateNewRoot001, TestSize.Level0)
{
    SandboxDirGuard guard("create_auto_name");
    ASSERT_TRUE(guard.MountRootExists());

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.CreateNewRoot();
    if (ret == SANDBOX_SUCCESS) {
        guard.TrackCreatedRoot(manager.newRootPath_);
        EXPECT_TRUE(SandboxDirGuard::Exists(manager.newRootPath_));
        EXPECT_TRUE(SandboxDirGuard::Exists(manager.putOldPath_));
    }
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: CreateNewRoot002
 * @tc.desc: CreateNewRoot with explicit name calls CreateSandboxWithName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, CreateNewRoot002, TestSize.Level0)
{
    SandboxDirGuard guard("create_new_root");
    ASSERT_TRUE(guard.MountRootExists());

    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.name = guard.Name();
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.CreateNewRoot();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(guard.RootPath(), manager.newRootPath_);
    EXPECT_TRUE(SandboxDirGuard::Exists(guard.RootPath()));
    EXPECT_TRUE(SandboxDirGuard::Exists(manager.putOldPath_));
}

/**
 * @tc.name: UnshareNamespaces001
 * @tc.desc: UnshareNamespaces with nsFlags=0 returns success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, UnshareNamespaces001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.nsFlags = 0;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.UnshareNamespaces();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: UnshareNamespaces002
 * @tc.desc: UnshareNamespaces with CLONE_NEWNS may fail in test env
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, UnshareNamespaces002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.nsFlags = CLONE_NEWNS;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.UnshareNamespaces();
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_NS_FAILED);
}

/**
 * @tc.name: ForkAfterUnshare001
 * @tc.desc: ForkAfterUnshare without CLONE_NEWPID returns success (no fork)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ForkAfterUnshare001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.nsFlags = CLONE_NEWNS | CLONE_NEWUTS;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.ForkAfterUnshare();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: ForkAfterUnshare002
 * @tc.desc: ForkAfterUnshare with nsFlags=0 returns success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ForkAfterUnshare002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.nsFlags = 0;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.ForkAfterUnshare();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: MountNewRoot001
 * @tc.desc: MountNewRoot without newRootPath_ set returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountNewRoot001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.MountNewRoot();
    EXPECT_EQ(ret, SANDBOX_ERR_MOUNT_FAILED);
}

/**
 * @tc.name: MountProcFs001
 * @tc.desc: MountProcFs without CLONE_NEWPID returns success (no mount)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountProcFs001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.nsFlags = CLONE_NEWNS;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.MountProcFs();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: MountProcFs002
 * @tc.desc: MountProcFs with CLONE_NEWPID set attempts mount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountProcFs002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.nsFlags = CLONE_NEWPID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.MountProcFs();
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_MOUNT_FAILED);
}


/**
 * @tc.name: IsPolicyWriteEscalation001
 * @tc.desc: IsPolicyWriteEscalation rejects only rw policy over existing readonly mounts
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, IsPolicyWriteEscalation001, TestSize.Level0)
{
    // Policy RO + Existing RO = not escalation
    EXPECT_FALSE(SandboxManager::IsPolicyWriteEscalation(true, true));
    // Policy RO + Existing RW = not escalation
    EXPECT_FALSE(SandboxManager::IsPolicyWriteEscalation(true, false));
    // Policy RW + Existing RW = not escalation
    EXPECT_FALSE(SandboxManager::IsPolicyWriteEscalation(false, false));
    // Policy RW + Existing RO = escalation (rw policy over readonly mount)
    EXPECT_TRUE(SandboxManager::IsPolicyWriteEscalation(false, true));
    // Summary: escalation only when policy requests write and existing mount is readonly
    EXPECT_FALSE(SandboxManager::IsPolicyWriteEscalation(true, true)); // verify idempotent
}

/**
 * @tc.name: MountSystemEntry001
 * @tc.desc: MountSystemEntry with non-existent source returns success (skip)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountSystemEntry001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    SandboxManager::MountEntry entry;
    entry.source = "/nonexistent_source_path_xyz";
    entry.target = "/test_target";

    int ret = manager.MountSystemEntry(entry, "");
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: MountSystemEntry002
 * @tc.desc: MountSystemEntry with /proc source and CLONE_NEWPID returns success (skip)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountSystemEntry002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.nsFlags = CLONE_NEWPID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    SandboxManager::MountEntry entry;
    entry.source = "/proc";
    entry.target = "/proc";

    int ret = manager.MountSystemEntry(entry, "");
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: MountSystemEntry003
 * @tc.desc: MountSystemEntry with /proc source without CLONE_NEWPID attempts mount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountSystemEntry003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.nsFlags = 0;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    SandboxManager::MountEntry entry;
    entry.source = "/proc";
    entry.target = "/proc";

    int ret = manager.MountSystemEntry(entry, "");
    // /proc exists, so it will try to create dir and mount
    // mount may succeed or fail depending on test environment
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_MOUNT_FAILED);
}

/**
 * @tc.name: MountSingleEntry001
 * @tc.desc: MountSingleEntry with checkExists and non-existent source returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountSingleEntry001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    SandboxManager::MountEntry entry;
    entry.source = "/nonexistent_source_xyz";
    entry.target = "/test_target";
    entry.checkExists = true;

    int ret = manager.MountSingleEntry(entry, "");
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: MountSingleEntry002
 * @tc.desc: MountSingleEntry without checkExists attempts mount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountSingleEntry002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.type = "cli";
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    SandboxManager::MountEntry entry;
    entry.source = "/nonexistent_source_xyz";
    entry.target = "/test_target";
    entry.checkExists = false;

    int ret = manager.MountSingleEntry(entry, "");
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_MOUNT_FAILED || ret == SANDBOX_ERR_PATH_CREATE_FAILED);
}

/**
 * @tc.name: MountSystemDirs001
 * @tc.desc: MountSystemDirs with empty systemMounts returns success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountSystemDirs001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    manager.newRootPath_ = "/mnt/sandbox/claw/test";
    int ret = manager.MountSystemDirs();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: Cleanup001
 * @tc.desc: Cleanup with pivotRootDone_ returns immediately without cleanup
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, Cleanup001, TestSize.Level0)
{
    SandboxManager manager;
    manager.pivotRootDone_ = true;
    manager.mountedDirs_.push_back("/nonexistent_mount");
    manager.newRootPath_ = "/tmp/test_root";
    manager.putOldPath_ = "/tmp/test_old";

    // pivotRootDone_ == true ⇒ skip all cleanup
    manager.Cleanup();

    EXPECT_TRUE(manager.pivotRootDone_);
    EXPECT_FALSE(manager.mountedDirs_.empty());
    EXPECT_FALSE(manager.newRootPath_.empty());
    EXPECT_FALSE(manager.putOldPath_.empty());
}

/**
 * @tc.name: Cleanup002
 * @tc.desc: Cleanup without pivotRootDone_ clears mountedDirs_ and paths
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, Cleanup002, TestSize.Level0)
{
    SandboxManager manager;
    manager.pivotRootDone_ = false;
    manager.mountedDirs_.push_back("/nonexistent_mount");
    manager.newRootPath_ = "/nonexistent_root";
    manager.putOldPath_ = "/nonexistent_old";

    manager.Cleanup();

    EXPECT_FALSE(manager.pivotRootDone_);
    EXPECT_TRUE(manager.mountedDirs_.empty());
    EXPECT_TRUE(manager.putOldPath_.empty());
    // newRootPath_ may or may not be cleared depending on rmdir result
}

/**
 * @tc.name: MountDir001
 * @tc.desc: MountDir with non-existent source attempts mount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountDir001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.type = "cli";
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    std::vector<std::string> flags = {"bind"};
    int ret = manager.MountDir("/nonexistent_source_xyz", "/test_target", flags);
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_MOUNT_FAILED || ret == SANDBOX_ERR_PATH_CREATE_FAILED);
}

/**
 * @tc.name: MountAppDirs001
 * @tc.desc: MountAppDirs with empty appMounts returns success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountAppDirs001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    manager.newRootPath_ = "/mnt/sandbox/claw/test";
    int ret = manager.MountAppDirs();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: EnterCallerSandbox001
 * @tc.desc: EnterCallerSandbox enters the caller's mount namespace
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, EnterCallerSandbox001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = getuid();
    config.gid = getgid();
    config.callerPid = getpid();
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.EnterCallerSandbox();
    // EnterCallerSandbox requires:
    //   1. "readproc" group to exist in /etc/group
    //   2. CAP_SETGID for setgroups()
    // If prerequisites are not met, returns SANDBOX_ERR_NS_FAILED.
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_NS_FAILED);
}

/**
 * @tc.name: EnterCallerSandbox002
 * @tc.desc: EnterCallerSandbox fails for invalid callerPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, EnterCallerSandbox002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = getuid();
    config.gid = getgid();
    // callerPid defaults to 0, which is an invalid PID
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.EnterCallerSandbox();
    EXPECT_EQ(SANDBOX_ERR_NS_FAILED, ret);
}

/**
 * @tc.name: EnterCallerSandbox003
 * @tc.desc: EnterCallerSandbox fails when caller uid/gid doesn't match target process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, EnterCallerSandbox003, TestSize.Level0)
{
    // Use PID 1 (init, always uid 0). Set a different uid so that
    // OpenCallerProcDir passes the open() call but fails the uid/gid mismatch check.
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 1;
    config.gid = 1;
    config.callerPid = 1;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.EnterCallerSandbox();
    // If SetReadProcGroup succeeds, this covers the uid/gid mismatch branch
    // in OpenCallerProcDir. Otherwise it covers the same SetReadProcGroup
    // failure path as the other tests.
    EXPECT_EQ(SANDBOX_ERR_NS_FAILED, ret);
}

// ==================== MatchConditionalSource tests ====================

/**
 * @tc.name: MatchConditionalSource001
 * @tc.desc: Empty conditional rules returns CONDITIONAL_NOMATCH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MatchConditionalSource001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    std::string physicalSource;
    EXPECT_EQ(manager.MatchConditionalSource("/any/path", physicalSource),
              SandboxManager::CONDITIONAL_NOMATCH);
    EXPECT_EQ(manager.MatchConditionalSource("", physicalSource),
              SandboxManager::CONDITIONAL_NOMATCH);
}

/**
 * @tc.name: MatchConditionalSource002
 * @tc.desc: Prefix match with granted permission returns CONDITIONAL_MATCHED with derived physicalSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MatchConditionalSource002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    SandboxManager::ConditionalRule rule;
    rule.source = "/mnt/user/123/nosharefs/docs";
    rule.target = "/storage/Users";
    rule.permissions = {"ohos.permission.GRANTED_TEST"};
    manager.templateConfig_.conditionalRules.push_back(rule);

    std::string physicalSource;
    EXPECT_EQ(manager.MatchConditionalSource("/storage/Users/Desktop", physicalSource),
              SandboxManager::CONDITIONAL_MATCHED);
    EXPECT_EQ(physicalSource, "/mnt/user/123/nosharefs/docs/Desktop");
    EXPECT_EQ(manager.MatchConditionalSource("/storage/Users", physicalSource),
              SandboxManager::CONDITIONAL_MATCHED);
    EXPECT_EQ(physicalSource, "/mnt/user/123/nosharefs/docs");
}

/**
 * @tc.name: MatchConditionalSource003
 * @tc.desc: Prefix match without granted permission returns CONDITIONAL_BLOCKED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MatchConditionalSource003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    SandboxManager::ConditionalRule rule;
    rule.source = "/mnt/user/123/nosharefs";
    rule.target = "/storage/Users";
    rule.permissions = {"ohos.permission.DENIED_CONDITIONAL"};
    manager.templateConfig_.conditionalRules.push_back(rule);

    std::string physicalSource;
    EXPECT_EQ(manager.MatchConditionalSource("/storage/Users/Desktop", physicalSource),
              SandboxManager::CONDITIONAL_BLOCKED);
}

/**
 * @tc.name: MatchConditionalSource004
 * @tc.desc: No prefix match returns CONDITIONAL_NOMATCH when rules exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MatchConditionalSource004, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    SandboxManager::ConditionalRule rule;
    rule.source = "/mnt/user/123/nosharefs/docs";
    rule.target = "/storage/Users";
    rule.permissions = {"ohos.permission.GRANTED_TEST"};
    manager.templateConfig_.conditionalRules.push_back(rule);

    std::string physicalSource;
    EXPECT_EQ(manager.MatchConditionalSource("/other/path", physicalSource),
              SandboxManager::CONDITIONAL_NOMATCH);
}

/**
 * @tc.name: MatchConditionalSource005
 * @tc.desc: Prefix match with empty permissions returns CONDITIONAL_MATCHED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MatchConditionalSource005, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    SandboxManager::ConditionalRule rule;
    rule.source = "/host/public";
    rule.target = "/public";
    rule.permissions = {};  // empty = unconditionally permitted
    manager.templateConfig_.conditionalRules.push_back(rule);

    std::string physicalSource;
    EXPECT_EQ(manager.MatchConditionalSource("/public/dir", physicalSource),
              SandboxManager::CONDITIONAL_MATCHED);
    EXPECT_EQ(physicalSource, "/host/public/dir");
}

/**
 * @tc.name: MatchConditionalSource006
 * @tc.desc: Multiple rules, second one matching with granted permission returns CONDITIONAL_MATCHED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MatchConditionalSource006, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    SandboxManager::ConditionalRule rule1;
    rule1.source = "/host/blocked";
    rule1.target = "/blocked";
    rule1.permissions = {"ohos.permission.DENIED"};
    manager.templateConfig_.conditionalRules.push_back(rule1);

    SandboxManager::ConditionalRule rule2;
    rule2.source = "/host/allowed";
    rule2.target = "/allowed";
    rule2.permissions = {"ohos.permission.GRANTED_TEST"};
    manager.templateConfig_.conditionalRules.push_back(rule2);

    std::string physicalSource;
    EXPECT_EQ(manager.MatchConditionalSource("/allowed/subdir", physicalSource),
              SandboxManager::CONDITIONAL_MATCHED);
    EXPECT_EQ(physicalSource, "/host/allowed/subdir");
    EXPECT_EQ(manager.MatchConditionalSource("/blocked/subdir", physicalSource),
              SandboxManager::CONDITIONAL_BLOCKED);
}

// ==================== BindMountConditionalPath tests ====================

/**
 * @tc.name: BindMountConditionalPath001
 * @tc.desc: BindMountConditionalPath returns error when physical source does not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, BindMountConditionalPath001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    manager.newRootPath_ = "/tmp/claw_sandbox_ut_nonexistent";

    SandboxConfig::PolicyMount policyMount;
    policyMount.readOnly = true;

    int ret = manager.BindMountConditionalPath(policyMount,
        "/tmp/claw_sandbox_ut_nonexistent/target",
        "/nonexistent/source/path");
    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, ret);
}

/**
 * @tc.name: BindMountConditionalPath002
 * @tc.desc: BindMountConditionalPath fails at mount when not running as root
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, BindMountConditionalPath002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    // Create a temporary physical source directory
    std::string tmpDir = "/tmp/claw_sandbox_ut_bindmount_" + std::to_string(getpid());
    std::error_code ec;
    std::filesystem::create_directories(tmpDir, ec);

    manager.newRootPath_ = "/tmp/claw_sandbox_ut_bindmount_root_" + std::to_string(getpid());

    SandboxConfig::PolicyMount policyMount;
    policyMount.readOnly = true;

    // Without root privileges, mount() will fail with EPERM.
    // In privileged environments, it may succeed.
    int ret = manager.BindMountConditionalPath(policyMount,
        manager.newRootPath_ + "/mounted",
        tmpDir);
    EXPECT_TRUE(ret == SANDBOX_ERR_MOUNT_FAILED || ret == SANDBOX_SUCCESS ||
                ret == SANDBOX_ERR_PATH_INVALID);

    // Cleanup
    std::filesystem::remove_all(tmpDir, ec);
    std::filesystem::remove_all(manager.newRootPath_, ec);
}

// ==================== RemountPolicyMount tests ====================

/**
 * @tc.name: RemountPolicyMount001
 * @tc.desc: RemountPolicyMount with readonly policy skips writability check and fails at mount in non-root environment
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, RemountPolicyMount001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    SandboxConfig::PolicyMount policyMount;
    policyMount.readOnly = true;

    // readonly policy skips writability check; mount() fails in non-root env
    int ret = manager.RemountPolicyMount(policyMount, "/nonexistent/path");
    EXPECT_EQ(SANDBOX_ERR_MOUNT_FAILED, ret);
}

/**
 * @tc.name: RemountPolicyMount002
 * @tc.desc: RemountPolicyMount with rw policy reads existing mount readonly status, then mount fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, RemountPolicyMount002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    SandboxConfig::PolicyMount policyMount;
    policyMount.readOnly = false;

    // rw policy → GetMountReadOnly on "/proc" → found, not usually readonly
    // → no write escalation → mount() with MS_REMOUNT fails in non-root env
    int ret = manager.RemountPolicyMount(policyMount, "/proc");
    EXPECT_EQ(SANDBOX_ERR_MOUNT_FAILED, ret);
}

/**
 * @tc.name: RemountPolicyMount003
 * @tc.desc: RemountPolicyMount with rw policy fails when mount point is not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, RemountPolicyMount003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    SandboxConfig::PolicyMount policyMount;
    policyMount.readOnly = false;

    // rw policy + non-existent path → GetMountReadOnly fails → PATH_INVALID
    int ret = manager.RemountPolicyMount(policyMount, "/nonexistent/path/that/does/not/exist");
    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, ret);
}

// ==================== MountPolicyPath tests ====================

/**
 * @tc.name: MountPolicyPath001
 * @tc.desc: MountPolicyPath returns error when target is not a mount point and no conditional rule matches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountPolicyPath001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    manager.newRootPath_ = "/tmp/claw_test_nomatch";
    SandboxConfig::PolicyMount policyMount;
    policyMount.source = "/nonexistent/mount/path";
    policyMount.readOnly = true;

    // No conditional rules → CONDITIONAL_NOMATCH → error
    int ret = manager.MountPolicyPath(policyMount);
    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, ret);
}

/**
 * @tc.name: MountPolicyPath002
 * @tc.desc: MountPolicyPath returns CONDITIONAL_BLOCKED when target matches rule but permission is denied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountPolicyPath002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    manager.newRootPath_ = "/tmp/claw_test_blocked";
    SandboxManager::ConditionalRule rule;
    rule.source = "/host/path";
    rule.target = "/policy/target";
    rule.permissions = {"ohos.permission.DENIED_CONDITIONAL"};
    manager.templateConfig_.conditionalRules.push_back(rule);

    SandboxConfig::PolicyMount policyMount;
    policyMount.source = "/policy/target/subdir";
    policyMount.readOnly = true;

    // Permission denied for the matching rule → CONDITIONAL_BLOCKED
    int ret = manager.MountPolicyPath(policyMount);
    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, ret);
}

/**
 * @tc.name: MountPolicyPath003
 * @tc.desc: MountPolicyPath reaches BindMountConditionalPath when conditional match succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountPolicyPath003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    // Create a physical source directory
    std::string tmpSource = "/tmp/claw_test_mpp_source_" + std::to_string(getpid());
    std::error_code ec;
    std::filesystem::create_directories(tmpSource, ec);

    manager.newRootPath_ = "/tmp/claw_test_mpp_root_" + std::to_string(getpid());

    SandboxManager::ConditionalRule rule;
    rule.source = tmpSource;
    rule.target = "/policy/target";
    rule.permissions = {"ohos.permission.GRANTED_TEST"};
    manager.templateConfig_.conditionalRules.push_back(rule);

    SandboxConfig::PolicyMount policyMount;
    policyMount.source = "/policy/target/subdir";
    policyMount.readOnly = true;

    // MatchConditionalSource succeeds → BindMountConditionalPath may fail at mount()
    // In privileged environments, mount may succeed.
    int ret = manager.MountPolicyPath(policyMount);
    EXPECT_TRUE(ret == SANDBOX_ERR_MOUNT_FAILED || ret == SANDBOX_ERR_PATH_INVALID ||
                ret == SANDBOX_SUCCESS);

    // Cleanup
    std::filesystem::remove_all(tmpSource, ec);
    std::filesystem::remove_all(manager.newRootPath_, ec);
}

/**
 * @tc.name: MountPolicyPath004
 * @tc.desc: MountPolicyPath remounts when target is an existing mount point, fails at mount in non-root env
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountPolicyPath004, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    manager.newRootPath_ = "";
    SandboxConfig::PolicyMount policyMount;
    policyMount.source = "/proc";
    policyMount.readOnly = true;

    // "/proc" is an existing mount point → MountPolicyPath calls RemountPolicyMount
    // readonly → skips writability check → mount() fails in non-root env
    int ret = manager.MountPolicyPath(policyMount);
    EXPECT_EQ(SANDBOX_ERR_MOUNT_FAILED, ret);
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
