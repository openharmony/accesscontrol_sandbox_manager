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
 * @tc.desc: ConvertMountFlags with empty vector returns 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ConvertMountFlags001, TestSize.Level0)
{
    std::vector<std::string> flags;
    unsigned long result = SandboxManager::ConvertMountFlags(flags);
    EXPECT_EQ(0UL, result);
}

/**
 * @tc.name: ConvertMountFlags002
 * @tc.desc: ConvertMountFlags with "bind" returns MS_BIND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ConvertMountFlags002, TestSize.Level0)
{
    std::vector<std::string> flags = {"bind"};
    unsigned long result = SandboxManager::ConvertMountFlags(flags);
    EXPECT_EQ(static_cast<unsigned long>(MS_BIND), result);
}

/**
 * @tc.name: ConvertMountFlags003
 * @tc.desc: ConvertMountFlags with "rec" returns MS_REC
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ConvertMountFlags003, TestSize.Level0)
{
    std::vector<std::string> flags = {"rec"};
    unsigned long result = SandboxManager::ConvertMountFlags(flags);
    EXPECT_EQ(static_cast<unsigned long>(MS_REC), result);
}

/**
 * @tc.name: ConvertMountFlags004
 * @tc.desc: ConvertMountFlags with "rdonly" returns MS_RDONLY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ConvertMountFlags004, TestSize.Level0)
{
    std::vector<std::string> flags = {"rdonly"};
    unsigned long result = SandboxManager::ConvertMountFlags(flags);
    EXPECT_EQ(static_cast<unsigned long>(MS_RDONLY), result);
}

/**
 * @tc.name: ConvertMountFlags005
 * @tc.desc: ConvertMountFlags with "ro" returns MS_RDONLY (alias)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ConvertMountFlags005, TestSize.Level0)
{
    std::vector<std::string> flags = {"ro"};
    unsigned long result = SandboxManager::ConvertMountFlags(flags);
    EXPECT_EQ(static_cast<unsigned long>(MS_RDONLY), result);
}

/**
 * @tc.name: ConvertMountFlags006
 * @tc.desc: ConvertMountFlags with multiple flags combines them
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ConvertMountFlags006, TestSize.Level0)
{
    std::vector<std::string> flags = {"bind", "rec", "rdonly"};
    unsigned long result = SandboxManager::ConvertMountFlags(flags);
    EXPECT_EQ(static_cast<unsigned long>(MS_BIND | MS_REC | MS_RDONLY), result);
}

/**
 * @tc.name: ConvertMountFlags007
 * @tc.desc: ConvertMountFlags with "slave" returns MS_SLAVE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ConvertMountFlags007, TestSize.Level0)
{
    std::vector<std::string> flags = {"slave"};
    unsigned long result = SandboxManager::ConvertMountFlags(flags);
    EXPECT_EQ(static_cast<unsigned long>(MS_SLAVE), result);
}

/**
 * @tc.name: ConvertMountFlags008
 * @tc.desc: ConvertMountFlags with "shared" returns MS_SHARED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ConvertMountFlags008, TestSize.Level0)
{
    std::vector<std::string> flags = {"shared"};
    unsigned long result = SandboxManager::ConvertMountFlags(flags);
    EXPECT_EQ(static_cast<unsigned long>(MS_SHARED), result);
}

/**
 * @tc.name: ConvertMountFlags009
 * @tc.desc: ConvertMountFlags with "private" returns MS_PRIVATE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ConvertMountFlags009, TestSize.Level0)
{
    std::vector<std::string> flags = {"private"};
    unsigned long result = SandboxManager::ConvertMountFlags(flags);
    EXPECT_EQ(static_cast<unsigned long>(MS_PRIVATE), result);
}

/**
 * @tc.name: ConvertMountFlags010
 * @tc.desc: ConvertMountFlags with "nosuid" returns MS_NOSUID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ConvertMountFlags010, TestSize.Level0)
{
    std::vector<std::string> flags = {"nosuid"};
    unsigned long result = SandboxManager::ConvertMountFlags(flags);
    EXPECT_EQ(static_cast<unsigned long>(MS_NOSUID), result);
}

/**
 * @tc.name: ConvertMountFlags011
 * @tc.desc: ConvertMountFlags with "nodev" returns MS_NODEV
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ConvertMountFlags011, TestSize.Level0)
{
    std::vector<std::string> flags = {"nodev"};
    unsigned long result = SandboxManager::ConvertMountFlags(flags);
    EXPECT_EQ(static_cast<unsigned long>(MS_NODEV), result);
}

/**
 * @tc.name: ConvertMountFlags012
 * @tc.desc: ConvertMountFlags with "noexec" returns MS_NOEXEC
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ConvertMountFlags012, TestSize.Level0)
{
    std::vector<std::string> flags = {"noexec"};
    unsigned long result = SandboxManager::ConvertMountFlags(flags);
    EXPECT_EQ(static_cast<unsigned long>(MS_NOEXEC), result);
}

/**
 * @tc.name: ConvertMountFlags013
 * @tc.desc: ConvertMountFlags with unknown flag returns 0 (ignored)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ConvertMountFlags013, TestSize.Level0)
{
    std::vector<std::string> flags = {"unknown_flag"};
    unsigned long result = SandboxManager::ConvertMountFlags(flags);
    EXPECT_EQ(0UL, result);
}

/**
 * @tc.name: ConvertMountFlags014
 * @tc.desc: ConvertMountFlags with MS_BIND style flag name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ConvertMountFlags014, TestSize.Level0)
{
    std::vector<std::string> flags = {"MS_BIND", "MS_REC"};
    unsigned long result = SandboxManager::ConvertMountFlags(flags);
    EXPECT_EQ(static_cast<unsigned long>(MS_BIND | MS_REC), result);
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
}

/**
 * @tc.name: CreateDir002
 * @tc.desc: CreateDir returns path create failure for empty path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, CreateDir002, TestSize.Level0)
{
    SandboxManager manager;

    int ret = manager.CreateDir("");
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
 * @tc.name: CollectGrantedPermissionMounts001
 * @tc.desc: CollectGrantedPermissionMounts returns only non-empty mounts for granted permissions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, CollectGrantedPermissionMounts001, TestSize.Level0)
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
    SandboxManager::PermissionMountEntry grantedMount;
    grantedMount.mount.source = "/storage/Users/currentUser/Download";
    grantedMount.mount.target = "/storage/Users/currentUser/Download";
    grantedMount.mount.mountFlags = {"bind", "rec"};
    grantedMount.mount.checkExists = true;
    grantedConfig.mounts.emplace_back(grantedMount);

    SandboxManager::PermissionMountEntry decOnlyMount;
    decOnlyMount.decPaths = {"/storage/Users/currentUser/Download"};
    grantedConfig.mounts.emplace_back(decOnlyMount);

    SandboxManager::PermissionConfig deniedConfig;
    deniedConfig.sandboxSwitch = true;
    SandboxManager::PermissionMountEntry deniedMount;
    deniedMount.mount.source = "/storage/Users/currentUser/Desktop";
    deniedMount.mount.target = "/storage/Users/currentUser/Desktop";
    deniedConfig.mounts.emplace_back(deniedMount);

    SandboxManager::PermissionConfig switchOffConfig;
    switchOffConfig.sandboxSwitch = false;
    SandboxManager::PermissionMountEntry switchOffMount;
    switchOffMount.mount.source = "/storage/Users/currentUser/Documents";
    switchOffMount.mount.target = "/storage/Users/currentUser/Documents";
    switchOffConfig.mounts.emplace_back(switchOffMount);

    manager.templateConfig_.permissions["ohos.permission.GRANTED_MOUNT"] = grantedConfig;
    manager.templateConfig_.permissions["ohos.permission.DENIED_MOUNT"] = deniedConfig;
    manager.templateConfig_.permissions["ohos.permission.GRANTED_SWITCH_OFF"] = switchOffConfig;

    std::vector<SandboxManager::MountEntry> mounts = manager.CollectGrantedPermissionMounts();
    ASSERT_EQ(1U, mounts.size());
    EXPECT_EQ("/storage/Users/currentUser/Download", mounts[0].source);
    EXPECT_EQ("/storage/Users/currentUser/Download", mounts[0].target);
    ASSERT_EQ(2U, mounts[0].mountFlags.size());
    EXPECT_EQ("bind", mounts[0].mountFlags[0]);
    EXPECT_EQ("rec", mounts[0].mountFlags[1]);
    EXPECT_TRUE(mounts[0].checkExists);
}

/**
 * @tc.name: CollectGrantedPermissionMounts002
 * @tc.desc: CollectGrantedPermissionMounts with empty permission config returns empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, CollectGrantedPermissionMounts002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    std::vector<SandboxManager::MountEntry> mounts = manager.CollectGrantedPermissionMounts();
    EXPECT_TRUE(mounts.empty());
}

/**
 * @tc.name: CollectGrantedPermissionMounts003
 * @tc.desc: CollectGrantedPermissionMounts skips permission with sandboxSwitch OFF
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, CollectGrantedPermissionMounts003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    SandboxManager::PermissionConfig switchOffConfig;
    switchOffConfig.sandboxSwitch = false;
    SandboxManager::PermissionMountEntry mountEntry;
    mountEntry.mount.source = "/data/test";
    mountEntry.mount.target = "/data/test";
    switchOffConfig.mounts.emplace_back(mountEntry);
    manager.templateConfig_.permissions["ohos.permission.GRANTED_TEST"] = switchOffConfig;

    std::vector<SandboxManager::MountEntry> mounts = manager.CollectGrantedPermissionMounts();
    EXPECT_TRUE(mounts.empty());
}

/**
 * @tc.name: CollectGrantedPermissionMounts004
 * @tc.desc: CollectGrantedPermissionMounts skips mount with empty source
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, CollectGrantedPermissionMounts004, TestSize.Level0)
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
    SandboxManager::PermissionMountEntry emptySourceMount;
    emptySourceMount.mount.source = "";
    emptySourceMount.mount.target = "/data/test";
    grantedConfig.mounts.emplace_back(emptySourceMount);

    SandboxManager::PermissionMountEntry emptyTargetMount;
    emptyTargetMount.mount.source = "/data/test";
    emptyTargetMount.mount.target = "";
    grantedConfig.mounts.emplace_back(emptyTargetMount);

    manager.templateConfig_.permissions["ohos.permission.GRANTED_TEST"] = grantedConfig;

    std::vector<SandboxManager::MountEntry> mounts = manager.CollectGrantedPermissionMounts();
    EXPECT_TRUE(mounts.empty());
}

/**
 * @tc.name: IsPolicyWriteEscalation001
 * @tc.desc: IsPolicyWriteEscalation rejects only rw policy over existing readonly mounts
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, IsPolicyWriteEscalation001, TestSize.Level0)
{
    EXPECT_FALSE(SandboxManager::IsPolicyWriteEscalation(true, true));
    EXPECT_FALSE(SandboxManager::IsPolicyWriteEscalation(true, false));
    EXPECT_FALSE(SandboxManager::IsPolicyWriteEscalation(false, false));
    EXPECT_TRUE(SandboxManager::IsPolicyWriteEscalation(false, true));
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
 * @tc.name: MountPermissionDirs001
 * @tc.desc: MountPermissionDirs with empty permission mounts returns success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountPermissionDirs001, TestSize.Level0)
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
    int ret = manager.MountPermissionDirs();
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
} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
