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
#include "sandbox_test_privileged.h"
#include "sandbox_mock_state.h"
#include <sys/mount.h>
#include <sys/syscall.h>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <utility>
#include <vector>

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

static constexpr uint64_t TEST_HAP_TOKEN_ID = TEST_TOKEN_ID_HIGH_BIT | 0x200D000D;

/*
 * A directory this test can actually create in.
 *
 * Probed rather than assumed: /tmp is not writable in every environment this
 * suite runs in, and a hard coded path turns an environment problem into a
 * confusing assertion failure somewhere else.
 */
static std::string MakeTempRoot(const std::string &tag)
{
    const char *candidates[] = {getenv("TMPDIR"), "/data/local/tmp", "/data", "/tmp", "."};
    for (const char *dir : candidates) {
        if (dir == nullptr || dir[0] == '\0') {
            continue;
        }
        std::string path = std::string(dir) + "/claw_" + tag + "_" + std::to_string(getpid());
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
        if (std::filesystem::create_directories(path, ec)) {
            return path;
        }
    }
    return "";
}

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

    // Creating it again is not an error: every component already exists.
    ret = manager.CreateDir(guard.RootPath() + "/nested");
    EXPECT_EQ(SANDBOX_SUCCESS, ret);

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
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.CreateNewRoot();
    if (ret == SANDBOX_SUCCESS) {
        guard.TrackCreatedRoot(manager.newRootPath_);
        EXPECT_TRUE(SandboxDirGuard::Exists(manager.newRootPath_));
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
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.CreateNewRoot();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(guard.RootPath(), manager.newRootPath_);
    EXPECT_TRUE(SandboxDirGuard::Exists(guard.RootPath()));
    // The sandbox root is the view root itself: CreateNewRoot stages nothing
    // inside it.
    EXPECT_EQ(guard.RootPath(), manager.GetMountRootPath());
    std::error_code ec;
    EXPECT_TRUE(std::filesystem::is_empty(guard.RootPath(), ec));
}

/**
 * @tc.name: GetMountRootPath001
 * @tc.desc: Mounts attach under the sandbox root, and an unset root is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, GetMountRootPath001, TestSize.Level0)
{
    SandboxManager manager;
    manager.newRootPath_ = "/tmp/claw_root";
    EXPECT_EQ("/tmp/claw_root", manager.GetMountRootPath());

    manager.newRootPath_.clear();
    EXPECT_TRUE(manager.GetMountRootPath().empty());
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
    manager.Initialize(std::move(config), cmdInfo);

    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.UnshareNamespaces(); }, ret));
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_NS_FAILED);
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
    manager.Initialize(std::move(config), cmdInfo);

    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.MountNewRoot(); }, ret));
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
    manager.Initialize(std::move(config), cmdInfo);

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
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.MountProcFs();
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_MOUNT_FAILED);
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
    manager.Initialize(std::move(config), cmdInfo);

    std::vector<std::string> flags = {"bind"};
    int ret = manager.MountDir("/nonexistent_source_xyz", "/test_target", flags);
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_MOUNT_FAILED || ret == SANDBOX_ERR_PATH_CREATE_FAILED);
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
    manager.mountTargets_.push_back("/nonexistent_mount");
    manager.newRootPath_ = "/tmp/test_root";

    // pivotRootDone_ == true ⇒ skip all cleanup
    manager.Cleanup();

    EXPECT_TRUE(manager.pivotRootDone_);
    EXPECT_FALSE(manager.mountTargets_.empty());
    EXPECT_FALSE(manager.newRootPath_.empty());
}

/**
 * @tc.name: Cleanup002
 * @tc.desc: Cleanup without pivotRootDone_ clears mountTargets_ and paths
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, Cleanup002, TestSize.Level0)
{
    SandboxManager manager;
    manager.pivotRootDone_ = false;
    manager.mountTargets_.push_back("/nonexistent_mount");
    manager.newRootPath_ = "/nonexistent_root";

    manager.Cleanup();

    EXPECT_FALSE(manager.pivotRootDone_);
    EXPECT_TRUE(manager.mountTargets_.empty());
    EXPECT_TRUE(manager.newRootPath_.empty());
}

/**
 * @tc.name: Cleanup003
 * @tc.desc: Cleanup recursively removes an owned sandbox root, including
 *           directories and symlinks that rmdir could not remove
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, Cleanup003, TestSize.Level0)
{
    SandboxDirGuard guard("cleanup_recursive");
    ASSERT_TRUE(guard.MountRootExists());

    SandboxManager manager;
    manager.newRootPath_ = guard.RootPath();

    std::error_code ec;
    ASSERT_TRUE(std::filesystem::create_directories(guard.RootPath() + "/system/bin", ec));
    ASSERT_EQ(0, symlink("/system/bin", (guard.RootPath() + "/bin").c_str()));

    manager.Cleanup();

    EXPECT_FALSE(std::filesystem::exists(guard.RootPath(), ec));
    EXPECT_TRUE(manager.newRootPath_.empty());
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
    manager.Initialize(std::move(config), cmdInfo);

    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.EnterCallerSandbox(); }, ret));
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
    manager.Initialize(std::move(config), cmdInfo);

    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.EnterCallerSandbox(); }, ret));
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
    manager.Initialize(std::move(config), cmdInfo);

    int ret = 0;
    ASSERT_TRUE(RunPrivilegedStepInChild([&manager]() { return manager.EnterCallerSandbox(); }, ret));
    // If SetReadProcGroup succeeds, this covers the uid/gid mismatch branch
    // in OpenCallerProcDir. Otherwise it covers the same SetReadProcGroup
    // failure path as the other tests.
    EXPECT_EQ(SANDBOX_ERR_NS_FAILED, ret);
}

// ==================== unified mount plan tests ====================

/**
 * @tc.name: MountPlanBuildsAllOrigins001
 * @tc.desc: The plan collects system binds, app binds and policy binds, sorted
 *           by origin and target depth; template symlinks are not plan entries
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountPlanBuildsAllOrigins001, TestSize.Level0)
{
    SandboxManager manager;
    manager.templateConfig_.systemMounts = {{"/sys", "/sys", {"bind", "rec"}, true}};
    manager.templateConfig_.appMounts = {{"/data/x", "/data/x", {"bind", "rec"}, true}};
    manager.templateConfig_.symLinks = {{"/system/bin", "/bin"}};
    manager.config_.policy.mounts = {{"/data/y", SandboxConfig::PolicyMountMode::NONE}};

    ASSERT_EQ(SANDBOX_SUCCESS, manager.PrepareMountPlan());
    ASSERT_EQ(3U, manager.mountPlan_.size());

    EXPECT_EQ(SandboxManager::MountOrigin::SYSTEM, manager.mountPlan_[0].origin);
    EXPECT_EQ("/sys", manager.mountPlan_[0].target);

    EXPECT_EQ(SandboxManager::MountOrigin::APP, manager.mountPlan_[1].origin);
    EXPECT_EQ("/data/x", manager.mountPlan_[1].target);

    EXPECT_EQ(SandboxManager::MountOrigin::POLICY, manager.mountPlan_[2].origin);
    EXPECT_EQ("/data/y", manager.mountPlan_[2].target);
}

/**
 * @tc.name: MountPlanKeepsSelfBinds001
 * @tc.desc: A "/" bind and template self-binds are ordinary ops. Nothing is
 *           pruned: "/" sorts first and each child stacks on the host view
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountPlanKeepsSelfBinds001, TestSize.Level0)
{
    SandboxManager manager;
    manager.templateConfig_.systemMounts = {
        {"/", "/", {"bind", "rec"}, true},
        {"/dev", "/dev", {"bind", "rec"}, true},
        {"/data", "/mnt/data", {"bind", "rec"}, true},
        {"/sys", "/sys", {"bind", "rec", "rdonly"}, true},
    };

    ASSERT_EQ(SANDBOX_SUCCESS, manager.PrepareMountPlan());

    ASSERT_EQ(4U, manager.mountPlan_.size());
    // "/" is depth 0; /dev and /sys are depth 1 in sequence order; /mnt/data
    // is depth 2.
    EXPECT_EQ("/", manager.mountPlan_[0].target);
    EXPECT_EQ("/dev", manager.mountPlan_[1].target);
    EXPECT_EQ("/sys", manager.mountPlan_[2].target);
    EXPECT_EQ("/mnt/data", manager.mountPlan_[3].target);
    for (const auto &op : manager.mountPlan_) {
        EXPECT_EQ(SandboxManager::MountOrigin::SYSTEM, op.origin);
    }
}

/**
 * @tc.name: MountPlanRootBindFromPolicy001
 * @tc.desc: Template and policy "/" address the same target, so the policy bind
 *           replaces the template one; only the policy "/" remains, at depth 0
 *           before any child mount is attached
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountPlanRootBindFromPolicy001, TestSize.Level0)
{
    SandboxManager manager;
    manager.templateConfig_.systemMounts = {
        {"/", "/", {"bind", "rec"}, true},
        {"/dev", "/dev", {"bind", "rec"}, true},
    };
    manager.config_.policy.mounts = {
        {"/data", SandboxConfig::PolicyMountMode::NONE},
        {"/", SandboxConfig::PolicyMountMode::RO},
    };

    ASSERT_EQ(SANDBOX_SUCCESS, manager.PrepareMountPlan());
    ASSERT_EQ(3U, manager.mountPlan_.size());
    // The policy "/" replaced the template "/" and is the only depth-0 op.
    // Depth 1 follows, SYSTEM before POLICY.
    EXPECT_EQ("/", manager.mountPlan_[0].target);
    EXPECT_EQ(SandboxManager::MountOrigin::POLICY, manager.mountPlan_[0].origin);
    EXPECT_EQ(SandboxConfig::PolicyMountMode::RO, manager.mountPlan_[0].mode);
    EXPECT_EQ("/dev", manager.mountPlan_[1].target);
    EXPECT_EQ(SandboxManager::MountOrigin::SYSTEM, manager.mountPlan_[1].origin);
    EXPECT_EQ("/data", manager.mountPlan_[2].target);
    EXPECT_EQ(SandboxManager::MountOrigin::POLICY, manager.mountPlan_[2].origin);
}

/**
 * @tc.name: MountPlanPolicyOverridesTemplate001
 * @tc.desc: A policy bind at the same target as a template bind replaces it, so
 *           only the policy op remains; the template symlink is not a plan entry
 *           at all
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountPlanPolicyOverridesTemplate001, TestSize.Level0)
{
    SandboxManager manager;
    manager.templateConfig_.systemMounts = {{"/data/x", "/data/x", {"bind", "rec"}, true}};
    manager.templateConfig_.symLinks = {{"/system/bin", "/bin"}};
    manager.config_.policy.mounts = {
        {"/data/x", SandboxConfig::PolicyMountMode::RO},
        {"/bin", SandboxConfig::PolicyMountMode::NONE},
    };

    ASSERT_EQ(SANDBOX_SUCCESS, manager.PrepareMountPlan());
    ASSERT_EQ(2U, manager.mountPlan_.size());
    EXPECT_EQ("/bin", manager.mountPlan_[0].target);
    EXPECT_EQ(SandboxManager::MountOrigin::POLICY, manager.mountPlan_[0].origin);
    EXPECT_EQ("/data/x", manager.mountPlan_[1].target);
    EXPECT_EQ(SandboxManager::MountOrigin::POLICY, manager.mountPlan_[1].origin);
    EXPECT_EQ(SandboxConfig::PolicyMountMode::RO, manager.mountPlan_[1].mode);
}

/**
 * @tc.name: MountPlanSortOrder001
 * @tc.desc: Parents mount before children whichever origin owns them, so a
 *           policy bind above a template bind attaches first; equal depth
 *           keeps SYSTEM, APP, POLICY order
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountPlanSortOrder001, TestSize.Level0)
{
    SandboxManager manager;
    manager.templateConfig_.systemMounts = {
        {"/a/b/c", "/a/b/c", {"bind", "rec"}, true},
        {"/s", "/s", {"bind", "rec"}, true},
    };
    manager.templateConfig_.appMounts = {{"/a/x", "/a/x", {"bind", "rec"}, true}};
    manager.config_.policy.mounts = {{"/a", SandboxConfig::PolicyMountMode::NONE}};

    ASSERT_EQ(SANDBOX_SUCCESS, manager.PrepareMountPlan());
    ASSERT_EQ(4U, manager.mountPlan_.size());
    // Depth 1: system before policy within the same depth.
    EXPECT_EQ(SandboxManager::MountOrigin::SYSTEM, manager.mountPlan_[0].origin);
    EXPECT_EQ("/s", manager.mountPlan_[0].target);
    EXPECT_EQ(SandboxManager::MountOrigin::POLICY, manager.mountPlan_[1].origin);
    EXPECT_EQ("/a", manager.mountPlan_[1].target);
    // Depth 2, then depth 3.
    EXPECT_EQ(SandboxManager::MountOrigin::APP, manager.mountPlan_[2].origin);
    EXPECT_EQ("/a/x", manager.mountPlan_[2].target);
    EXPECT_EQ(SandboxManager::MountOrigin::SYSTEM, manager.mountPlan_[3].origin);
    EXPECT_EQ("/a/b/c", manager.mountPlan_[3].target);
}

/**
 * @tc.name: MountPlanPolicyOverridesTemplateTarget001
 * @tc.desc: A policy bind replaces a template bind at the same target rather
 *           than stacking on it; symlinks are not plan entries
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountPlanPolicyOverridesTemplateTarget001, TestSize.Level0)
{
    SandboxManager manager;
    manager.templateConfig_.systemMounts = {{"/a", "/x", {"bind"}, true}};
    manager.config_.policy.mounts = {{"/x", SandboxConfig::PolicyMountMode::NONE}};
    ASSERT_EQ(SANDBOX_SUCCESS, manager.PrepareMountPlan());
    ASSERT_EQ(1U, manager.mountPlan_.size());
    EXPECT_EQ(SandboxManager::MountOrigin::POLICY, manager.mountPlan_[0].origin);

    manager.templateConfig_.systemMounts.clear();
    manager.config_.policy.mounts.clear();
    manager.templateConfig_.symLinks = {
        {"/system/bin", "/bin"},
        {"/system/lib", "/bin"},
    };
    ASSERT_EQ(SANDBOX_SUCCESS, manager.PrepareMountPlan());
    EXPECT_TRUE(manager.mountPlan_.empty());
}

/**
 * @tc.name: MountPlanRejectsInvalidTemplateMount001
 * @tc.desc: Unknown flags, non-bind entries, and non-canonical paths are
 *           rejected before anything is created
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountPlanRejectsInvalidTemplateMount001, TestSize.Level0)
{
    SandboxManager manager;
    manager.templateConfig_.systemMounts = {{"/a", "/a", {"bind", "bogus"}, true}};
    EXPECT_EQ(SANDBOX_ERR_TEMPLATE_INVALID, manager.PrepareMountPlan());

    manager.templateConfig_.systemMounts = {{"/a", "/a", {"rec"}, true}};
    EXPECT_EQ(SANDBOX_ERR_TEMPLATE_INVALID, manager.PrepareMountPlan());

    manager.templateConfig_.systemMounts = {{"/a", "/a", {"bind", "remount"}, true}};
    EXPECT_EQ(SANDBOX_ERR_TEMPLATE_INVALID, manager.PrepareMountPlan());

    manager.templateConfig_.systemMounts = {{"/a", "relative", {"bind"}, true}};
    EXPECT_EQ(SANDBOX_ERR_TEMPLATE_INVALID, manager.PrepareMountPlan());

    manager.templateConfig_.systemMounts = {{"relative", "/a", {"bind"}, true}};
    EXPECT_EQ(SANDBOX_ERR_TEMPLATE_INVALID, manager.PrepareMountPlan());
}

/**
 * @tc.name: MountPlanAllowsTemplateRootBind001
 * @tc.desc: A "/" target is an ordinary target: any source may carry the
 *           whole view, and the op still sorts first
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountPlanAllowsTemplateRootBind001, TestSize.Level0)
{
    SandboxManager manager;
    manager.templateConfig_.systemMounts = {
        {"/data/root", "/", {"bind", "rec"}, true},
        {"/dev", "/dev", {"bind", "rec"}, true},
    };

    ASSERT_EQ(SANDBOX_SUCCESS, manager.PrepareMountPlan());
    ASSERT_EQ(2U, manager.mountPlan_.size());
    EXPECT_EQ("/", manager.mountPlan_[0].target);
    EXPECT_EQ("/data/root", manager.mountPlan_[0].source);
    EXPECT_EQ("/dev", manager.mountPlan_[1].target);
}

/**
 * @tc.name: MountPlanRejectsPolicyConflicts001
 * @tc.desc: Policy targets must be canonical and unique; symbol links are not
 *           plan entries and are not compared against policy targets, so a
 *           policy above or below a link path is accepted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountPlanRejectsPolicyConflicts001, TestSize.Level0)
{
    SandboxManager manager;
    manager.templateConfig_.symLinks = {{"/system/bin", "/usr/bin"}};

    // The link is not part of the plan; only the policy bind is.
    manager.config_.policy.mounts = {{"/usr", SandboxConfig::PolicyMountMode::NONE}};
    ASSERT_EQ(SANDBOX_SUCCESS, manager.PrepareMountPlan());
    ASSERT_EQ(1U, manager.mountPlan_.size());
    EXPECT_EQ("/usr", manager.mountPlan_[0].target);

    manager.config_.policy.mounts = {{"/usr/bin/tool", SandboxConfig::PolicyMountMode::NONE}};
    ASSERT_EQ(SANDBOX_SUCCESS, manager.PrepareMountPlan());
    ASSERT_EQ(1U, manager.mountPlan_.size());
    EXPECT_EQ("/usr/bin/tool", manager.mountPlan_[0].target);

    // A policy bind above a template bind is allowed: it is mounted first and
    // the template bind stacks on top of it.
    manager.templateConfig_.symLinks.clear();
    manager.templateConfig_.systemMounts = {{"/a/b", "/a/b", {"bind", "rec"}, true}};
    manager.config_.policy.mounts = {{"/a", SandboxConfig::PolicyMountMode::NONE}};
    ASSERT_EQ(SANDBOX_SUCCESS, manager.PrepareMountPlan());
    ASSERT_EQ(2U, manager.mountPlan_.size());
    EXPECT_EQ(SandboxManager::MountOrigin::POLICY, manager.mountPlan_[0].origin);
    EXPECT_EQ("/a", manager.mountPlan_[0].target);
    EXPECT_EQ(SandboxManager::MountOrigin::SYSTEM, manager.mountPlan_[1].origin);
    EXPECT_EQ("/a/b", manager.mountPlan_[1].target);

    // Below a template bind is fine too: parents always mount first.
    manager.config_.policy.mounts = {{"/a/b/c", SandboxConfig::PolicyMountMode::NONE}};
    EXPECT_EQ(SANDBOX_SUCCESS, manager.PrepareMountPlan());
    manager.templateConfig_.systemMounts.clear();
    manager.templateConfig_.symLinks = {{"/system/bin", "/usr/bin"}};

    // The policy owns the exact link path: the link is still not a plan entry,
    // and the mount wins when the link pass runs.
    manager.config_.policy.mounts = {{"/usr/bin", SandboxConfig::PolicyMountMode::NONE}};
    EXPECT_EQ(SANDBOX_SUCCESS, manager.PrepareMountPlan());
    ASSERT_EQ(1U, manager.mountPlan_.size());
    EXPECT_EQ(SandboxManager::MountOrigin::POLICY, manager.mountPlan_[0].origin);

    manager.config_.policy.mounts = {
        {"/data", SandboxConfig::PolicyMountMode::NONE},
        {"/data", SandboxConfig::PolicyMountMode::RO},
    };
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, manager.PrepareMountPlan());

    manager.config_.policy.mounts = {{"/data/", SandboxConfig::PolicyMountMode::NONE}};
    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, manager.PrepareMountPlan());

    // "/" is legal: it is an ordinary bind onto the sandbox root, and the mode
    // is applied to that mount.
    manager.config_.policy.mounts = {{"/", SandboxConfig::PolicyMountMode::NONE}};
    ASSERT_EQ(SANDBOX_SUCCESS, manager.PrepareMountPlan());
    ASSERT_EQ(1U, manager.mountPlan_.size());
    EXPECT_EQ(SandboxManager::MountOrigin::POLICY, manager.mountPlan_[0].origin);
    EXPECT_EQ("/", manager.mountPlan_[0].target);
}

// ==================== symlink execution ====================

/**
 * @tc.name: CreateTemplateSymlinksFailsMissingViewSource001
 * @tc.desc: A source missing from the sandbox view fails the link pass instead
 *           of silently leaving the link out
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, CreateTemplateSymlinksFailsMissingViewSource001, TestSize.Level0)
{
    std::string root = MakeTempRoot("symlink_empty_root");
    ASSERT_FALSE(root.empty());

    SandboxManager manager;
    manager.newRootPath_ = root;
    manager.templateConfig_.symLinks = {{"/dev", "/dev_link"}};

    ASSERT_NE(0, access((root + "/dev").c_str(), F_OK));

    EXPECT_EQ(SANDBOX_ERR_SYMLINK_FAILED, manager.CreateTemplateSymlinks());

    struct stat st = {};
    EXPECT_NE(0, lstat((root + "/dev_link").c_str(), &st));

    std::error_code ec;
    std::filesystem::remove_all(root, ec);
}

/**
 * @tc.name: CreateTemplateSymlinksCreatesLink001
 * @tc.desc: Once the view has the source, the link is created
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, CreateTemplateSymlinksCreatesLink001, TestSize.Level0)
{
    std::string root = MakeTempRoot("symlink_ready_root");
    ASSERT_FALSE(root.empty());

    SandboxManager manager;
    manager.newRootPath_ = root;
    manager.templateConfig_.symLinks = {{"/dev", "/dev_link"}};

    std::error_code ec;
    ASSERT_TRUE(std::filesystem::create_directories(root + "/dev", ec));

    EXPECT_EQ(SANDBOX_SUCCESS, manager.CreateTemplateSymlinks());

    struct stat st = {};
    ASSERT_EQ(0, lstat((root + "/dev_link").c_str(), &st));
    EXPECT_TRUE(S_ISLNK(st.st_mode));
    char linkTarget[64] = {0};
    ASSERT_GT(readlink((root + "/dev_link").c_str(), linkTarget, sizeof(linkTarget) - 1), 0);
    EXPECT_STREQ("/dev", linkTarget);

    std::filesystem::remove_all(root, ec);
}

/**
 * @tc.name: CreateTemplateSymlinksHandlesExistingPath001
 * @tc.desc: Whatever already occupies a link path wins, so an existing path is
 *           skipped without requiring the source
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, CreateTemplateSymlinksHandlesExistingPath001, TestSize.Level0)
{
    std::string root = MakeTempRoot("symlink_existing_root");
    ASSERT_FALSE(root.empty());

    SandboxManager manager;
    manager.newRootPath_ = root;
    manager.templateConfig_.symLinks = {{"/system/missing", "/bin"}};

    std::error_code ec;
    ASSERT_TRUE(std::filesystem::create_directories(root + "/bin", ec));
    ASSERT_NE(0, access((root + "/system/missing").c_str(), F_OK));

    EXPECT_EQ(SANDBOX_SUCCESS, manager.CreateTemplateSymlinks());

    struct stat st = {};
    EXPECT_EQ(0, lstat((root + "/bin").c_str(), &st));
    EXPECT_TRUE(S_ISDIR(st.st_mode));

    std::filesystem::remove_all(root, ec);
}

/**
 * @tc.name: CreateTemplateSymlinksValidatesPaths001
 * @tc.desc: Symbol-link paths are validated when the link pass runs, after the
 *           mounts, rather than during plan preparation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, CreateTemplateSymlinksValidatesPaths001, TestSize.Level0)
{
    std::string root = MakeTempRoot("symlink_invalid_root");
    ASSERT_FALSE(root.empty());

    SandboxManager manager;
    manager.newRootPath_ = root;

    manager.templateConfig_.symLinks = {{"relative", "/bin"}};
    EXPECT_EQ(SANDBOX_ERR_TEMPLATE_INVALID, manager.CreateTemplateSymlinks());

    manager.templateConfig_.symLinks = {{"/system/bin", "relative"}};
    EXPECT_EQ(SANDBOX_ERR_TEMPLATE_INVALID, manager.CreateTemplateSymlinks());

    manager.templateConfig_.symLinks = {{"/system/bin", "/"}};
    EXPECT_EQ(SANDBOX_ERR_TEMPLATE_INVALID, manager.CreateTemplateSymlinks());

    std::error_code ec;
    std::filesystem::remove_all(root, ec);
}

// ==================== policy bind execution ====================

/**
 * @tc.name: ExecuteBindOpRejectsTargetSymlink001
 * @tc.desc: A policy target whose leaf is a symlink is rejected rather than followed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ExecuteBindOpRejectsTargetSymlink001, TestSize.Level0)
{
    std::string root = MakeTempRoot("policy_target_symlink");
    ASSERT_FALSE(root.empty());

    SandboxManager manager;
    manager.newRootPath_ = root;

    std::error_code ec;
    ASSERT_TRUE(std::filesystem::create_directories(root + "/real", ec));
    ASSERT_EQ(0, symlink((root + "/real").c_str(), (root + "/dev").c_str()));
    ASSERT_TRUE(std::filesystem::is_directory("/dev"));

    SandboxManager::MountOp op;
    op.origin = SandboxManager::MountOrigin::POLICY;
    op.source = "/dev";
    op.target = "/dev";
    op.mode = SandboxConfig::PolicyMountMode::RO;

    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, manager.ExecuteBindOp(op));
    EXPECT_FALSE(std::filesystem::exists(root + "/real/child", ec));

    std::filesystem::remove_all(root, ec);
}

/**
 * @tc.name: ExecuteBindOpRejectsMissingSource001
 * @tc.desc: A policy bind fails when the canonical target has no host source
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ExecuteBindOpRejectsMissingSource001, TestSize.Level0)
{
    std::string root = MakeTempRoot("policy_missing_source");
    ASSERT_FALSE(root.empty());

    SandboxManager manager;
    manager.newRootPath_ = root;

    SandboxManager::MountOp op;
    op.origin = SandboxManager::MountOrigin::POLICY;
    op.source = "/nonexistent/policy/source/for/unit/test";
    op.target = op.source;
    op.mode = SandboxConfig::PolicyMountMode::RO;

    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, manager.ExecuteBindOp(op));

    std::error_code ec;
    std::filesystem::remove_all(root, ec);
}

/**
 * @tc.name: ExecuteBindOpNonDirectorySource001
 * @tc.desc: A FIFO is a valid policy source, like any other non-directory inode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ExecuteBindOpNonDirectorySource001, TestSize.Level0)
{
    std::string root = MakeTempRoot("policy_fifo");
    ASSERT_FALSE(root.empty());

    SandboxManager manager;
    manager.newRootPath_ = root;

    const std::string fifoPath = root + "/fifo_source";
    ASSERT_EQ(0, mkfifo(fifoPath.c_str(), 0600));

    SandboxManager::MountOp op;
    op.origin = SandboxManager::MountOrigin::POLICY;
    op.source = fifoPath;
    op.target = fifoPath;
    op.mode = SandboxConfig::PolicyMountMode::NONE;
    const std::string mountTarget = root + fifoPath;

    int ret = manager.ExecuteBindOp(op);
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_MOUNT_FAILED) << ret;
    ASSERT_TRUE(std::filesystem::exists(mountTarget));

    if (ret == SANDBOX_SUCCESS) {
        EXPECT_TRUE(std::filesystem::is_fifo(mountTarget));
        EXPECT_EQ(0, umount2(mountTarget.c_str(), MNT_DETACH));
    } else {
        // The mount never happened, so the placeholder is still a regular file.
        EXPECT_TRUE(std::filesystem::is_regular_file(mountTarget));
    }

    std::error_code ec;
    std::filesystem::remove_all(root, ec);
}

/**
 * @tc.name: ExecuteBindOpFileTarget001
 * @tc.desc: A regular-file policy mount creates a regular-file target
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ExecuteBindOpFileTarget001, TestSize.Level0)
{
    std::string root = MakeTempRoot("policy_file_target");
    ASSERT_FALSE(root.empty());
    std::string sourceRoot = MakeTempRoot("policy_file_source");
    ASSERT_FALSE(sourceRoot.empty());

    const std::string sourceFile = sourceRoot + "/payload";
    {
        std::ofstream out(sourceFile);
        ASSERT_TRUE(out.is_open());
        out << "policy file target";
    }
    ASSERT_TRUE(std::filesystem::is_regular_file(sourceFile));

    SandboxManager manager;
    manager.newRootPath_ = root;

    SandboxManager::MountOp op;
    op.origin = SandboxManager::MountOrigin::POLICY;
    op.source = sourceFile;
    op.target = sourceFile;
    op.mode = SandboxConfig::PolicyMountMode::NONE;
    const std::string mountTarget = root + sourceFile;

    int ret = manager.ExecuteBindOp(op);
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_MOUNT_FAILED) << ret;
    EXPECT_TRUE(std::filesystem::is_regular_file(mountTarget));

    if (ret == SANDBOX_SUCCESS) {
        umount2(mountTarget.c_str(), MNT_DETACH);
    }

    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::remove_all(sourceRoot, ec);
}

/**
 * @tc.name: ExecuteBindOpUsesSandboxRoot001
 * @tc.desc: A policy mount is attached under the sandbox root returned by
 *           GetMountRootPath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ExecuteBindOpUsesSandboxRoot001, TestSize.Level0)
{
    std::string root = MakeTempRoot("policy_sandbox_root");
    ASSERT_FALSE(root.empty());
    std::string sourceRoot = MakeTempRoot("policy_sandbox_root_source");
    ASSERT_FALSE(sourceRoot.empty());

    SandboxManager manager;
    manager.newRootPath_ = root;

    SandboxManager::MountOp op;
    op.origin = SandboxManager::MountOrigin::POLICY;
    op.source = sourceRoot;
    op.target = sourceRoot;
    op.mode = SandboxConfig::PolicyMountMode::NONE;
    const std::string mountTarget = root + sourceRoot;

    int ret = manager.ExecuteBindOp(op);
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_MOUNT_FAILED) << ret;
    ASSERT_TRUE(std::filesystem::exists(mountTarget));

    std::error_code ec;

    if (ret == SANDBOX_SUCCESS) {
        EXPECT_EQ(0, umount2(mountTarget.c_str(), MNT_DETACH));
    }

    std::filesystem::remove_all(root, ec);
    std::filesystem::remove_all(sourceRoot, ec);
}

// ==================== plan and bind validation branches ====================

/**
 * @tc.name: MountPlanSkipsPolicyProc001
 * @tc.desc: Policy mounts at /proc or under it are platform-provided and skipped;
 *           a lookalike path such as /procfoo is not
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountPlanSkipsPolicyProc001, TestSize.Level0)
{
    SandboxManager manager;
    manager.templateConfig_.systemMounts = {{"/sys", "/sys", {"bind", "rec"}, true}};
    manager.config_.policy.mounts = {
        {"/proc", SandboxConfig::PolicyMountMode::NONE},
        {"/proc/self", SandboxConfig::PolicyMountMode::NONE},
        {"/procfoo", SandboxConfig::PolicyMountMode::NONE},
    };

    ASSERT_EQ(SANDBOX_SUCCESS, manager.PrepareMountPlan());
    ASSERT_EQ(2U, manager.mountPlan_.size());
    EXPECT_EQ("/sys", manager.mountPlan_[0].target);
    EXPECT_EQ("/procfoo", manager.mountPlan_[1].target);
}

/**
 * @tc.name: MountPlanProcBindUnderPidNamespace001
 * @tc.desc: Only a SYSTEM /proc bind is dropped under CLONE_NEWPID, because
 *           procfs is mounted after the fork; app entries are kept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountPlanProcBindUnderPidNamespace001, TestSize.Level0)
{
    SandboxManager manager;
    manager.templateConfig_.systemMounts = {
        {"/proc", "/proc", {"bind", "rec"}, true},
        {"/dev", "/dev", {"bind", "rec"}, true},
    };
    manager.config_.nsFlags = CLONE_NEWPID;

    ASSERT_EQ(SANDBOX_SUCCESS, manager.PrepareMountPlan());
    ASSERT_EQ(1U, manager.mountPlan_.size());
    EXPECT_EQ("/dev", manager.mountPlan_[0].target);

    // Without a pid namespace the template /proc bind stays.
    manager.config_.nsFlags = 0;
    ASSERT_EQ(SANDBOX_SUCCESS, manager.PrepareMountPlan());
    EXPECT_EQ(2U, manager.mountPlan_.size());

    // The skip is for SYSTEM entries only; an app entry is kept.
    manager.config_.nsFlags = CLONE_NEWPID;
    manager.templateConfig_.appMounts = {{"/proc", "/proc", {"bind", "rec"}, true}};
    ASSERT_EQ(SANDBOX_SUCCESS, manager.PrepareMountPlan());
    ASSERT_EQ(2U, manager.mountPlan_.size());
    EXPECT_EQ("/dev", manager.mountPlan_[0].target);
    EXPECT_EQ("/proc", manager.mountPlan_[1].target);
}

/**
 * @tc.name: MountTargetPathViewRoot001
 * @tc.desc: GetMountTargetPath joins the root and the view target, keeps "/" as
 *           the root itself, and leaves the target alone without a root
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountTargetPathViewRoot001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxManager::MountOp op;
    op.target = "/data/x";

    // No root yet: the view path stands alone.
    EXPECT_EQ("/data/x", manager.GetMountTargetPath(op));

    manager.newRootPath_ = "/";
    EXPECT_EQ("/data/x", manager.GetMountTargetPath(op));

    // A trailing slash on the root does not double up.
    manager.newRootPath_ = "/mnt/sandbox/claw/abc/";
    EXPECT_EQ("/mnt/sandbox/claw/abc/data/x", manager.GetMountTargetPath(op));

    // "/" names the root itself, and never carries a trailing slash.
    op.target = "/";
    EXPECT_EQ("/mnt/sandbox/claw/abc", manager.GetMountTargetPath(op));

    manager.newRootPath_ = "/";
    EXPECT_EQ("/", manager.GetMountTargetPath(op));
}

/**
 * @tc.name: BindOpFlagsPolicyAndTemplate001
 * @tc.desc: A policy bind always recurses into a directory source and carries no
 *           template flags; a template bind keeps the flags it declared
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, BindOpFlagsPolicyAndTemplate001, TestSize.Level0)
{
    SandboxManager::MountOp op;
    op.origin = SandboxManager::MountOrigin::POLICY;
    EXPECT_EQ(static_cast<unsigned long>(MS_BIND | MS_REC),
        SandboxManager::BindOpFlags(op, true));
    EXPECT_EQ(static_cast<unsigned long>(MS_BIND),
        SandboxManager::BindOpFlags(op, false));

    op.origin = SandboxManager::MountOrigin::SYSTEM;
    op.mountFlags = {"bind", "rec", "rdonly"};
    EXPECT_EQ(static_cast<unsigned long>(MS_BIND | MS_REC | MS_RDONLY),
        SandboxManager::BindOpFlags(op, true));
}

/**
 * @tc.name: ExecuteMountPlanEmptyPlan001
 * @tc.desc: An empty plan is a no-op success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ExecuteMountPlanEmptyPlan001, TestSize.Level0)
{
    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ExecuteMountPlan());
}

/**
 * @tc.name: ExecuteBindOpRejectsEmptyRoot001
 * @tc.desc: A bind refuses to run before the sandbox root exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ExecuteBindOpRejectsEmptyRoot001, TestSize.Level0)
{
    SandboxManager manager;

    SandboxManager::MountOp op;
    op.origin = SandboxManager::MountOrigin::POLICY;
    op.source = "/dev";
    op.target = "/dev";

    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, manager.ExecuteBindOp(op));
    EXPECT_TRUE(manager.mountTargets_.empty());
}

/**
 * @tc.name: ExecuteBindOpCheckExists001
 * @tc.desc: checkExists skips only ENOENT; any other source failure still fails
 *           the launch and nothing is attached
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ExecuteBindOpCheckExists001, TestSize.Level0)
{
    std::string root = MakeTempRoot("check_exists_source");
    ASSERT_FALSE(root.empty());

    SandboxManager manager;
    manager.newRootPath_ = root;

    SandboxManager::MountOp op;
    op.origin = SandboxManager::MountOrigin::SYSTEM;
    op.source = root + "/missing_source";
    op.target = "/missing_source";
    op.checkExists = true;

    // Missing source on a best-effort entry: skipped, nothing attached.
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ExecuteBindOp(op));
    EXPECT_TRUE(manager.mountTargets_.empty());

    // The same entry without best-effort fails instead.
    op.checkExists = false;
    EXPECT_EQ(SANDBOX_ERR_MOUNT_FAILED, manager.ExecuteBindOp(op));

    // A non-ENOENT failure is never swallowed, even when best-effort is on.
    const std::string filePath = root + "/plain_file";
    {
        std::ofstream out(filePath);
        ASSERT_TRUE(out.is_open());
    }
    op.source = filePath + "/child";
    op.checkExists = true;
    EXPECT_EQ(SANDBOX_ERR_MOUNT_FAILED, manager.ExecuteBindOp(op));
    EXPECT_TRUE(manager.mountTargets_.empty());

    std::error_code ec;
    std::filesystem::remove_all(root, ec);
}

/**
 * @tc.name: ExecuteBindOpRejectsInvalidTargetPath001
 * @tc.desc: A relative target fails target walking before any mount is attempted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ExecuteBindOpRejectsInvalidTargetPath001, TestSize.Level0)
{
    std::string root = MakeTempRoot("invalid_target_path");
    ASSERT_FALSE(root.empty());

    SandboxManager manager;
    manager.newRootPath_ = root;

    SandboxManager::MountOp op;
    op.origin = SandboxManager::MountOrigin::SYSTEM;
    op.source = "/dev";
    op.target = "relative";

    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, manager.ExecuteBindOp(op));
    EXPECT_TRUE(manager.mountTargets_.empty());

    std::error_code ec;
    std::filesystem::remove_all(root, ec);
}

/**
 * @tc.name: ExecuteBindOpRejectsMissingRootPath001
 * @tc.desc: The sandbox root must exist; failing to open it is a path error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ExecuteBindOpRejectsMissingRootPath001, TestSize.Level0)
{
    std::string root = MakeTempRoot("missing_root_path");
    ASSERT_FALSE(root.empty());

    SandboxManager manager;
    manager.newRootPath_ = root + "/absent";

    SandboxManager::MountOp op;
    op.origin = SandboxManager::MountOrigin::SYSTEM;
    op.source = "/dev";
    op.target = "/dev";

    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, manager.ExecuteBindOp(op));
    EXPECT_TRUE(manager.mountTargets_.empty());

    std::error_code ec;
    std::filesystem::remove_all(root, ec);
}

/**
 * @tc.name: ExecuteBindOpRejectsTargetUnderFile001
 * @tc.desc: A component of the target that is not a directory is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ExecuteBindOpRejectsTargetUnderFile001, TestSize.Level0)
{
    std::string root = MakeTempRoot("target_under_file");
    ASSERT_FALSE(root.empty());

    SandboxManager manager;
    manager.newRootPath_ = root;

    {
        std::ofstream out(root + "/blocker");
        ASSERT_TRUE(out.is_open());
    }

    SandboxManager::MountOp op;
    op.origin = SandboxManager::MountOrigin::SYSTEM;
    op.source = "/dev";
    op.target = "/blocker/child";

    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, manager.ExecuteBindOp(op));
    EXPECT_TRUE(manager.mountTargets_.empty());

    std::error_code ec;
    std::filesystem::remove_all(root, ec);
}

/**
 * @tc.name: ExecuteBindOpRejectsNonDirectorySourceAtRoot001
 * @tc.desc: A "/" target requires a directory source, since it covers the root
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ExecuteBindOpRejectsNonDirectorySourceAtRoot001, TestSize.Level0)
{
    std::string root = MakeTempRoot("file_source_at_root");
    ASSERT_FALSE(root.empty());

    SandboxManager manager;
    manager.newRootPath_ = root;

    const std::string sourceFile = root + "/payload";
    {
        std::ofstream out(sourceFile);
        ASSERT_TRUE(out.is_open());
    }

    SandboxManager::MountOp op;
    op.origin = SandboxManager::MountOrigin::SYSTEM;
    op.source = sourceFile;
    op.target = "/";

    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, manager.ExecuteBindOp(op));
    EXPECT_TRUE(manager.mountTargets_.empty());

    std::error_code ec;
    std::filesystem::remove_all(root, ec);
}

/**
 * @tc.name: ExecuteBindOpRejectsFileSourceLeafMismatch001
 * @tc.desc: A non-directory source refuses a symlink leaf and a directory leaf
 *           rather than following one or mounting over the other
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ExecuteBindOpRejectsFileSourceLeafMismatch001, TestSize.Level0)
{
    std::string root = MakeTempRoot("file_source_leaf");
    ASSERT_FALSE(root.empty());

    SandboxManager manager;
    manager.newRootPath_ = root;

    const std::string sourceFile = root + "/payload";
    {
        std::ofstream out(sourceFile);
        ASSERT_TRUE(out.is_open());
    }
    ASSERT_EQ(0, symlink("/dev/null", (root + "/link_leaf").c_str()));
    std::error_code ec;
    ASSERT_TRUE(std::filesystem::create_directories(root + "/dir_leaf", ec));

    SandboxManager::MountOp op;
    op.origin = SandboxManager::MountOrigin::SYSTEM;
    op.source = sourceFile;

    op.target = "/link_leaf";
    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, manager.ExecuteBindOp(op));

    op.target = "/dir_leaf";
    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, manager.ExecuteBindOp(op));
    EXPECT_TRUE(manager.mountTargets_.empty());

    std::filesystem::remove_all(root, ec);
}

/**
 * @tc.name: CreateTemplateSymlinksSafeBranches001
 * @tc.desc: An empty link list is a no-op, and a link whose parent directory does
 *           not exist fails instead of escaping the view
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, CreateTemplateSymlinksSafeBranches001, TestSize.Level0)
{
    std::string root = MakeTempRoot("symlink_safe_branches");
    ASSERT_FALSE(root.empty());

    SandboxManager manager;
    manager.newRootPath_ = root;

    // Nothing to create.
    EXPECT_EQ(SANDBOX_SUCCESS, manager.CreateTemplateSymlinks());

    std::error_code ec;
    ASSERT_TRUE(std::filesystem::create_directories(root + "/dev", ec));
    manager.templateConfig_.symLinks = {{"/dev", "/missing_dir/link"}};
    EXPECT_EQ(SANDBOX_ERR_SYMLINK_FAILED, manager.CreateTemplateSymlinks());

    struct stat st = {};
    EXPECT_NE(0, lstat((root + "/missing_dir/link").c_str(), &st));

    std::filesystem::remove_all(root, ec);
}

/**
 * @tc.name: ApplyBindModeBranches001
 * @tc.desc: No mode is a no-op; a forced ro that cannot open its target fails
 *           without mounting anything
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ApplyBindModeBranches001, TestSize.Level0)
{
    SandboxManager::MountOp plain;
    plain.origin = SandboxManager::MountOrigin::SYSTEM;
    plain.target = "/x";
    EXPECT_EQ(SANDBOX_SUCCESS, SandboxManager::ApplyBindMode(plain, "", "/nonexistent_target",
        true, MS_BIND));

    SandboxManager::MountOp ro;
    ro.origin = SandboxManager::MountOrigin::POLICY;
    ro.mode = SandboxConfig::PolicyMountMode::RO;
    ro.target = "/x";
    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, SandboxManager::ApplyBindMode(ro, "/nonexistent_root",
        "/nonexistent_target", true, MS_BIND));
}

/**
 * @tc.name: ApplyBindPropagationNoFlags001
 * @tc.desc: No propagation flag means no mount call
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, ApplyBindPropagationNoFlags001, TestSize.Level0)
{
    EXPECT_EQ(SANDBOX_SUCCESS,
        SandboxManager::ApplyBindPropagation("/nonexistent_target", 0));
}

/**
 * @tc.name: MountDirRejectsEmptyTarget001
 * @tc.desc: MountDir creates the target first, so an empty target fails before
 *           the mount call
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, MountDirRejectsEmptyTarget001, TestSize.Level0)
{
    SandboxManager manager;
    EXPECT_EQ(SANDBOX_ERR_PATH_CREATE_FAILED,
        manager.MountDir("/dev", "", {"bind"}));
}

/**
 * @tc.name: CleanupSkipsUnownedRoot001
 * @tc.desc: Cleanup removes only paths under the sandbox base directory; any
 *           other path is left on disk untouched
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, CleanupSkipsUnownedRoot001, TestSize.Level0)
{
    std::string root = MakeTempRoot("cleanup_unowned");
    ASSERT_FALSE(root.empty());

    SandboxManager manager;
    manager.newRootPath_ = root;

    manager.Cleanup();

    std::error_code ec;
    EXPECT_TRUE(std::filesystem::exists(root, ec));
    EXPECT_TRUE(manager.newRootPath_.empty());

    std::filesystem::remove_all(root, ec);
}

/**
 * @tc.name: DumpMountPlanAllOrigins001
 * @tc.desc: DumpMountPlan walks every origin and mode without touching the mount
 *           table, including values outside the known enumerators
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMountTest, DumpMountPlanAllOrigins001, TestSize.Level0)
{
    SandboxManager manager;
    manager.templateConfig_.systemMounts = {{"/sys", "/sys", {"bind", "rec"}, true}};
    manager.templateConfig_.appMounts = {{"/data/x", "/data/x", {"bind", "rec"}, true}};
    manager.config_.policy.mounts = {{"/data/y", SandboxConfig::PolicyMountMode::NONE}};
    ASSERT_EQ(SANDBOX_SUCCESS, manager.PrepareMountPlan());
    manager.DumpMountPlan();

    SandboxManager::MountOp unknown;
    unknown.origin = static_cast<SandboxManager::MountOrigin>(0xFF);
    unknown.mode = static_cast<SandboxConfig::PolicyMountMode>(0xFF);
    unknown.source = "/x";
    unknown.target = "/x";
    manager.mountPlan_.push_back(unknown);
    manager.DumpMountPlan();
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
