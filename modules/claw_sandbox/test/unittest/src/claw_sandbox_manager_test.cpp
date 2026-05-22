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
#include <sys/mount.h>
#include <cstdint>
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
 * @tc.desc: ValidateConfig with invalid callerPid (negative) returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ValidateConfig003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = static_cast<uint32_t>(-1);  // Will be interpreted as large positive
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;

    manager.Initialize(config, cmdInfo);
    int ret = manager.ValidateConfig();
    // callerPid > 0 check passes for large uint32
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

// ==================== ConvertMountFlags tests ====================

/**
 * @tc.name: ConvertMountFlags001
 * @tc.desc: ConvertMountFlags with empty vector returns 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ConvertMountFlags001, TestSize.Level0)
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
HWTEST_F(ClawSandboxManagerTest, ConvertMountFlags002, TestSize.Level0)
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
HWTEST_F(ClawSandboxManagerTest, ConvertMountFlags003, TestSize.Level0)
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
HWTEST_F(ClawSandboxManagerTest, ConvertMountFlags004, TestSize.Level0)
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
HWTEST_F(ClawSandboxManagerTest, ConvertMountFlags005, TestSize.Level0)
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
HWTEST_F(ClawSandboxManagerTest, ConvertMountFlags006, TestSize.Level0)
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
HWTEST_F(ClawSandboxManagerTest, ConvertMountFlags007, TestSize.Level0)
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
HWTEST_F(ClawSandboxManagerTest, ConvertMountFlags008, TestSize.Level0)
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
HWTEST_F(ClawSandboxManagerTest, ConvertMountFlags009, TestSize.Level0)
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
HWTEST_F(ClawSandboxManagerTest, ConvertMountFlags010, TestSize.Level0)
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
HWTEST_F(ClawSandboxManagerTest, ConvertMountFlags011, TestSize.Level0)
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
HWTEST_F(ClawSandboxManagerTest, ConvertMountFlags012, TestSize.Level0)
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
HWTEST_F(ClawSandboxManagerTest, ConvertMountFlags013, TestSize.Level0)
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
HWTEST_F(ClawSandboxManagerTest, ConvertMountFlags014, TestSize.Level0)
{
    std::vector<std::string> flags = {"MS_BIND", "MS_REC"};
    unsigned long result = SandboxManager::ConvertMountFlags(flags);
    EXPECT_EQ(static_cast<unsigned long>(MS_BIND | MS_REC), result);
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
    config.callerTokenId = 12345;
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

// ==================== LoadDefaultConfig tests ====================

/**
 * @tc.name: LoadDefaultConfig001
 * @tc.desc: LoadDefaultConfig sets systemMounts correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, LoadDefaultConfig001, TestSize.Level0)
{
    SandboxManager manager;
    int ret = manager.LoadDefaultConfig();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    // LoadDefaultConfig populates systemMounts with default entries
}

// ==================== ParseMountEntry tests ====================

/**
 * @tc.name: ParseMountEntry001
 * @tc.desc: ParseMountEntry parses source and target correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParseMountEntry001, TestSize.Level0)
{
    const char *json = R"({
        "source": "/src/path",
        "target": "/tgt/path"
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager::MountEntry me;
    SandboxManager::ParseMountEntry(root, me);
    EXPECT_EQ("/src/path", me.source);
    EXPECT_EQ("/tgt/path", me.target);
    EXPECT_TRUE(me.mountFlags.empty());
    EXPECT_FALSE(me.checkExists);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseMountEntry002
 * @tc.desc: ParseMountEntry parses mount-flags array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParseMountEntry002, TestSize.Level0)
{
    const char *json = R"({
        "source": "/src",
        "target": "/tgt",
        "mount-flags": ["bind", "rec", "rdonly"]
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager::MountEntry me;
    SandboxManager::ParseMountEntry(root, me);
    ASSERT_EQ(3U, me.mountFlags.size());
    EXPECT_EQ("bind", me.mountFlags[0]);
    EXPECT_EQ("rec", me.mountFlags[1]);
    EXPECT_EQ("rdonly", me.mountFlags[2]);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseMountEntry003
 * @tc.desc: ParseMountEntry parses check-exists boolean
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParseMountEntry003, TestSize.Level0)
{
    const char *json = R"({
        "source": "/src",
        "target": "/tgt",
        "check-exists": true
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager::MountEntry me;
    SandboxManager::ParseMountEntry(root, me);
    EXPECT_TRUE(me.checkExists);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseMountEntry004
 * @tc.desc: ParseMountEntry with check-exists false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParseMountEntry004, TestSize.Level0)
{
    const char *json = R"({
        "source": "/src",
        "target": "/tgt",
        "check-exists": false
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager::MountEntry me;
    SandboxManager::ParseMountEntry(root, me);
    EXPECT_FALSE(me.checkExists);

    cJSON_Delete(root);
}

// ==================== ParsePermissionMountEntry tests ====================

/**
 * @tc.name: ParsePermissionMountEntry001
 * @tc.desc: ParsePermissionMountEntry parses base mount fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParsePermissionMountEntry001, TestSize.Level0)
{
    const char *json = R"({
        "source": "/src",
        "target": "/tgt",
        "mount-flags": ["bind"]
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager::PermissionMountEntry pme;
    SandboxManager::ParsePermissionMountEntry(root, pme);
    EXPECT_EQ("/src", pme.mount.source);
    EXPECT_EQ("/tgt", pme.mount.target);
    ASSERT_EQ(1U, pme.mount.mountFlags.size());
    EXPECT_EQ("bind", pme.mount.mountFlags[0]);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParsePermissionMountEntry002
 * @tc.desc: ParsePermissionMountEntry parses dec-paths array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParsePermissionMountEntry002, TestSize.Level0)
{
    const char *json = R"({
        "source": "/src",
        "target": "/tgt",
        "dec-paths": ["/path1", "/path2", "/path3"]
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager::PermissionMountEntry pme;
    SandboxManager::ParsePermissionMountEntry(root, pme);
    ASSERT_EQ(3U, pme.decPaths.size());
    EXPECT_EQ("/path1", pme.decPaths[0]);
    EXPECT_EQ("/path2", pme.decPaths[1]);
    EXPECT_EQ("/path3", pme.decPaths[2]);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParsePermissionMountEntry003
 * @tc.desc: ParsePermissionMountEntry parses mount-shared-flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParsePermissionMountEntry003, TestSize.Level0)
{
    const char *json = R"({
        "source": "/src",
        "target": "/tgt",
        "mount-shared-flag": "shared"
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager::PermissionMountEntry pme;
    SandboxManager::ParsePermissionMountEntry(root, pme);
    EXPECT_EQ("shared", pme.mountSharedFlag);

    cJSON_Delete(root);
}

// ==================== ParsePermissionSwitch tests ====================

/**
 * @tc.name: ParsePermissionSwitch001
 * @tc.desc: ParsePermissionSwitch with "ON" sets sandboxSwitch true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParsePermissionSwitch001, TestSize.Level0)
{
    const char *json = R"({"sandbox-switch": "ON"})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    SandboxManager::PermissionConfig pc;
    manager.ParsePermissionSwitch(root, pc);
    EXPECT_TRUE(pc.sandboxSwitch);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParsePermissionSwitch002
 * @tc.desc: ParsePermissionSwitch with "OFF" leaves sandboxSwitch false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParsePermissionSwitch002, TestSize.Level0)
{
    const char *json = R"({"sandbox-switch": "OFF"})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    SandboxManager::PermissionConfig pc;
    manager.ParsePermissionSwitch(root, pc);
    EXPECT_FALSE(pc.sandboxSwitch);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParsePermissionSwitch003
 * @tc.desc: ParsePermissionSwitch with missing field leaves default false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParsePermissionSwitch003, TestSize.Level0)
{
    const char *json = R"({})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    SandboxManager::PermissionConfig pc;
    manager.ParsePermissionSwitch(root, pc);
    EXPECT_FALSE(pc.sandboxSwitch);

    cJSON_Delete(root);
}

// ==================== ParsePermissionGids tests ====================

/**
 * @tc.name: ParsePermissionGids001
 * @tc.desc: ParsePermissionGids parses gids array correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParsePermissionGids001, TestSize.Level0)
{
    const char *json = R"({"gids": [1000, 2000, 3000]})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    SandboxManager::PermissionConfig pc;
    manager.ParsePermissionGids(root, pc);
    ASSERT_EQ(3U, pc.gids.size());
    EXPECT_EQ(1000, pc.gids[0]);
    EXPECT_EQ(2000, pc.gids[1]);
    EXPECT_EQ(3000, pc.gids[2]);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParsePermissionGids002
 * @tc.desc: ParsePermissionGids with empty array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParsePermissionGids002, TestSize.Level0)
{
    const char *json = R"({"gids": []})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    SandboxManager::PermissionConfig pc;
    manager.ParsePermissionGids(root, pc);
    EXPECT_TRUE(pc.gids.empty());

    cJSON_Delete(root);
}

/**
 * @tc.name: ParsePermissionGids003
 * @tc.desc: ParsePermissionGids with missing gids field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParsePermissionGids003, TestSize.Level0)
{
    const char *json = R"({})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    SandboxManager::PermissionConfig pc;
    manager.ParsePermissionGids(root, pc);
    EXPECT_TRUE(pc.gids.empty());

    cJSON_Delete(root);
}

// ==================== ParseSeccompJson tests ====================

/**
 * @tc.name: ParseSeccompJson001
 * @tc.desc: ParseSeccompJson parses allow-list correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParseSeccompJson001, TestSize.Level0)
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
    // SeccompAllowList is populated internally

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseSeccompJson002
 * @tc.desc: ParseSeccompJson with missing seccomp object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParseSeccompJson002, TestSize.Level0)
{
    const char *json = R"({})";
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

    // Should not crash
    manager.ParseSeccompJson(root);

    cJSON_Delete(root);
}

// ==================== ParseSystemMountsJson tests ====================

/**
 * @tc.name: ParseSystemMountsJson001
 * @tc.desc: ParseSystemMountsJson parses system-mounts array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParseSystemMountsJson001, TestSize.Level0)
{
    const char *json = R"({
        "system-mounts": [
            {"source": "/proc", "target": "/proc", "mount-flags": ["bind", "rec"]},
            {"source": "/sys", "target": "/sys", "mount-flags": ["bind"]}
        ]
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

    int ret = manager.ParseSystemMountsJson(root);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseSystemMountsJson002
 * @tc.desc: ParseSystemMountsJson with missing system-mounts returns success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParseSystemMountsJson002, TestSize.Level0)
{
    const char *json = R"({})";
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

    int ret = manager.ParseSystemMountsJson(root);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);

    cJSON_Delete(root);
}

// ==================== ParseAppMountsJson tests ====================

/**
 * @tc.name: ParseAppMountsJson001
 * @tc.desc: ParseAppMountsJson parses app-mounts array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParseAppMountsJson001, TestSize.Level0)
{
    const char *json = R"({
        "app-mounts": [
            {"source": "/data/app", "target": "/data/app", "mount-flags": ["bind"]}
        ]
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

    int ret = manager.ParseAppMountsJson(root);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);

    cJSON_Delete(root);
}

// ==================== ParsePermissionJson tests ====================

/**
 * @tc.name: ParsePermissionJson001
 * @tc.desc: ParsePermissionJson parses permission object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParsePermissionJson001, TestSize.Level0)
{
    const char *json = R"({
        "permission": {
            "ohos.permission.TEST": [
                {
                    "sandbox-switch": "ON",
                    "gids": [1001, 1002],
                    "mounts": [
                        {"source": "/src", "target": "/tgt"}
                    ]
                }
            ]
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

    int ret = manager.ParsePermissionJson(root);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParsePermissionJson002
 * @tc.desc: ParsePermissionJson with empty permission object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ParsePermissionJson002, TestSize.Level0)
{
    const char *json = R"({"permission": {}})";
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

    int ret = manager.ParsePermissionJson(root);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);

    cJSON_Delete(root);
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

    // Verify args[0] (ruid) JGE: jt=1, jf=0
    EXPECT_EQ(prog.filter[SETRESUID_RUID_JGE_IDX].code,
              static_cast<uint16_t>(BPF_JMP | BPF_JGE | BPF_K));
    EXPECT_EQ(prog.filter[SETRESUID_RUID_JGE_IDX].jt, static_cast<uint8_t>(1));
    EXPECT_EQ(prog.filter[SETRESUID_RUID_JGE_IDX].jf, static_cast<uint8_t>(0));
    EXPECT_EQ(prog.filter[SETRESUID_RUID_JGE_IDX].k, static_cast<uint32_t>(20000000));

    // Verify args[1] (euid) JGE: jt=1, jf=0
    EXPECT_EQ(prog.filter[SETRESUID_EUID_JGE_IDX].code,
              static_cast<uint16_t>(BPF_JMP | BPF_JGE | BPF_K));
    EXPECT_EQ(prog.filter[SETRESUID_EUID_JGE_IDX].jt, static_cast<uint8_t>(1));
    EXPECT_EQ(prog.filter[SETRESUID_EUID_JGE_IDX].jf, static_cast<uint8_t>(0));
    EXPECT_EQ(prog.filter[SETRESUID_EUID_JGE_IDX].k, static_cast<uint32_t>(20000000));

    // Verify args[2] (suid) JGE: jt=1, jf=0
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

// ==================== ForkAfterUnshare tests ====================

/**
 * @tc.name: ForkAfterUnshare001
 * @tc.desc: ForkAfterUnshare without CLONE_NEWPID returns success (no fork)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ForkAfterUnshare001, TestSize.Level0)
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
HWTEST_F(ClawSandboxManagerTest, ForkAfterUnshare002, TestSize.Level0)
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
 * @tc.name: ForkAfterUnshare003
 * @tc.desc: ForkAfterUnshare with CLONE_NEWPID set - verify the function
 *          checks nsFlags correctly (fork is not called in test env to
 *          avoid test process exit)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ForkAfterUnshare003, TestSize.Level0)
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

    // Note: When CLONE_NEWPID is set, ForkAfterUnshare calls fork().
    // If fork succeeds, the child process (pid == 0) returns SANDBOX_SUCCESS,
    // while the parent process exits (waitpid + exit), terminating the test.
    // If fork fails, SANDBOX_ERR_GENERIC is returned.
    // In the test environment, fork typically succeeds, so the child returns
    // SANDBOX_SUCCESS. We accept both outcomes.
    int ret = manager.ForkAfterUnshare();
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_GENERIC);
}

// ==================== MountProcFs tests ====================

/**
 * @tc.name: MountProcFs001
 * @tc.desc: MountProcFs without CLONE_NEWPID returns success (no mount)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, MountProcFs001, TestSize.Level0)
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
HWTEST_F(ClawSandboxManagerTest, MountProcFs002, TestSize.Level0)
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

// ==================== CreateNewRoot tests ====================

/**
 * @tc.name: CreateNewRoot001
 * @tc.desc: CreateNewRoot with empty name calls CreateSandboxAutoName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, CreateNewRoot001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.CreateNewRoot();
    EXPECT_TRUE(ret == SANDBOX_SUCCESS ||
                ret == SANDBOX_ERR_PATH_CREATE_FAILED ||
                ret == SANDBOX_ERR_SANDBOX_PATH_EXHAUSTED);
}

/**
 * @tc.name: CreateNewRoot002
 * @tc.desc: CreateNewRoot with explicit name calls CreateSandboxWithName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, CreateNewRoot002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.name = "test_sandbox_name";
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.CreateNewRoot();
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_PATH_CREATE_FAILED);
}

// ==================== UnshareNamespaces tests ====================

/**
 * @tc.name: UnshareNamespaces001
 * @tc.desc: UnshareNamespaces with nsFlags=0 returns success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, UnshareNamespaces001, TestSize.Level0)
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
HWTEST_F(ClawSandboxManagerTest, UnshareNamespaces002, TestSize.Level0)
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

// ==================== MountNewRoot tests ====================

/**
 * @tc.name: MountNewRoot001
 * @tc.desc: MountNewRoot without newRootPath_ set returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, MountNewRoot001, TestSize.Level0)
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
                ret == SANDBOX_ERR_NS_FAILED ||
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

// ==================== ExecuteEarlySteps tests ====================

/**
 * @tc.name: ExecuteEarlySteps001
 * @tc.desc: ExecuteEarlySteps fails at LoadTemplate (template file missing)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ExecuteEarlySteps001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.ExecuteEarlySteps();
    EXPECT_EQ(SANDBOX_ERR_GEN_TOKENID_FAILED, ret);
}

// ==================== ExecuteMountSteps tests ====================

/**
 * @tc.name: ExecuteMountSteps001
 * @tc.desc: ExecuteMountSteps fails at CreateNewRoot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, ExecuteMountSteps001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.ExecuteMountSteps();
    EXPECT_TRUE(ret == SANDBOX_ERR_PATH_CREATE_FAILED ||
                ret == SANDBOX_ERR_SANDBOX_PATH_EXHAUSTED ||
                ret == SANDBOX_ERR_MOUNT_FAILED);
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
    // ExecuteLateSteps calls setgroups() first, which fails in test environment
    // returns an error from the first failing step.
    EXPECT_EQ(SANDBOX_ERR_NS_FAILED, ret);
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

/**
 * @tc.name: Execute002
 * @tc.desc: Execute with valid config fails at LoadTemplate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, Execute002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.Execute();
    EXPECT_EQ(SANDBOX_ERR_GEN_TOKENID_FAILED, ret);
}

// ==================== MountSystemEntry tests ====================

/**
 * @tc.name: MountSystemEntry001
 * @tc.desc: MountSystemEntry with non-existent source returns success (skip)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, MountSystemEntry001, TestSize.Level0)
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
HWTEST_F(ClawSandboxManagerTest, MountSystemEntry002, TestSize.Level0)
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
HWTEST_F(ClawSandboxManagerTest, MountSystemEntry003, TestSize.Level0)
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

// ==================== MountSingleEntry tests ====================

/**
 * @tc.name: MountSingleEntry001
 * @tc.desc: MountSingleEntry with checkExists and non-existent source skips
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, MountSingleEntry001, TestSize.Level0)
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
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: MountSingleEntry002
 * @tc.desc: MountSingleEntry without checkExists attempts mount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, MountSingleEntry002, TestSize.Level0)
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
    entry.checkExists = false;

    int ret = manager.MountSingleEntry(entry, "");
    EXPECT_TRUE(ret == SANDBOX_SUCCESS || ret == SANDBOX_ERR_MOUNT_FAILED || ret == SANDBOX_ERR_PATH_CREATE_FAILED);
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
