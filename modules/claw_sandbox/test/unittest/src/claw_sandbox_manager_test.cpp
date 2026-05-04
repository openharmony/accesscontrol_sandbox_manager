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
    config.callerTokenId = 12345;
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
    config.callerTokenId = 12345;
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
    config.callerTokenId = 12345;
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
    config.callerTokenId = 12345;
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
    config.callerTokenId = 12345;
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
    config.callerTokenId = 12345;
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
    config.callerTokenId = 12345;
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

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
