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

#include "claw_sandbox_config_parser_test.h"
#include "sandbox_error.h"
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>

#define private public
#include "sandbox_manager.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {


// TempJsonFile helper (needed for LoadJsonConfig tests)
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

void ClawSandboxConfigParserTest::SetUpTestCase() {}
void ClawSandboxConfigParserTest::TearDownTestCase() {}
void ClawSandboxConfigParserTest::SetUp() {}
void ClawSandboxConfigParserTest::TearDown() {}

// ==================== LoadDefaultConfig tests ====================

/**
 * @tc.name: LoadDefaultConfig001
 * @tc.desc: LoadDefaultConfig sets systemMounts correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, LoadDefaultConfig001, TestSize.Level0)
{
    SandboxManager manager;
    int ret = manager.LoadDefaultConfig();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    // LoadDefaultConfig populates systemMounts with default entries
}

// ==================== LoadJsonConfig tests ====================

/**
 * @tc.name: LoadJsonConfig001
 * @tc.desc: LoadJsonConfig falls back to default config when file is missing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, LoadJsonConfig001, TestSize.Level0)
{
    TempJsonFile file("missing");
    SandboxManager manager;

    int ret = manager.LoadJsonConfig(file.Path());
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_FALSE(manager.templateConfig_.systemMounts.empty());
    EXPECT_FALSE(manager.templateConfig_.appMounts.empty());
}

/**
 * @tc.name: LoadJsonConfig002
 * @tc.desc: LoadJsonConfig rejects malformed template JSON
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, LoadJsonConfig002, TestSize.Level0)
{
    TempJsonFile file("malformed");
    ASSERT_TRUE(file.Write(R"({"system-mounts": [)"));
    SandboxManager manager;

    int ret = manager.LoadJsonConfig(file.Path());
    EXPECT_EQ(SANDBOX_ERR_TEMPLATE_INVALID, ret);
    EXPECT_TRUE(manager.templateConfig_.systemMounts.empty());
}

/**
 * @tc.name: LoadJsonConfig003
 * @tc.desc: LoadJsonConfig replaces template variables before parsing JSON
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, LoadJsonConfig003, TestSize.Level0)
{
    TempJsonFile file("variables");
    ASSERT_TRUE(file.Write(R"({"app-mounts":[{"source":"/data/<currentUserId>/<PackageName>",
        "target":"/dst/<PackageName>"}]})"));
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.bundleName = "com.example.bundle";
    CmdInfo cmdInfo;
    manager.Initialize(config, cmdInfo);

    int ret = manager.LoadJsonConfig(file.Path());
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(1U, manager.templateConfig_.appMounts.size());
    EXPECT_EQ("/data/100/com.example.bundle", manager.templateConfig_.appMounts[0].source);
    EXPECT_EQ("/dst/com.example.bundle", manager.templateConfig_.appMounts[0].target);
}

// ==================== ParseMountEntry tests ====================

/**
 * @tc.name: ParseMountEntry001
 * @tc.desc: ParseMountEntry parses source and target correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseMountEntry001, TestSize.Level0)
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
HWTEST_F(ClawSandboxConfigParserTest, ParseMountEntry002, TestSize.Level0)
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
HWTEST_F(ClawSandboxConfigParserTest, ParseMountEntry003, TestSize.Level0)
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
HWTEST_F(ClawSandboxConfigParserTest, ParseMountEntry004, TestSize.Level0)
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

/**
 * @tc.name: ParseMountEntry005
 * @tc.desc: ParseMountEntry ignores fields with unexpected JSON types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseMountEntry005, TestSize.Level0)
{
    const char *json = R"({
        "source": 100,
        "target": false,
        "mount-flags": ["bind", 123, "rec"],
        "check-exists": "true"
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager::MountEntry me;
    SandboxManager::ParseMountEntry(root, me);
    EXPECT_TRUE(me.source.empty());
    EXPECT_TRUE(me.target.empty());
    ASSERT_EQ(2U, me.mountFlags.size());
    EXPECT_EQ("bind", me.mountFlags[0]);
    EXPECT_EQ("rec", me.mountFlags[1]);
    EXPECT_FALSE(me.checkExists);

    cJSON_Delete(root);
}

// ==================== ParseMountEntry fallback tests ====================

/**
 * @tc.name: ParseMountEntry006
 * @tc.desc: ParseMountEntry falls back to src-path when source is missing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseMountEntry006, TestSize.Level0)
{
    const char *json = R"({
        "src-path": "/fallback/src",
        "target": "/tgt/path"
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager::MountEntry me;
    SandboxManager::ParseMountEntry(root, me);
    EXPECT_EQ("/fallback/src", me.source);
    EXPECT_EQ("/tgt/path", me.target);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseMountEntry007
 * @tc.desc: ParseMountEntry falls back to sandbox-path when target is missing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseMountEntry007, TestSize.Level0)
{
    const char *json = R"({
        "source": "/src/path",
        "sandbox-path": "/fallback/tgt"
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager::MountEntry me;
    SandboxManager::ParseMountEntry(root, me);
    EXPECT_EQ("/src/path", me.source);
    EXPECT_EQ("/fallback/tgt", me.target);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseMountEntry008
 * @tc.desc: ParseMountEntry skips source when value is "none"
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseMountEntry008, TestSize.Level0)
{
    const char *json = R"({
        "source": "none",
        "target": "/tgt/path"
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager::MountEntry me;
    SandboxManager::ParseMountEntry(root, me);
    EXPECT_TRUE(me.source.empty());
    EXPECT_EQ("/tgt/path", me.target);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseMountEntry009
 * @tc.desc: ParseMountEntry skips target when value is "none"
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseMountEntry009, TestSize.Level0)
{
    const char *json = R"({
        "source": "/src/path",
        "target": "none"
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager::MountEntry me;
    SandboxManager::ParseMountEntry(root, me);
    EXPECT_EQ("/src/path", me.source);
    EXPECT_TRUE(me.target.empty());

    cJSON_Delete(root);
}

// ==================== ParsePermissionMountEntry tests ====================

/**
 * @tc.name: ParsePermissionMountEntry001
 * @tc.desc: ParsePermissionMountEntry parses base mount fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionMountEntry001, TestSize.Level0)
{
    const char *json = R"({
        "source": "/src",
        "target": "/tgt",
        "mount-flags": ["bind"],
        "check-exists": true
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager::PermissionMountEntry pme;
    SandboxManager::ParsePermissionMountEntry(root, pme);
    EXPECT_EQ("/src", pme.mount.source);
    EXPECT_EQ("/tgt", pme.mount.target);
    ASSERT_EQ(1U, pme.mount.mountFlags.size());
    EXPECT_EQ("bind", pme.mount.mountFlags[0]);
    EXPECT_TRUE(pme.mount.checkExists);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParsePermissionMountEntry002
 * @tc.desc: ParsePermissionMountEntry parses dec-paths array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionMountEntry002, TestSize.Level0)
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
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionMountEntry003, TestSize.Level0)
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

/**
 * @tc.name: ParsePermissionMountEntry004
 * @tc.desc: ParsePermissionMountEntry ignores invalid optional field elements
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionMountEntry004, TestSize.Level0)
{
    const char *json = R"({
        "source": "/src",
        "target": "/tgt",
        "dec-paths": ["/path1", 100, {}, "/path2"],
        "mount-shared-flag": true
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager::PermissionMountEntry pme;
    SandboxManager::ParsePermissionMountEntry(root, pme);
    ASSERT_EQ(2U, pme.decPaths.size());
    EXPECT_EQ("/path1", pme.decPaths[0]);
    EXPECT_EQ("/path2", pme.decPaths[1]);
    EXPECT_TRUE(pme.mountSharedFlag.empty());

    cJSON_Delete(root);
}

// ==================== ParsePermissionSwitch tests ====================

/**
 * @tc.name: ParsePermissionSwitch001
 * @tc.desc: ParsePermissionSwitch with "ON" sets sandboxSwitch true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionSwitch001, TestSize.Level0)
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
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionSwitch002, TestSize.Level0)
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
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionSwitch003, TestSize.Level0)
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
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionGids001, TestSize.Level0)
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
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionGids002, TestSize.Level0)
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
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionGids003, TestSize.Level0)
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

/**
 * @tc.name: ParsePermissionGids004
 * @tc.desc: ParsePermissionGids ignores non-number array elements
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionGids004, TestSize.Level0)
{
    const char *json = R"({"gids": [1000, "bad", {}, 2000]})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    SandboxManager::PermissionConfig pc;
    manager.ParsePermissionGids(root, pc);
    ASSERT_EQ(2U, pc.gids.size());
    EXPECT_EQ(1000, pc.gids[0]);
    EXPECT_EQ(2000, pc.gids[1]);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParsePermissionGids005
 * @tc.desc: ParsePermissionGids ignores non-array gids field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionGids005, TestSize.Level0)
{
    const char *json = R"({"gids": 1000})";
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
HWTEST_F(ClawSandboxConfigParserTest, ParseSeccompJson001, TestSize.Level0)
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
    ASSERT_EQ(3U, manager.templateConfig_.seccompAllowList.size());
    EXPECT_EQ("execve", manager.templateConfig_.seccompAllowList[0]);
    EXPECT_EQ("read", manager.templateConfig_.seccompAllowList[1]);
    EXPECT_EQ("write", manager.templateConfig_.seccompAllowList[2]);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseSeccompJson002
 * @tc.desc: ParseSeccompJson with missing seccomp object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseSeccompJson002, TestSize.Level0)
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

/**
 * @tc.name: ParseSeccompJson003
 * @tc.desc: ParseSeccompJson ignores non-string allow-list elements
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseSeccompJson003, TestSize.Level0)
{
    const char *json = R"({
        "seccomp": {
            "allow-list": ["read", 100, {}, "write"]
        }
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    manager.ParseSeccompJson(root);
    ASSERT_EQ(2U, manager.templateConfig_.seccompAllowList.size());
    EXPECT_EQ("read", manager.templateConfig_.seccompAllowList[0]);
    EXPECT_EQ("write", manager.templateConfig_.seccompAllowList[1]);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseSeccompJson004
 * @tc.desc: ParseSeccompJson ignores wrong seccomp object shape
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseSeccompJson004, TestSize.Level0)
{
    const char *json = R"({"seccomp": {"allow-list": "read"}})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    manager.ParseSeccompJson(root);
    EXPECT_TRUE(manager.templateConfig_.seccompAllowList.empty());

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseSeccompJson005
 * @tc.desc: ParseSeccompJson ignores non-object seccomp field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseSeccompJson005, TestSize.Level0)
{
    const char *json = R"({"seccomp": ["read"]})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    manager.ParseSeccompJson(root);
    EXPECT_TRUE(manager.templateConfig_.seccompAllowList.empty());

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseSeccompJson006
 * @tc.desc: ParseSeccompJson accepts an empty allow-list array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseSeccompJson006, TestSize.Level0)
{
    const char *json = R"({"seccomp": {"allow-list": []}})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    manager.ParseSeccompJson(root);
    EXPECT_TRUE(manager.templateConfig_.seccompAllowList.empty());

    cJSON_Delete(root);
}

// ==================== ParseEnvPolicyJson tests ====================

/**
 * @tc.name: ParseEnvPolicyJson001
 * @tc.desc: ParseEnvPolicyJson parses env-policy arrays with trim and uppercase normalization
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseEnvPolicyJson001, TestSize.Level0)
{
    const char *json = R"({
        "env-policy": {
            "blocked-everywhere-keys": [" path ", 123, ""],
            "blocked-override-only-keys": ["home"],
            "allowed-inherited-override-only-keys": [" Home "],
            "blocked-prefixes": ["dyld_"],
            "blocked-override-prefixes": ["ssh_"]
        }
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    manager.ParseEnvPolicyJson(root);

    ASSERT_EQ(1U, manager.templateConfig_.envPolicy.blockedEverywhereKeys.size());
    EXPECT_EQ("PATH", manager.templateConfig_.envPolicy.blockedEverywhereKeys[0]);
    ASSERT_EQ(1U, manager.templateConfig_.envPolicy.blockedOverrideOnlyKeys.size());
    EXPECT_EQ("HOME", manager.templateConfig_.envPolicy.blockedOverrideOnlyKeys[0]);
    ASSERT_EQ(1U, manager.templateConfig_.envPolicy.allowedInheritedOverrideOnlyKeys.size());
    EXPECT_EQ("HOME", manager.templateConfig_.envPolicy.allowedInheritedOverrideOnlyKeys[0]);
    ASSERT_EQ(1U, manager.templateConfig_.envPolicy.blockedPrefixes.size());
    EXPECT_EQ("DYLD_", manager.templateConfig_.envPolicy.blockedPrefixes[0]);
    ASSERT_EQ(1U, manager.templateConfig_.envPolicy.blockedOverridePrefixes.size());
    EXPECT_EQ("SSH_", manager.templateConfig_.envPolicy.blockedOverridePrefixes[0]);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseEnvPolicyJson002
 * @tc.desc: ParseEnvPolicyJson ignores missing or invalid env-policy fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseEnvPolicyJson002, TestSize.Level0)
{
    const char *json = R"({"env-policy": "bad"})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    manager.templateConfig_.envPolicy.blockedEverywhereKeys = {"KEEP"};
    manager.ParseEnvPolicyJson(root);

    ASSERT_EQ(1U, manager.templateConfig_.envPolicy.blockedEverywhereKeys.size());
    EXPECT_EQ("KEEP", manager.templateConfig_.envPolicy.blockedEverywhereKeys[0]);

    cJSON_Delete(root);
}

// ==================== ParseSystemMountsJson tests ====================

/**
 * @tc.name: ParseSystemMountsJson001
 * @tc.desc: ParseSystemMountsJson parses system-mounts array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseSystemMountsJson001, TestSize.Level0)
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
HWTEST_F(ClawSandboxConfigParserTest, ParseSystemMountsJson002, TestSize.Level0)
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

/**
 * @tc.name: ParseSystemMountsJson003
 * @tc.desc: ParseSystemMountsJson skips invalid entries and incomplete mounts
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseSystemMountsJson003, TestSize.Level0)
{
    const char *json = R"({
        "system-mounts": [
            100,
            {"source": "/src-only"},
            {"target": "/target-only"},
            {"source": "/src", "target": "/target"}
        ]
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParseSystemMountsJson(root));
    ASSERT_EQ(1U, manager.templateConfig_.systemMounts.size());
    EXPECT_EQ("/src", manager.templateConfig_.systemMounts[0].source);
    EXPECT_EQ("/target", manager.templateConfig_.systemMounts[0].target);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseSystemMountsJson004
 * @tc.desc: ParseSystemMountsJson ignores non-array system-mounts field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseSystemMountsJson004, TestSize.Level0)
{
    const char *json = R"({"system-mounts": {"source": "/src", "target": "/dst"}})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParseSystemMountsJson(root));
    EXPECT_TRUE(manager.templateConfig_.systemMounts.empty());

    cJSON_Delete(root);
}

// ==================== ParseAppMountsJson tests ====================

/**
 * @tc.name: ParseAppMountsJson001
 * @tc.desc: ParseAppMountsJson parses app-mounts array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseAppMountsJson001, TestSize.Level0)
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

/**
 * @tc.name: ParseAppMountsJson002
 * @tc.desc: ParseAppMountsJson skips non-object and incomplete entries
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseAppMountsJson002, TestSize.Level0)
{
    const char *json = R"({
        "app-mounts": [
            false,
            {"source": "/data/app"},
            {"target": "/data/app"},
            {"source": "/data/src", "target": "/data/target"}
        ]
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParseAppMountsJson(root));
    ASSERT_EQ(1U, manager.templateConfig_.appMounts.size());
    EXPECT_EQ("/data/src", manager.templateConfig_.appMounts[0].source);
    EXPECT_EQ("/data/target", manager.templateConfig_.appMounts[0].target);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseAppMountsJson003
 * @tc.desc: ParseAppMountsJson ignores non-array app-mounts field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseAppMountsJson003, TestSize.Level0)
{
    const char *json = R"({"app-mounts": {"source": "/data/src", "target": "/data/dst"}})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParseAppMountsJson(root));
    EXPECT_TRUE(manager.templateConfig_.appMounts.empty());

    cJSON_Delete(root);
}

// ==================== ParsePermissionJson tests ====================

/**
 * @tc.name: ParsePermissionJson001
 * @tc.desc: ParsePermissionJson parses permission object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionJson001, TestSize.Level0)
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
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionJson002, TestSize.Level0)
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

/**
 * @tc.name: ParsePermissionJson003
 * @tc.desc: ParsePermissionJson ignores non-object permission field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionJson003, TestSize.Level0)
{
    const char *json = R"({"permission": []})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParsePermissionJson(root));
    EXPECT_TRUE(manager.templateConfig_.permissions.empty());

    cJSON_Delete(root);
}

/**
 * @tc.name: ParsePermissionJson004
 * @tc.desc: ParsePermissionJson skips invalid permission array elements
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionJson004, TestSize.Level0)
{
    const char *json = R"({
        "permission": {
            "ohos.permission.TEST": [100, {"sandbox-switch": "ON"}],
            "ohos.permission.BAD": "not-array"
        }
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParsePermissionJson(root));
    ASSERT_EQ(1U, manager.templateConfig_.permissions.size());
    EXPECT_TRUE(manager.templateConfig_.permissions["ohos.permission.TEST"].sandboxSwitch);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParsePermissionJson005
 * @tc.desc: ParsePermissionJson accepts an empty permission config array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionJson005, TestSize.Level0)
{
    const char *json = R"({"permission": {"ohos.permission.EMPTY": []}})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParsePermissionJson(root));
    EXPECT_TRUE(manager.templateConfig_.permissions.empty());

    cJSON_Delete(root);
}

/**
 * @tc.name: ParsePermissionJson006
 * @tc.desc: ParsePermissionJson parses array-form permission entries with default switch on
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionJson006, TestSize.Level0)
{
    const char *json = R"({
        "permission": [
            {
                "name": "ohos.permission.GRANTED_ARRAY",
                "gids": [1006],
                "mount-paths": [
                    {"source": "/src", "target": "/dst", "mount-flags": ["bind"]}
                ]
            },
            100,
            {"sandbox-switch": "ON"},
            {"name": ""}
        ]
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParsePermissionJson(root));
    ASSERT_EQ(1U, manager.templateConfig_.permissions.size());
    const auto &pc = manager.templateConfig_.permissions["ohos.permission.GRANTED_ARRAY"];
    EXPECT_TRUE(pc.sandboxSwitch);
    ASSERT_EQ(1U, pc.gids.size());
    EXPECT_EQ(1006, pc.gids[0]);
    ASSERT_EQ(1U, pc.mounts.size());
    EXPECT_EQ("/src", pc.mounts[0].mount.source);
    EXPECT_EQ("/dst", pc.mounts[0].mount.target);
    ASSERT_EQ(1U, pc.mounts[0].mount.mountFlags.size());
    EXPECT_EQ("bind", pc.mounts[0].mount.mountFlags[0]);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParsePermissionJson007
 * @tc.desc: ParsePermissionJson parses conditional permission section
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionJson007, TestSize.Level0)
{
    const char *json = R"({
        "conditional": {
            "permission": {
                "ohos.permission.GRANTED_CONDITIONAL": [
                    {"sandbox-switch": "ON", "gids": [3076]}
                ]
            }
        }
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParsePermissionJson(root));
    ASSERT_EQ(1U, manager.templateConfig_.permissions.size());
    const auto &pc = manager.templateConfig_.permissions["ohos.permission.GRANTED_CONDITIONAL"];
    EXPECT_TRUE(pc.sandboxSwitch);
    ASSERT_EQ(1U, pc.gids.size());
    EXPECT_EQ(3076, pc.gids[0]);

    cJSON_Delete(root);
}

// ==================== ParseSinglePermissionItem tests ====================

/**
 * @tc.name: ParseSinglePermissionItem001
 * @tc.desc: ParseSinglePermissionItem ignores non-array permission item
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseSinglePermissionItem001, TestSize.Level0)
{
    const char *json = R"({"ohos.permission.TEST": {"sandbox-switch": "ON"}})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);
    cJSON *item = cJSON_GetObjectItem(root, "ohos.permission.TEST");

    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParseSinglePermissionItem(item));
    EXPECT_TRUE(manager.templateConfig_.permissions.empty());

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseSinglePermissionItem002
 * @tc.desc: ParseSinglePermissionItem ignores array item with empty permission name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseSinglePermissionItem002, TestSize.Level0)
{
    const char *json = R"({"": [{"sandbox-switch": "ON"}]})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);
    cJSON *item = cJSON_GetObjectItem(root, "");

    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParseSinglePermissionItem(item));
    EXPECT_TRUE(manager.templateConfig_.permissions.empty());

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseSinglePermissionItem003
 * @tc.desc: ParseSinglePermissionItem accepts an empty config array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseSinglePermissionItem003, TestSize.Level0)
{
    const char *json = R"({"ohos.permission.EMPTY": []})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);
    cJSON *item = cJSON_GetObjectItem(root, "ohos.permission.EMPTY");

    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParseSinglePermissionItem(item));
    EXPECT_TRUE(manager.templateConfig_.permissions.empty());

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseSinglePermissionConfig001
 * @tc.desc: ParseSinglePermissionConfig stores parsed permission config
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseSinglePermissionConfig001, TestSize.Level0)
{
    const char *json = R"({"sandbox-switch": "ON", "gids": [1001],
        "mounts": [{"source": "/src", "target": "/dst"}]})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS,
        manager.ParseSinglePermissionConfig(root, "ohos.permission.TEST"));
    ASSERT_EQ(1U, manager.templateConfig_.permissions.size());
    const auto &pc = manager.templateConfig_.permissions["ohos.permission.TEST"];
    EXPECT_TRUE(pc.sandboxSwitch);
    ASSERT_EQ(1U, pc.gids.size());
    ASSERT_EQ(1U, pc.mounts.size());

    cJSON_Delete(root);
}

// ==================== ParsePermissionSectionJson tests ====================

/**
 * @tc.name: ParsePermissionSectionJson001
 * @tc.desc: ParsePermissionSectionJson parses a permission object section
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionSectionJson001, TestSize.Level0)
{
    const char *json = R"({"test_permission": [{"sandbox-switch": "ON", "gids": [1001]}]})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParsePermissionSectionJson(root));
    ASSERT_EQ(1U, manager.templateConfig_.permissions.size());
    EXPECT_TRUE(manager.templateConfig_.permissions["test_permission"].sandboxSwitch);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParsePermissionSectionJson002
 * @tc.desc: ParsePermissionSectionJson parses a permission array section
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionSectionJson002, TestSize.Level0)
{
    const char *json = R"([{"name": "perm1", "sandbox-switch": "ON", "gids": [1001]},
                           {"name": "perm2", "sandbox-switch": "OFF", "gids": [2002]}])";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParsePermissionSectionJson(root));
    ASSERT_EQ(2U, manager.templateConfig_.permissions.size());

    cJSON_Delete(root);
}

// ==================== ParsePermissionObjectJson tests ====================

/**
 * @tc.name: ParsePermissionObjectJson001
 * @tc.desc: ParsePermissionObjectJson stores a single permission object and handles null input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionObjectJson001, TestSize.Level0)
{
    const char *json = R"({"sandbox-switch": "ON", "gids": [1001],
        "mounts": [{"source": "/src", "target": "/dst"}]})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParsePermissionObjectJson(root));
    ASSERT_EQ(1U, manager.templateConfig_.permissions.size());

    cJSON_Delete(root);

    SandboxManager nullManager;
    EXPECT_EQ(SANDBOX_SUCCESS, nullManager.ParsePermissionObjectJson(nullptr));
}

// ==================== ParsePermissionArrayJson tests ====================

/**
 * @tc.name: ParsePermissionArrayJson001
 * @tc.desc: ParsePermissionArrayJson stores permissions from an array and handles null input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionArrayJson001, TestSize.Level0)
{
    const char *json = R"([{"name": "perm1", "sandbox-switch": "ON", "gids": [1001]},
                           {"name": "perm2", "sandbox-switch": "OFF", "gids": [2002]}])";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParsePermissionArrayJson(root));
    ASSERT_EQ(2U, manager.templateConfig_.permissions.size());

    cJSON_Delete(root);

    SandboxManager nullManager;
    EXPECT_EQ(SANDBOX_SUCCESS, nullManager.ParsePermissionArrayJson(nullptr));
}

// ==================== ParseSinglePermissionArrayItem tests ====================

/**
 * @tc.name: ParseSinglePermissionArrayItem001
 * @tc.desc: ParseSinglePermissionArrayItem stores a single permission from array item and handles null input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseSinglePermissionArrayItem001, TestSize.Level0)
{
    const char *json = R"({"name": "test_perm", "sandbox-switch": "ON", "gids": [3003]})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParseSinglePermissionArrayItem(root));
    ASSERT_EQ(1U, manager.templateConfig_.permissions.size());
    EXPECT_EQ(3003, manager.templateConfig_.permissions["test_perm"].gids[0]);

    cJSON_Delete(root);

    SandboxManager nullManager;
    EXPECT_EQ(SANDBOX_SUCCESS, nullManager.ParseSinglePermissionArrayItem(nullptr));
}

// ==================== ParsePermissionMounts tests ====================

/**
 * @tc.name: ParsePermissionMounts001
 * @tc.desc: ParsePermissionMounts ignores non-array mounts field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionMounts001, TestSize.Level0)
{
    const char *json = R"({"mounts": "not-array"})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    SandboxManager::PermissionConfig pc;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParsePermissionMounts(root, pc));
    EXPECT_TRUE(pc.mounts.empty());

    cJSON_Delete(root);
}

/**
 * @tc.name: ParsePermissionMounts002
 * @tc.desc: ParsePermissionMounts skips non-object mount elements
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionMounts002, TestSize.Level0)
{
    const char *json = R"({"mounts": [100, {"source": "/src", "target": "/tgt"}]})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    SandboxManager::PermissionConfig pc;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParsePermissionMounts(root, pc));
    ASSERT_EQ(1U, pc.mounts.size());
    EXPECT_EQ("/src", pc.mounts[0].mount.source);
    EXPECT_EQ("/tgt", pc.mounts[0].mount.target);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParsePermissionMounts003
 * @tc.desc: ParsePermissionMounts preserves empty mount objects
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionMounts003, TestSize.Level0)
{
    const char *json = R"({"mounts": [{}]})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    SandboxManager::PermissionConfig pc;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParsePermissionMounts(root, pc));
    ASSERT_EQ(1U, pc.mounts.size());
    EXPECT_TRUE(pc.mounts[0].mount.source.empty());
    EXPECT_TRUE(pc.mounts[0].mount.target.empty());
    EXPECT_TRUE(pc.mounts[0].mount.mountFlags.empty());

    cJSON_Delete(root);
}

/**
 * @tc.name: ParsePermissionMounts004
 * @tc.desc: ParsePermissionMounts accepts mount-paths as a fallback field name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionMounts004, TestSize.Level0)
{
    const char *json = R"({"mount-paths": [{"source": "/src", "target": "/dst"}]})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    SandboxManager::PermissionConfig pc;
    EXPECT_EQ(SANDBOX_SUCCESS, manager.ParsePermissionMounts(root, pc));
    ASSERT_EQ(1U, pc.mounts.size());
    EXPECT_EQ("/src", pc.mounts[0].mount.source);
    EXPECT_EQ("/dst", pc.mounts[0].mount.target);

    cJSON_Delete(root);
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
