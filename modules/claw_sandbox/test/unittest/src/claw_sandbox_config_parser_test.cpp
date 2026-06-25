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

// ==================== ParsePermissionDecPaths tests ====================

/**
 * @tc.name: ParsePermissionDecPaths001
 * @tc.desc: ParsePermissionDecPaths parses an array of decryption paths
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionDecPaths001, TestSize.Level0)
{
    const char *json = R"({"dec-paths": ["/path1", "/path2", "/path3"]})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    SandboxManager::PermissionConfig pc;
    manager.ParsePermissionDecPaths(root, pc);
    ASSERT_EQ(3U, pc.decPaths.size());
    EXPECT_EQ("/path1", pc.decPaths[0]);
    EXPECT_EQ("/path2", pc.decPaths[1]);
    EXPECT_EQ("/path3", pc.decPaths[2]);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParsePermissionDecPaths002
 * @tc.desc: ParsePermissionDecPaths ignores non-string elements in array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionDecPaths002, TestSize.Level0)
{
    const char *json = R"({"dec-paths": ["/path1", 100, {}, "/path2"]})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    SandboxManager::PermissionConfig pc;
    manager.ParsePermissionDecPaths(root, pc);
    ASSERT_EQ(2U, pc.decPaths.size());
    EXPECT_EQ("/path1", pc.decPaths[0]);
    EXPECT_EQ("/path2", pc.decPaths[1]);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParsePermissionDecPaths003
 * @tc.desc: ParsePermissionDecPaths handles missing dec-paths field gracefully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionDecPaths003, TestSize.Level0)
{
    const char *json = R"({"sandbox-switch": "ON"})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    SandboxManager::PermissionConfig pc;
    manager.ParsePermissionDecPaths(root, pc);
    EXPECT_TRUE(pc.decPaths.empty());

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
                "dec-paths": ["/path1", "/path2"]
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
    ASSERT_EQ(2U, pc.decPaths.size());
    EXPECT_EQ("/path1", pc.decPaths[0]);
    EXPECT_EQ("/path2", pc.decPaths[1]);

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
        "dec-paths": ["/path1", "/path2"]})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    EXPECT_EQ(SANDBOX_SUCCESS,
        manager.ParseSinglePermissionConfig(root, "ohos.permission.TEST"));
    ASSERT_EQ(1U, manager.templateConfig_.permissions.size());
    const auto &pc = manager.templateConfig_.permissions["ohos.permission.TEST"];
    EXPECT_TRUE(pc.sandboxSwitch);
    ASSERT_EQ(1U, pc.gids.size());
    ASSERT_EQ(2U, pc.decPaths.size());
    EXPECT_EQ("/path1", pc.decPaths[0]);
    EXPECT_EQ("/path2", pc.decPaths[1]);

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

// ==================== ParsePermissionDecPaths integration tests ====================

/**
 * @tc.name: ParsePermissionDecPaths004
 * @tc.desc: ParsePermissionDecPaths with missing field leaves decPaths empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionDecPaths004, TestSize.Level0)
{
    const char *json = R"({"sandbox-switch": "ON"})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    SandboxManager::PermissionConfig pc;
    manager.ParsePermissionDecPaths(root, pc);
    EXPECT_TRUE(pc.decPaths.empty());

    cJSON_Delete(root);
}

/**
 * @tc.name: ParsePermissionDecPaths005
 * @tc.desc: ParsePermissionDecPaths handles non-array dec-paths field gracefully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParsePermissionDecPaths005, TestSize.Level0)
{
    const char *json = R"({"dec-paths": "not-an-array"})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    SandboxManager::PermissionConfig pc;
    manager.ParsePermissionDecPaths(root, pc);
    EXPECT_TRUE(pc.decPaths.empty());

    cJSON_Delete(root);
}

// ==================== ParseConditionalJson tests ====================

/**
 * @tc.name: ParseConditionalJson001
 * @tc.desc: ParseConditionalJson parses source, target, mount-flags, check-exists, permissions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseConditionalJson001, TestSize.Level0)
{
    const char *json = R"({
        "conditional": [
            {
                "source": "/mnt/user/100/docs/Desktop",
                "target": "/storage/Users/currentUser/Desktop",
                "mount-flags": ["bind", "rec"],
                "check-exists": true,
                "permissions": ["ohos.permission.READ_WRITE_DESKTOP", "ohos.permission.FILE_ACCESS_MANAGER"]
            },
            {
                "source": "/mnt/user/100/docs",
                "target": "/storage/Users",
                "mount-flags": ["bind", "rec"],
                "check-exists": false,
                "permissions": ["ohos.permission.FILE_ACCESS_MANAGER"]
            }
        ]
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    manager.ParseConditionalJson(root);
    ASSERT_EQ(2U, manager.templateConfig_.conditionalRules.size());

    // First rule
    const auto &rule1 = manager.templateConfig_.conditionalRules[0];
    EXPECT_EQ("/mnt/user/100/docs/Desktop", rule1.source);
    EXPECT_EQ("/storage/Users/currentUser/Desktop", rule1.target);
    ASSERT_EQ(2U, rule1.mountFlags.size());
    EXPECT_EQ("bind", rule1.mountFlags[0]);
    EXPECT_EQ("rec", rule1.mountFlags[1]);
    EXPECT_TRUE(rule1.checkExists);
    ASSERT_EQ(2U, rule1.permissions.size());
    EXPECT_EQ("ohos.permission.READ_WRITE_DESKTOP", rule1.permissions[0]);
    EXPECT_EQ("ohos.permission.FILE_ACCESS_MANAGER", rule1.permissions[1]);

    // Second rule
    const auto &rule2 = manager.templateConfig_.conditionalRules[1];
    EXPECT_EQ("/mnt/user/100/docs", rule2.source);
    EXPECT_EQ("/storage/Users", rule2.target);
    ASSERT_EQ(2U, rule2.mountFlags.size());
    EXPECT_EQ("bind", rule2.mountFlags[0]);
    EXPECT_EQ("rec", rule2.mountFlags[1]);
    EXPECT_FALSE(rule2.checkExists);
    ASSERT_EQ(1U, rule2.permissions.size());
    EXPECT_EQ("ohos.permission.FILE_ACCESS_MANAGER", rule2.permissions[0]);

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseConditionalJson002
 * @tc.desc: ParseConditionalJson handles missing conditional section gracefully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseConditionalJson002, TestSize.Level0)
{
    const char *json = R"({})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    manager.ParseConditionalJson(root);
    EXPECT_TRUE(manager.templateConfig_.conditionalRules.empty());

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseConditionalJson003
 * @tc.desc: ParseConditionalJson ignores non-array conditional field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseConditionalJson003, TestSize.Level0)
{
    const char *json = R"({"conditional": "not-an-array"})";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    manager.templateConfig_.conditionalRules.push_back({});
    ASSERT_EQ(1U, manager.templateConfig_.conditionalRules.size());

    manager.ParseConditionalJson(root);
    EXPECT_EQ(1U, manager.templateConfig_.conditionalRules.size());

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseConditionalJson004
 * @tc.desc: ParseConditionalJson keeps entries even if target is missing, skips non-object items
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseConditionalJson004, TestSize.Level0)
{
    const char *json = R"({
        "conditional": [
            {"source": "/src", "target": "/tgt", "permissions": []},
            {"source": "/src2"},
            "bad-item"
        ]
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    manager.ParseConditionalJson(root);
    ASSERT_EQ(2U, manager.templateConfig_.conditionalRules.size());
    EXPECT_EQ("/tgt", manager.templateConfig_.conditionalRules[0].target);
    EXPECT_TRUE(manager.templateConfig_.conditionalRules[1].target.empty());

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseConditionalJson005
 * @tc.desc: ParseConditionalJson handles empty permissions array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseConditionalJson005, TestSize.Level0)
{
    const char *json = R"({
        "conditional": [
            {
                "source": "/src",
                "target": "/tgt",
                "permissions": []
            }
        ]
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    manager.ParseConditionalJson(root);
    ASSERT_EQ(1U, manager.templateConfig_.conditionalRules.size());
    EXPECT_TRUE(manager.templateConfig_.conditionalRules[0].permissions.empty());

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseConditionalJson006
 * @tc.desc: ParseConditionalJson exits early when root is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseConditionalJson006, TestSize.Level0)
{
    // Pass a JSON array (not object) → early return without crash
    const char *json = R"(["item1", "item2"])";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    manager.ParseConditionalJson(root);
    EXPECT_TRUE(manager.templateConfig_.conditionalRules.empty());

    cJSON_Delete(root);
}

/**
 * @tc.name: ParseConditionalJson007
 * @tc.desc: ParseConditionalRule handles non-string source, mount-flags, check-exists, permissions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxConfigParserTest, ParseConditionalJson007, TestSize.Level0)
{
    // Covers: non-string source, non-string mount-flags item,
    // non-bool check-exists, non-string permissions item, missing source field
    const char *json = R"({
        "conditional": [
            {
                "target": "/tgt",
                "source": 123,
                "mount-flags": [true, 456],
                "check-exists": "not-a-bool",
                "permissions": [789, false]
            },
            {
                "target": "/tgt2"
            }
        ]
    })";
    cJSON *root = cJSON_Parse(json);
    ASSERT_NE(root, nullptr);

    SandboxManager manager;
    manager.ParseConditionalJson(root);
    ASSERT_EQ(2U, manager.templateConfig_.conditionalRules.size());

    // Rule 1: source=123 is not string → source stays empty
    EXPECT_TRUE(manager.templateConfig_.conditionalRules[0].source.empty());
    EXPECT_EQ("/tgt", manager.templateConfig_.conditionalRules[0].target);
    // mount-flags items true/456 are not strings → skipped
    EXPECT_TRUE(manager.templateConfig_.conditionalRules[0].mountFlags.empty());
    // check-exists "not-a-bool" → not cJSON_IsBool → skips, keeps default true
    EXPECT_TRUE(manager.templateConfig_.conditionalRules[0].checkExists);
    // permissions items 789/false are not strings → skipped
    EXPECT_TRUE(manager.templateConfig_.conditionalRules[0].permissions.empty());

    // Rule 2: only target, no source/other fields → all remain empty/default
    EXPECT_EQ("/tgt2", manager.templateConfig_.conditionalRules[1].target);
    EXPECT_TRUE(manager.templateConfig_.conditionalRules[1].source.empty());

    cJSON_Delete(root);
}
} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
