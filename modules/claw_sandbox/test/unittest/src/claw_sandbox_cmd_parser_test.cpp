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

#include "claw_sandbox_cmd_parser_test.h"
#include "sandbox_cmd_parser.h"
#include "sandbox_error.h"
#include <sched.h>
#include <cstdint>
#include <unistd.h>

/*
 * NOTE: execvp() and execl() are mocked via linker interposition in
 * execvp_mock_stub.cpp. That file defines the actual execvp() and execl()
 * symbols, which the linker resolves in preference to the libc versions.
 * This approach is more reliable than preprocessor-based mocking because
 * it operates at the linker level.
 */

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
static constexpr uint64_t TEST_HAP_TOKEN_ID = TEST_SYSTEM_APP_MASK | 0x200D000D;

struct ConfigJsonField {
    const char *key;
    std::string value;
};

static const ConfigJsonField BASE_CONFIG_FIELDS[] = {
    {"callerTokenId", "1"},
    {"callerPid", "1"},
    {"uid", "20020026"},
    {"gid", "20020026"},
    {"challenge", R"("ch")"},
    {"appid", R"("app")"},
    {"bundleName", R"("bundle")"},
    {"cliName", R"("cli")"},
    {"subCliName", R"("sub")"},
};

static std::string BuildConfigJsonWithoutField(const std::string &missingKey)
{
    std::string json = "{";
    bool first = true;
    for (const auto &field : BASE_CONFIG_FIELDS) {
        if (missingKey == field.key) {
            continue;
        }
        json += first ? "" : ",";
        json += "\"";
        json += field.key;
        json += "\":";
        json += field.value;
        first = false;
    }
    json += "}";
    return json;
}

static std::string BuildConfigJsonWithValue(const std::string &overrideKey,
    const std::string &overrideValue)
{
    std::string json = "{";
    bool first = true;
    for (const auto &field : BASE_CONFIG_FIELDS) {
        json += first ? "" : ",";
        json += "\"";
        json += field.key;
        json += "\":";
        json += (overrideKey == field.key) ? overrideValue : field.value;
        first = false;
    }
    json += "}";
    return json;
}

void ClawSandboxCmdParserTest::SetUpTestCase() {}
void ClawSandboxCmdParserTest::TearDownTestCase() {}
void ClawSandboxCmdParserTest::SetUp() {}
void ClawSandboxCmdParserTest::TearDown() {}

// ==================== ParseConfig tests ====================

/**
 * @tc.name: ParseConfig001
 * @tc.desc: ParseConfig with valid JSON containing all required fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig001, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 123456789,
        "callerPid": 1000,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "test-challenge",
        "appid": "com.example.app",
        "bundleName": "com.example.bundle",
        "cliName": "testCli",
        "subCliName": "testSubCli"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(123456789ULL, config.callerTokenId);
    EXPECT_EQ(1000U, config.callerPid);
    EXPECT_EQ(20020026U, config.uid);
    EXPECT_EQ(20020026U, config.gid);
    EXPECT_EQ("test-challenge", config.challenge);
    EXPECT_EQ("com.example.app", config.appid);
    EXPECT_EQ("com.example.bundle", config.bundleName);
    EXPECT_EQ("testCli", config.cliName);
    EXPECT_EQ("testSubCli", config.subCliName);
    EXPECT_TRUE(config.name.empty());
    // When nsFlags is not specified in JSON, it defaults to CLONE_NEWNS | CLONE_NEWNET
    EXPECT_EQ(static_cast<int>(CLONE_NEWNS | CLONE_NEWNET), config.nsFlags);
}

/**
 * @tc.name: ParseConfig002
 * @tc.desc: ParseConfig with invalid JSON string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig002, TestSize.Level0)
{
    const std::string json = "not valid json";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig003
 * @tc.desc: ParseConfig with missing required field (callerTokenId)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig003, TestSize.Level0)
{
    const std::string json = R"({
        "callerPid": 1000,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appid": "app",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig004
 * @tc.desc: ParseConfig with valid name (hex string)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig004, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appid": "app",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "name": "abcdef0123456789"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ("abcdef0123456789", config.name);
}

/**
 * @tc.name: ParseConfig005
 * @tc.desc: ParseConfig with invalid name (non-hex characters)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig005, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appid": "app",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "name": "hello-world!"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig006
 * @tc.desc: ParseConfig with name exceeding max length (64 chars)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig006, TestSize.Level0)
{
    std::string longName(65, 'a');
    std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appid": "app",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "name": ")" + longName + R"("
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig007
 * @tc.desc: ParseConfig with valid nsFlags array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig007, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appid": "app",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "nsFlags": ["net", "pid", "uts"]
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    int expectedFlags = CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWUTS;
    EXPECT_EQ(expectedFlags, config.nsFlags);
}

/**
 * @tc.name: ParseConfig008
 * @tc.desc: ParseConfig with nsFlags exceeding max count (10)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig008, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appid": "app",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "nsFlags": ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"]
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig009
 * @tc.desc: ParseConfig with nsFlags containing non-string element
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig009, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appid": "app",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "nsFlags": [123]
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig010
 * @tc.desc: ParseConfig with uint32 field out of range
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig010, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 1,
        "callerPid": -1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appid": "app",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig011
 * @tc.desc: ParseConfig with large uint64 tokenId (close to 2^53 safe boundary)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig011, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 9007199254740990,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appid": "app",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(9007199254740990ULL, config.callerTokenId);
}

/**
 * @tc.name: ParseConfig012
 * @tc.desc: ParseConfig with empty JSON object (all required fields missing)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig012, TestSize.Level0)
{
    const std::string json = "{}";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig013
 * @tc.desc: ParseConfig with string field exceeding max length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig013, TestSize.Level0)
{
    std::string longStr(257, 'x');
    std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appid": "app",
        "bundleName": "bundle",
        "cliName": ")" + longStr + R"(",
        "subCliName": "sub"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig014
 * @tc.desc: ParseConfig with nsFlags string exceeding max length per flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig014, TestSize.Level0)
{
    std::string longFlag(25, 'x');
    std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appid": "app",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "nsFlags": [")" + longFlag + R"("]
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig015
 * @tc.desc: ParseConfig rejects optional fields with wrong JSON types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig015, TestSize.Level0)
{
    const std::string invalidNameJson = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appid": "app",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "name": 123
    })";
    SandboxConfig config;
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, CmdParser::ParseConfig(invalidNameJson, config));

    const std::string invalidNsFlagsJson = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appid": "app",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "nsFlags": {"net": true}
    })";
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, CmdParser::ParseConfig(invalidNsFlagsJson, config));
}

/**
 * @tc.name: ParseConfig016
 * @tc.desc: ParseConfig rejects missing required numeric fields after callerTokenId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig016, TestSize.Level0)
{
    const char *missingFields[] = {"callerPid", "uid", "gid"};

    for (const char *field : missingFields) {
        SCOPED_TRACE(field);
        SandboxConfig config;
        EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
            CmdParser::ParseConfig(BuildConfigJsonWithoutField(field), config));
    }
}

/**
 * @tc.name: ParseConfig017
 * @tc.desc: ParseConfig rejects missing required string fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig017, TestSize.Level0)
{
    const char *missingFields[] = {"challenge", "appid", "bundleName",
        "cliName", "subCliName"};

    for (const char *field : missingFields) {
        SCOPED_TRACE(field);
        SandboxConfig config;
        EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
            CmdParser::ParseConfig(BuildConfigJsonWithoutField(field), config));
    }
}

/**
 * @tc.name: ParseConfig018
 * @tc.desc: ParseConfig rejects required numeric fields with wrong JSON types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig018, TestSize.Level0)
{
    const ConfigJsonField invalidFields[] = {
        {"callerTokenId", R"("1")"},
        {"callerPid", R"("1")"},
        {"uid", "true"},
        {"gid", "null"},
    };

    for (const auto &field : invalidFields) {
        SCOPED_TRACE(field.key);
        SandboxConfig config;
        EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
            CmdParser::ParseConfig(BuildConfigJsonWithValue(field.key, field.value), config));
    }
}

/**
 * @tc.name: ParseConfig019
 * @tc.desc: ParseConfig rejects uint32 values above the supported range
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig019, TestSize.Level0)
{
    const ConfigJsonField invalidFields[] = {
        {"callerPid", "4294967296"},
        {"uid", "4294967296"},
        {"gid", "4294967296"},
    };

    for (const auto &field : invalidFields) {
        SCOPED_TRACE(field.key);
        SandboxConfig config;
        EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
            CmdParser::ParseConfig(BuildConfigJsonWithValue(field.key, field.value), config));
    }
}

/**
 * @tc.name: ParseConfig020
 * @tc.desc: ParseConfig rejects required string fields with wrong JSON types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig020, TestSize.Level0)
{
    const ConfigJsonField invalidFields[] = {
        {"challenge", "123"},
        {"appid", "false"},
        {"bundleName", "{}"},
        {"cliName", "[]"},
        {"subCliName", "null"},
    };

    for (const auto &field : invalidFields) {
        SCOPED_TRACE(field.key);
        SandboxConfig config;
        EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
            CmdParser::ParseConfig(BuildConfigJsonWithValue(field.key, field.value), config));
    }
}

/**
 * @tc.name: ParseConfig021
 * @tc.desc: ParseConfig accepts callerTokenId values above the double safe boundary
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig021, TestSize.Level0)
{
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(
        BuildConfigJsonWithValue("callerTokenId", "9007199254740994"), config);

    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(9007199254740994ULL, config.callerTokenId);
}

/**
 * @tc.name: ParseConfig022
 * @tc.desc: ParseConfig rejects each required string field above its max length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig022, TestSize.Level0)
{
    const ConfigJsonField invalidFields[] = {
        {"challenge", "\"" + std::string(40961, 'c') + "\""},
        {"appid", "\"" + std::string(10241, 'a') + "\""},
        {"bundleName", "\"" + std::string(257, 'b') + "\""},
        {"subCliName", "\"" + std::string(257, 's') + "\""},
    };

    for (const auto &field : invalidFields) {
        SCOPED_TRACE(field.key);
        SandboxConfig config;
        EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
            CmdParser::ParseConfig(BuildConfigJsonWithValue(field.key, field.value), config));
    }
}

/**
 * @tc.name: ParseConfig023
 * @tc.desc: ParseConfig accepts empty optional name and empty nsFlags array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig023, TestSize.Level0)
{
    std::string json = "{";
    for (const auto &field : BASE_CONFIG_FIELDS) {
        json += "\"";
        json += field.key;
        json += "\":";
        json += field.value;
        json += ",";
    }
    json += R"("name":"","nsFlags":[]})";

    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_TRUE(config.name.empty());
    EXPECT_EQ(static_cast<int>(CLONE_NEWNS | CLONE_NEWNET), config.nsFlags);
}

// ==================== ParseCommandFromArgv tests ====================

/**
 * @tc.name: ParseCommandFromArgv001
 * @tc.desc: ParseCommandFromArgv copies a basic argv array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseCommandFromArgv001, TestSize.Level0)
{
    char arg0[] = "echo";
    char arg1[] = "hello";
    char arg2[] = "world";
    char *argv[] = {arg0, arg1, arg2};

    CmdInfo info = CmdParser::ParseCommandFromArgv(3, argv);
    ASSERT_EQ(3U, info.argv.size());
    EXPECT_EQ("echo", info.argv[0]);
    EXPECT_EQ("hello", info.argv[1]);
    EXPECT_EQ("world", info.argv[2]);
}

/**
 * @tc.name: ParseCommandFromArgv002
 * @tc.desc: ParseCommandFromArgv preserves each argv element as one argument
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseCommandFromArgv002, TestSize.Level0)
{
    char arg0[] = "cmd";
    char arg1[] = "arg with spaces";
    char arg2[] = "\"quoted value\"";
    char arg3[] = "";
    char *argv[] = {arg0, arg1, arg2, arg3};

    CmdInfo info = CmdParser::ParseCommandFromArgv(4, argv);
    ASSERT_EQ(4U, info.argv.size());
    EXPECT_EQ("cmd", info.argv[0]);
    EXPECT_EQ("arg with spaces", info.argv[1]);
    EXPECT_EQ("\"quoted value\"", info.argv[2]);
    EXPECT_EQ("", info.argv[3]);
}

/**
 * @tc.name: ParseCommandFromArgv003
 * @tc.desc: ParseCommandFromArgv returns empty argv for invalid inputs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseCommandFromArgv003, TestSize.Level0)
{
    char arg0[] = "ignored";
    char *argv[] = {arg0};

    CmdInfo zeroArgcInfo = CmdParser::ParseCommandFromArgv(0, argv);
    EXPECT_TRUE(zeroArgcInfo.argv.empty());

    CmdInfo negativeArgcInfo = CmdParser::ParseCommandFromArgv(-1, argv);
    EXPECT_TRUE(negativeArgcInfo.argv.empty());

    CmdInfo nullArgvInfo = CmdParser::ParseCommandFromArgv(1, nullptr);
    EXPECT_TRUE(nullArgvInfo.argv.empty());
}

/**
 * @tc.name: ParseCommandFromArgv004
 * @tc.desc: ParseCommandFromArgv skips null argv elements
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseCommandFromArgv004, TestSize.Level0)
{
    char arg0[] = "cmd";
    char arg2[] = "tail";
    char *argv[] = {arg0, nullptr, arg2};

    CmdInfo info = CmdParser::ParseCommandFromArgv(3, argv);
    ASSERT_EQ(2U, info.argv.size());
    EXPECT_EQ("cmd", info.argv[0]);
    EXPECT_EQ("tail", info.argv[1]);
}

/**
 * @tc.name: ParseCommandFromArgv005
 * @tc.desc: ParseCommandFromArgv stores string values instead of argv pointers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseCommandFromArgv005, TestSize.Level0)
{
    char arg0[] = "cmd";
    char arg1[] = "arg";
    char *argv[] = {arg0, arg1};

    CmdInfo info = CmdParser::ParseCommandFromArgv(2, argv);
    ASSERT_EQ(2U, info.argv.size());
    EXPECT_EQ("cmd", info.argv[0]);
    EXPECT_EQ("arg", info.argv[1]);

    arg1[0] = 'A';
    EXPECT_EQ("arg", info.argv[1]);
}

// ==================== ConvertNsFlags tests ====================

/**
 * @tc.name: ConvertNsFlags001
 * @tc.desc: ConvertNsFlags with empty vector returns CLONE_NEWNS | CLONE_NEWNET
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ConvertNsFlags001, TestSize.Level0)
{
    std::vector<std::string> flags;
    int result = CmdParser::ConvertNsFlags(flags);
    EXPECT_EQ(CLONE_NEWNS | CLONE_NEWNET, result);
}

/**
 * @tc.name: ConvertNsFlags002
 * @tc.desc: ConvertNsFlags with "pid" adds CLONE_NEWPID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ConvertNsFlags002, TestSize.Level0)
{
    std::vector<std::string> flags = {"pid"};
    int result = CmdParser::ConvertNsFlags(flags);
    EXPECT_TRUE(result & CLONE_NEWPID);
    EXPECT_TRUE(result & CLONE_NEWNS);
    EXPECT_TRUE(result & CLONE_NEWNET);
}

/**
 * @tc.name: ConvertNsFlags003
 * @tc.desc: ConvertNsFlags with "uts" adds CLONE_NEWUTS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ConvertNsFlags003, TestSize.Level0)
{
    std::vector<std::string> flags = {"uts"};
    int result = CmdParser::ConvertNsFlags(flags);
    EXPECT_TRUE(result & CLONE_NEWUTS);
}

/**
 * @tc.name: ConvertNsFlags004
 * @tc.desc: ConvertNsFlags with "ipc" adds CLONE_NEWIPC
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ConvertNsFlags004, TestSize.Level0)
{
    std::vector<std::string> flags = {"ipc"};
    int result = CmdParser::ConvertNsFlags(flags);
    EXPECT_TRUE(result & CLONE_NEWIPC);
}

/**
 * @tc.name: ConvertNsFlags005
 * @tc.desc: ConvertNsFlags with "user" adds CLONE_NEWUSER
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ConvertNsFlags005, TestSize.Level0)
{
    std::vector<std::string> flags = {"user"};
    int result = CmdParser::ConvertNsFlags(flags);
    EXPECT_TRUE(result & CLONE_NEWUSER);
}

/**
 * @tc.name: ConvertNsFlags006
 * @tc.desc: ConvertNsFlags with multiple flags combines all
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ConvertNsFlags006, TestSize.Level0)
{
    std::vector<std::string> flags = {"pid", "uts", "ipc", "user", "net"};
    int result = CmdParser::ConvertNsFlags(flags);
    EXPECT_TRUE(result & CLONE_NEWPID);
    EXPECT_TRUE(result & CLONE_NEWUTS);
    EXPECT_TRUE(result & CLONE_NEWIPC);
    EXPECT_TRUE(result & CLONE_NEWUSER);
    EXPECT_TRUE(result & CLONE_NEWNET);
    EXPECT_TRUE(result & CLONE_NEWNS);
}

/**
 * @tc.name: ConvertNsFlags007
 * @tc.desc: ConvertNsFlags with unknown flag name is silently ignored
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ConvertNsFlags007, TestSize.Level0)
{
    std::vector<std::string> flags = {"unknown", "bogus"};
    int result = CmdParser::ConvertNsFlags(flags);
    // Only base flags should be present
    EXPECT_EQ(CLONE_NEWNS | CLONE_NEWNET, result);
}

/**
 * @tc.name: ConvertNsFlags008
 * @tc.desc: ConvertNsFlags with "mnt" adds CLONE_NEWNS (duplicate, but valid)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ConvertNsFlags008, TestSize.Level0)
{
    std::vector<std::string> flags = {"mnt"};
    int result = CmdParser::ConvertNsFlags(flags);
    // CLONE_NEWNS is already in the base flags
    EXPECT_TRUE(result & CLONE_NEWNS);
}

// ==================== ExecuteCommand tests ====================

/**
 * @tc.name: ExecuteCommand001
 * @tc.desc: ExecuteCommand with valid command - execvp is mocked via linker
 *           interposition (execvp_mock_stub.cpp) to return -1 with errno=EACCES,
 *           so ExecuteCommand returns SANDBOX_ERR_CMD_INVALID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ExecuteCommand001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    cmdInfo.argv = {"echo", "hello"};
    manager.Initialize(config, cmdInfo);

    int ret = manager.ExecuteCommand();
    // execvp_mock_stub.cpp returns -1 with errno=EACCES, so ExecuteCommand
    // should return SANDBOX_ERR_CMD_INVALID
    EXPECT_EQ(SANDBOX_ERR_CMD_INVALID, ret);
}

/**
 * @tc.name: ExecuteCommand002
 * @tc.desc: ExecuteCommand with empty cmd falls back to execl which fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ExecuteCommand002, TestSize.Level0)
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
    EXPECT_EQ(SANDBOX_ERR_CMD_INVALID, ret);
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
