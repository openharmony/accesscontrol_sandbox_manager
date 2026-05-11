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

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

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
    EXPECT_TRUE(config.nsFlags.empty());
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
    ASSERT_EQ(3U, config.nsFlags.size());
    EXPECT_EQ("net", config.nsFlags[0]);
    EXPECT_EQ("pid", config.nsFlags[1]);
    EXPECT_EQ("uts", config.nsFlags[2]);
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

// ==================== ParseCommand tests ====================

/**
 * @tc.name: ParseCommand001
 * @tc.desc: ParseCommand with basic command parsing - simple cmd, quotes, empty/whitespace input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseCommand001, TestSize.Level0)
{
    // Test simple command without quotes
    CmdInfo info = CmdParser::ParseCommand("echo hello world");
    ASSERT_EQ(3U, info.argv.size());
    EXPECT_EQ("echo", info.argv[0]);
    EXPECT_EQ("hello", info.argv[1]);
    EXPECT_EQ("world", info.argv[2]);

    // Test double-quoted arguments are preserved as-is
    CmdInfo info2 = CmdParser::ParseCommand("echo \"hello world\"");
    ASSERT_EQ(2U, info2.argv.size());
    EXPECT_EQ("echo", info2.argv[0]);
    EXPECT_EQ("hello world", info2.argv[1]);

    // Test single-quoted arguments are preserved as-is
    CmdInfo info3 = CmdParser::ParseCommand("echo 'hello world'");
    ASSERT_EQ(2U, info3.argv.size());
    EXPECT_EQ("echo", info3.argv[0]);
    EXPECT_EQ("hello world", info3.argv[1]);

    // Test empty string returns empty argv
    CmdInfo info4 = CmdParser::ParseCommand("");
    EXPECT_TRUE(info4.argv.empty());

    // Test whitespace-only string returns empty argv
    CmdInfo info5 = CmdParser::ParseCommand("   \t  \n  ");
    EXPECT_TRUE(info5.argv.empty());

    // Test raw command string is preserved with leading/trailing spaces
    CmdInfo info6 = CmdParser::ParseCommand("  mycommand arg1 arg2  ");
    EXPECT_EQ("  mycommand arg1 arg2  ", info6.raw);
    ASSERT_EQ(3U, info6.argv.size());
    EXPECT_EQ("mycommand", info6.argv[0]);
    EXPECT_EQ("arg1", info6.argv[1]);
    EXPECT_EQ("arg2", info6.argv[2]);

    // Test all Trim whitespace characters are treated as argument separators
    CmdInfo info7 = CmdParser::ParseCommand("cmd\narg1\rarg2\farg3\varg4");
    ASSERT_EQ(5U, info7.argv.size());
    EXPECT_EQ("cmd", info7.argv[0]);
    EXPECT_EQ("arg1", info7.argv[1]);
    EXPECT_EQ("arg2", info7.argv[2]);
    EXPECT_EQ("arg3", info7.argv[3]);
    EXPECT_EQ("arg4", info7.argv[4]);
}

/**
 * @tc.name: ParseCommand002
 * @tc.desc: ParseCommand with mixed quoted and unquoted arguments
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseCommand002, TestSize.Level0)
{
    CmdInfo info = CmdParser::ParseCommand("cmd arg1 \"arg with spaces\" arg3");
    ASSERT_EQ(4U, info.argv.size());
    EXPECT_EQ("cmd", info.argv[0]);
    EXPECT_EQ("arg1", info.argv[1]);
    EXPECT_EQ("arg with spaces", info.argv[2]);
    EXPECT_EQ("arg3", info.argv[3]);
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

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
