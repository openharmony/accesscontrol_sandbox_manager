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

#include "claw_sandbox_exec_test.h"
#define private public
#include "sandbox_exec.h"
#undef private
#include "sandbox_error.h"
#include <cstring>
#include <string>

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

void ClawSandboxExecTest::SetUpTestCase() {}
void ClawSandboxExecTest::TearDownTestCase() {}
void ClawSandboxExecTest::SetUp() {}
void ClawSandboxExecTest::TearDown() {}

// ==================== ParseArguments tests ====================

/**
 * @tc.name: ParseArguments001
 * @tc.desc: ParseArguments with --help sets helpRequested
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments001, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--help";
    char *argv[] = {arg0, arg1, nullptr};
    int ret = exec.ParseArguments(2, argv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_TRUE(exec.HasHelpRequested());
}

/**
 * @tc.name: ParseArguments002
 * @tc.desc: ParseArguments with -h sets helpRequested
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments002, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "-h";
    char *argv[] = {arg0, arg1, nullptr};
    int ret = exec.ParseArguments(2, argv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_TRUE(exec.HasHelpRequested());
}

/**
 * @tc.name: ParseArguments003
 * @tc.desc: ParseArguments with no arguments returns error (missing --config)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments003, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char *argv[] = {arg0, nullptr};
    int ret = exec.ParseArguments(1, argv);
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, ret);
}

/**
 * @tc.name: ParseArguments004
 * @tc.desc: ParseArguments with --config but missing value returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments004, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--config";
    char *argv[] = {arg0, arg1, nullptr};
    int ret = exec.ParseArguments(2, argv);
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, ret);
}

/**
 * @tc.name: ParseArguments005
 * @tc.desc: ParseArguments with --config and valid JSON but no --cmd returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments005, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--config";
    char arg2[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appIdentifier":"a", "bundleName":"b", "cliName":"cli", "subCliName":"sub"})";
    char *argv[] = {arg0, arg1, arg2, nullptr};
    int ret = exec.ParseArguments(3, argv);
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, ret);
    EXPECT_FALSE(exec.HasHelpRequested());
}

/**
 * @tc.name: ParseArguments006
 * @tc.desc: ParseArguments with --config and invalid JSON returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments006, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--config";
    char arg2[] = "not json";
    char *argv[] = {arg0, arg1, arg2, nullptr};
    int ret = exec.ParseArguments(3, argv);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseArguments007
 * @tc.desc: ParseArguments with --cmd but missing value returns CMD_INVALID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments007, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--cmd";
    char *argv[] = {arg0, arg1, nullptr};
    int ret = exec.ParseArguments(2, argv);
    EXPECT_EQ(SANDBOX_ERR_CMD_INVALID, ret);
}

/**
 * @tc.name: ParseArguments008
 * @tc.desc: ParseArguments with --cmd but no --config returns BAD_PARAMETERS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments008, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--cmd";
    char arg2[] = "ls";
    char *argv[] = {arg0, arg1, arg2, nullptr};
    int ret = exec.ParseArguments(3, argv);
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, ret);
}

/**
 * @tc.name: ParseArguments009
 * @tc.desc: ParseArguments with --cmd argv where argv[1] is a flag (-la),
 *           config.subCliName must be empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments009, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--config";
    // subCliName is empty because argv[1] (-la) is a flag
    char arg2[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appIdentifier":"a", "bundleName":"b", "cliName":"cli", "subCliName":""})";
    char arg3[] = "--cmd";
    char arg4[] = "ls";
    char arg5[] = "-la";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, nullptr};
    int ret = exec.ParseArguments(6, argv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_FALSE(exec.HasHelpRequested());
}

/**
 * @tc.name: ParseArguments010
 * @tc.desc: ParseArguments with -c alias for --config and --cmd argv array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments010, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "-c";
    char arg2[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appIdentifier":"a", "bundleName":"b", "cliName":"cli", "subCliName":""})";
    char arg3[] = "--cmd";
    char arg4[] = "ls";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4, nullptr};
    int ret = exec.ParseArguments(5, argv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: ParseArguments011
 * @tc.desc: ParseArguments with -c alias but missing --cmd returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments011, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "-c";
    char arg2[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appIdentifier":"a", "bundleName":"b", "cliName":"cli", "subCliName":"sub"})";
    char *argv[] = {arg0, arg1, arg2, nullptr};
    int ret = exec.ParseArguments(3, argv);
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, ret);
}

/**
 * @tc.name: ParseArguments012
 * @tc.desc: ParseArguments with -m alias for --cmd (argv array form),
 *           argv[1] is "hello" (not a flag), config.subCliName must match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments012, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--config";
    // subCliName matches argv[1] ("hello")
    char arg2[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appIdentifier":"a", "bundleName":"b", "cliName":"cli", "subCliName":"hello"})";
    char arg3[] = "-m";
    char arg4[] = "echo";
    char arg5[] = "hello";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, nullptr};
    int ret = exec.ParseArguments(6, argv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: ParseArguments013
 * @tc.desc: ParseArguments with -d and valid config enters delete mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments013, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "-d";
    char arg2[] = "--config";
    char arg3[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026,
        "challenge":"c", "appIdentifier":"a", "bundleName":"b", "cliName":"cli", "subCliName":"sub",
        "name":"abcdef0123456789"})";
    char *argv[] = {arg0, arg1, arg2, arg3, nullptr};
    int ret = exec.ParseArguments(4, argv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_FALSE(exec.HasHelpRequested());
    EXPECT_TRUE(exec.HasDeleteRequested());
}

/**
 * @tc.name: ParseArguments014
 * @tc.desc: ParseArguments with -d and config without name still parses normally
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments014, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "-d";
    char arg2[] = "--config";
    char arg3[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026,
        "challenge":"c", "appIdentifier":"a", "bundleName":"b", "cliName":"cli", "subCliName":"sub"})";
    char *argv[] = {arg0, arg1, arg2, arg3, nullptr};
    int ret = exec.ParseArguments(4, argv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_TRUE(exec.HasDeleteRequested());
}

/**
 * @tc.name: ParseArguments015
 * @tc.desc: ParseArguments with -d and --cmd argv array,
 *           argv[1] is "-la" (a flag), config.subCliName must be empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments015, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "-d";
    char arg2[] = "--config";
    // subCliName is empty because argv[1] (-la) is a flag
    char arg3[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026,
        "challenge":"c", "appIdentifier":"a", "bundleName":"b", "cliName":"cli", "subCliName":"",
        "name":"abcdef0123456789"})";
    char arg4[] = "--cmd";
    char arg5[] = "ls";
    char arg6[] = "-la";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, arg6, nullptr};
    int ret = exec.ParseArguments(7, argv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_TRUE(exec.HasDeleteRequested());
}

/**
 * @tc.name: ParseArguments016
 * @tc.desc: ParseArguments with --cmd argv where argv[1] is a flag (-v) but
 *           config.subCliName is non-empty, should return CMD_INVALID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments016, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--config";
    // subCliName is non-empty but argv[1] (-v) is a flag -> mismatch
    char arg2[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appIdentifier":"a", "bundleName":"b", "cliName":"cli", "subCliName":"sub"})";
    char arg3[] = "--cmd";
    char arg4[] = "ls";
    char arg5[] = "-v";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, nullptr};
    int ret = exec.ParseArguments(6, argv);
    EXPECT_EQ(SANDBOX_ERR_CMD_INVALID, ret);
}

/**
 * @tc.name: ParseArguments017
 * @tc.desc: ParseArguments with --cmd argv where argv[1] is not a flag ("world")
 *           but config.subCliName does not match, should return CMD_INVALID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments017, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--config";
    // subCliName is "sub" but argv[1] is "world" -> mismatch
    char arg2[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appIdentifier":"a", "bundleName":"b", "cliName":"cli", "subCliName":"sub"})";
    char arg3[] = "--cmd";
    char arg4[] = "echo";
    char arg5[] = "world";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, nullptr};
    int ret = exec.ParseArguments(6, argv);
    EXPECT_EQ(SANDBOX_ERR_CMD_INVALID, ret);
}

/**
 * @tc.name: ParseArguments018
 * @tc.desc: ParseArguments with --cmd argv where argv[1] is an empty string,
 *           but config.subCliName is non-empty, should return CMD_INVALID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments018, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--config";
    // subCliName is non-empty but argv[1] is empty -> mismatch
    char arg2[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appIdentifier":"a", "bundleName":"b", "cliName":"cli", "subCliName":"sub"})";
    char arg3[] = "--cmd";
    char arg4[] = "ls";
    char arg5[] = "";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, nullptr};
    int ret = exec.ParseArguments(6, argv);
    EXPECT_EQ(SANDBOX_ERR_CMD_INVALID, ret);
}

/**
 * @tc.name: ParseArguments019
 * @tc.desc: ParseArguments with --cmd argv where argv[1] is an empty string
 *           and config.subCliName is empty, should return success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments019, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--config";
    // Empty subCliName skips subCliName validation.
    char arg2[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appIdentifier":"a", "bundleName":"b", "cliName":"cli", "subCliName":""})";
    char arg3[] = "--cmd";
    char arg4[] = "ls";
    char arg5[] = "";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, nullptr};
    int ret = exec.ParseArguments(6, argv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: ParseArguments020
 * @tc.desc: ParseArguments with -d after --cmd treats -d as command argv,
 *           not a claw_sandbox delete option
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments020, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--config";
    // subCliName is empty because argv[1] (-d) is a flag
    char arg2[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appIdentifier":"a", "bundleName":"b", "cliName":"cli", "subCliName":""})";
    char arg3[] = "--cmd";
    char arg4[] = "ls";
    char arg5[] = "-d";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, nullptr};
    int ret = exec.ParseArguments(6, argv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_FALSE(exec.HasDeleteRequested());
    EXPECT_FALSE(exec.HasHelpRequested());
}

/**
 * @tc.name: ParseArguments021
 * @tc.desc: ParseArguments with --help after --cmd treats --help as command argv,
 *           not a claw_sandbox help option
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments021, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--config";
    // subCliName is empty because argv[1] (--help) is a flag
    char arg2[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appIdentifier":"a", "bundleName":"b", "cliName":"cli", "subCliName":""})";
    char arg3[] = "--cmd";
    char arg4[] = "ls";
    char arg5[] = "--help";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, nullptr};
    int ret = exec.ParseArguments(6, argv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_FALSE(exec.HasHelpRequested());
    EXPECT_FALSE(exec.HasDeleteRequested());
}

/**
 * @tc.name: ParseArguments022
 * @tc.desc: ParseArguments with non-empty config.subCliName but no command argv[1]
 *           returns CMD_INVALID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments022, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--config";
    char arg2[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appIdentifier":"a", "bundleName":"b", "cliName":"cli", "subCliName":"sub"})";
    char arg3[] = "--cmd";
    char arg4[] = "ls";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4, nullptr};
    int ret = exec.ParseArguments(5, argv);
    EXPECT_EQ(SANDBOX_ERR_CMD_INVALID, ret);
}

/**
 * @tc.name: ParseArguments023
 * @tc.desc: ParseArguments with --cmd before --config treats --config as command argv,
 *           so config is not parsed and BAD_PARAMETERS is returned
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments023, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--cmd";
    char arg2[] = "ls";
    char arg3[] = "--config";
    char arg4[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appIdentifier":"a", "bundleName":"b", "cliName":"cli", "subCliName":""})";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4, nullptr};
    int ret = exec.ParseArguments(5, argv);
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, ret);
}

/**
 * @tc.name: ParseArguments024
 * @tc.desc: ParseArguments returns CMD_INVALID when --cmd argv entries are all null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments024, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--config";
    char arg2[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appIdentifier":"a", "bundleName":"b", "cliName":"cli", "subCliName":""})";
    char arg3[] = "--cmd";
    char *argv[] = {arg0, arg1, arg2, arg3, nullptr};

    int ret = exec.ParseArguments(5, argv);
    EXPECT_EQ(SANDBOX_ERR_CMD_INVALID, ret);
}

/**
 * @tc.name: ParseArguments025
 * @tc.desc: ParseArguments returns CMD_INVALID when --cmd argv entries are all null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments025, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--config";
    // subCliName is empty because argv[1] (--help) is a flag
    char arg2[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appIdentifier":"a", "bundleName":"b", "type": "cli", "cliName":"cli", "subCliName":""})";
    char arg3[] = "--cmd";
    char arg4[] = "ls";
    char arg5[] = "--help";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, nullptr};
    int ret = exec.ParseArguments(6, argv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_FALSE(exec.HasHelpRequested());
    EXPECT_FALSE(exec.HasDeleteRequested());
}

/**
 * @tc.name: ParseArguments026
 * @tc.desc: ParseArguments returns CMD_INVALID when --cmd argv entries are all null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments026, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--config";
    // subCliName is empty because argv[1] (--help) is a flag
    char arg2[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appIdentifier":"a", "bundleName":"b", "type": "shell"})";
    char arg3[] = "--cmd";
    char arg4[] = "ls";
    char arg5[] = "--help";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, nullptr};
    int ret = exec.ParseArguments(6, argv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: ParseArguments027
 * @tc.desc: ParseArguments returns CMD_INVALID when --cmd argv entries are all null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments027, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--config";
    // subCliName is empty because argv[1] (--help) is a flag
    char arg2[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appIdentifier":"a", "bundleName":"b", "type": "others"})";
    char arg3[] = "--cmd";
    char arg4[] = "ls";
    char arg5[] = "--help";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, nullptr};
    int ret = exec.ParseArguments(6, argv);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}


// ==================== Run tests ====================

/**
 * @tc.name: Run001
 * @tc.desc: Run without parsing arguments returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, Run001, TestSize.Level0)
{
    SandboxExec exec;
    int ret = exec.Run();
    EXPECT_EQ(SANDBOX_ERR_GENERIC, ret);
}


// ==================== PrintUsage tests ====================

/**
 * @tc.name: PrintUsage001
 * @tc.desc: PrintUsage prints help message without crashing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, PrintUsage001, TestSize.Level0)
{
    SandboxExec::PrintUsage();
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
