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
#include "sandbox_exec.h"
#include "sandbox_error.h"
#include <cstring>

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
 * @tc.desc: ParseArguments with --config and valid JSON but no --cmd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments005, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--config";
    char arg2[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appid":"a", "bundleName":"b", "cliName":"cli", "subCliName":"sub"})";
    char *argv[] = {arg0, arg1, arg2, nullptr};
    int ret = exec.ParseArguments(3, argv);
    // --cmd is optional, so this should succeed
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
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
 * @tc.desc: ParseArguments with --cmd but missing value returns error
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
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, ret);
}

/**
 * @tc.name: ParseArguments008
 * @tc.desc: ParseArguments with --cmd and empty string returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments008, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--cmd";
    char arg2[] = "";
    char *argv[] = {arg0, arg1, arg2, nullptr};
    int ret = exec.ParseArguments(3, argv);
    EXPECT_EQ(SANDBOX_ERR_CMD_INVALID, ret);
}

/**
 * @tc.name: ParseArguments009
 * @tc.desc: ParseArguments with valid --config and --cmd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments009, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--config";
    char arg2[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appid":"a", "bundleName":"b", "cliName":"cli", "subCliName":"sub"})";
    char arg3[] = "--cmd";
    char arg4[] = "ls -la";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4, nullptr};
    int ret = exec.ParseArguments(5, argv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_FALSE(exec.HasHelpRequested());
}

/**
 * @tc.name: ParseArguments010
 * @tc.desc: ParseArguments with -c alias for --config
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments010, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "-c";
    char arg2[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appid":"a", "bundleName":"b", "cliName":"cli", "subCliName":"sub"})";
    char *argv[] = {arg0, arg1, arg2, nullptr};
    int ret = exec.ParseArguments(3, argv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: ParseArguments011
 * @tc.desc: ParseArguments with -m alias for --cmd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxExecTest, ParseArguments011, TestSize.Level0)
{
    SandboxExec exec;
    char arg0[] = "claw_sandbox";
    char arg1[] = "--config";
    char arg2[] = R"({"callerTokenId":1, "callerPid":1, "uid":20020026, "gid":20020026, "challenge":"c",
        "appid":"a", "bundleName":"b", "cliName":"cli", "subCliName":"sub"})";
    char arg3[] = "-m";
    char arg4[] = "echo hello";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4, nullptr};
    int ret = exec.ParseArguments(5, argv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
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

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
