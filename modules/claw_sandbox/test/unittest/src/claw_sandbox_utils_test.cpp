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

#include "claw_sandbox_utils_test.h"
#include "sandbox_utils.h"

#include <climits>
#include <cstdint>
#include <cstdio>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

void ClawSandboxUtilsTest::SetUpTestCase() {}
void ClawSandboxUtilsTest::TearDownTestCase() {}
void ClawSandboxUtilsTest::SetUp() {}
void ClawSandboxUtilsTest::TearDown() {}

/**
 * @tc.name: GetRealPath001
 * @tc.desc: GetRealPath resolves an existing absolute path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxUtilsTest, GetRealPath001, TestSize.Level0)
{
    EXPECT_EQ("/", GetRealPath("/"));
}

/**
 * @tc.name: GetRealPath002
 * @tc.desc: GetRealPath returns an empty string for a path that cannot be resolved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxUtilsTest, GetRealPath002, TestSize.Level0)
{
    EXPECT_EQ("", GetRealPath("/claw_sandbox_ut_no_such_path/nope"));
    EXPECT_EQ("", GetRealPath(""));
}

namespace {
/*
 * A directory this process can create things in. IsPathUnder resolves both of
 * its arguments through realpath, so every path in these cases has to exist -
 * a made-up path only ever exercises the "unresolvable" branch.
 */
std::string WritableDir()
{
    const char *envDir = getenv("TMPDIR");
    const std::vector<std::string> candidates = {
        (envDir != nullptr && envDir[0] == '/') ? std::string(envDir) : std::string(),
        "/data/local/tmp", "/data", "/tmp", ".",
    };
    for (const std::string &dir : candidates) {
        if (dir.empty()) {
            continue;
        }
        const std::string probe = dir + "/claw_ut_utils_" + std::to_string(getpid());
        if (mkdir(probe.c_str(), S_IRWXU) == 0) {
            rmdir(probe.c_str());
            return dir;
        }
    }
    return "";
}
} // namespace

/**
 * @tc.name: ParseDecimalU64_001
 * @tc.desc: A run of digits and nothing else parses, including the largest value
 *           a uint64_t holds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxUtilsTest, ParseDecimalU64_001, TestSize.Level0)
{
    uint64_t value = 1;
    EXPECT_TRUE(ParseDecimalU64("0", value));
    EXPECT_EQ(0u, value);

    EXPECT_TRUE(ParseDecimalU64("4660", value));
    EXPECT_EQ(4660u, value);

    EXPECT_TRUE(ParseDecimalU64("18446744073709551615", value));
    EXPECT_EQ(UINT64_MAX, value);
}

/**
 * @tc.name: ParseDecimalU64_002
 * @tc.desc: Nothing numeric at all is rejected: the from_chars error code branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxUtilsTest, ParseDecimalU64_002, TestSize.Level0)
{
    uint64_t value = 0;
    EXPECT_FALSE(ParseDecimalU64("", value));
    EXPECT_FALSE(ParseDecimalU64("abc", value));
    EXPECT_FALSE(ParseDecimalU64(" 12", value));   // no leading space, unlike strtoull
}

/**
 * @tc.name: ParseDecimalU64_003
 * @tc.desc: Digits followed by anything else are rejected: from_chars stops
 *           early and succeeds, so the "consumed it all" half of the condition
 *           is the only thing that catches this
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxUtilsTest, ParseDecimalU64_003, TestSize.Level0)
{
    uint64_t value = 0;
    EXPECT_FALSE(ParseDecimalU64("12abc", value));
    EXPECT_FALSE(ParseDecimalU64("12 ", value));
    EXPECT_FALSE(ParseDecimalU64("1.5", value));
}

/**
 * @tc.name: ParseDecimalU64_004
 * @tc.desc: A sign is rejected rather than wrapped, and a value past UINT64_MAX
 *           is rejected rather than saturated. Both are why from_chars is used
 *           here instead of strtoull, which would turn "-1" into UINT64_MAX.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxUtilsTest, ParseDecimalU64_004, TestSize.Level0)
{
    uint64_t value = 7;
    EXPECT_FALSE(ParseDecimalU64("-1", value));
    EXPECT_FALSE(ParseDecimalU64("+1", value));
    EXPECT_FALSE(ParseDecimalU64("18446744073709551616", value));  // UINT64_MAX + 1
}

/**
 * @tc.name: IsPathUnder001
 * @tc.desc: A path that does not resolve is not under anything, and nothing is
 *           under a directory that does not resolve
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxUtilsTest, IsPathUnder001, TestSize.Level0)
{
    EXPECT_FALSE(IsPathUnder("/claw_sandbox_ut_no_such_path/nope", "/"));
    EXPECT_FALSE(IsPathUnder("/", "/claw_sandbox_ut_no_such_dir"));
    EXPECT_FALSE(IsPathUnder("", "/"));
    EXPECT_FALSE(IsPathUnder("/", ""));
}

/**
 * @tc.name: IsPathUnder002
 * @tc.desc: Root contains every resolvable path, and a path equals itself
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxUtilsTest, IsPathUnder002, TestSize.Level0)
{
    // realDir == "/" takes its own branch, because the generic test below would
    // compare against a one-character prefix and then look for a second '/'.
    EXPECT_TRUE(IsPathUnder("/", "/"));

    const std::string dir = WritableDir();
    ASSERT_FALSE(dir.empty());
    EXPECT_TRUE(IsPathUnder(dir, "/"));
    // Same path both sides: equal, so contained.
    EXPECT_TRUE(IsPathUnder(dir, dir));
}

/**
 * @tc.name: IsPathUnder003
 * @tc.desc: Real containment, and the three ways the prefix test says no: too
 *           short, different prefix, and a prefix that is not a whole component
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxUtilsTest, IsPathUnder003, TestSize.Level0)
{
    const std::string base = WritableDir();
    ASSERT_FALSE(base.empty());
    const std::string tag = std::to_string(getpid());
    const std::string dir = base + "/claw_ut_x_" + tag;
    const std::string inside = dir + "/child";
    // dir's spelling plus a suffix: a string prefix match with no component
    // boundary, which is the case a plain prefix test gets wrong.
    const std::string sibling = dir + "_sib";
    // Longer than dir and sharing none of its last component, which is the only
    // way to reach the compare() arm - a shorter path stops at the size check.
    const std::string otherChild = base + "/claw_ut_y_" + tag + "/child";

    ASSERT_EQ(0, mkdir(dir.c_str(), S_IRWXU));
    ASSERT_EQ(0, mkdir(inside.c_str(), S_IRWXU));
    ASSERT_EQ(0, mkdir(sibling.c_str(), S_IRWXU));
    ASSERT_EQ(0, mkdir((base + "/claw_ut_y_" + tag).c_str(), S_IRWXU));
    ASSERT_EQ(0, mkdir(otherChild.c_str(), S_IRWXU));

    EXPECT_TRUE(IsPathUnder(inside, dir));        // contained
    EXPECT_FALSE(IsPathUnder(dir, inside));       // shorter than the directory
    EXPECT_FALSE(IsPathUnder(base, dir));         // shorter again, via the parent
    EXPECT_FALSE(IsPathUnder(sibling, dir));      // prefix matches, no '/' boundary
    EXPECT_FALSE(IsPathUnder(otherChild, dir));   // longer, prefix differs

    rmdir(otherChild.c_str());
    rmdir((base + "/claw_ut_y_" + tag).c_str());
    rmdir(sibling.c_str());
    rmdir(inside.c_str());
    rmdir(dir.c_str());
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
