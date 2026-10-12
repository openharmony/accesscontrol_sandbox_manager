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

#include "sandbox_glob_pattern_test.h"
#include "sandbox_error.h"
#include "sandbox_glob_pattern.h"

#include <string>

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

namespace {
struct ValidPattern {
    const char *pattern;
    const char *prefix;
    const char *suffix;
};
} // namespace

void ClawSandboxGlobPatternTest::SetUpTestCase() {}
void ClawSandboxGlobPatternTest::TearDownTestCase() {}
void ClawSandboxGlobPatternTest::SetUp() {}
void ClawSandboxGlobPatternTest::TearDown() {}

/**
 * @tc.name: IsWildcardPattern001
 * @tc.desc: Any '*' claims the entry as a pattern; a path without one is literal.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxGlobPatternTest, IsWildcardPattern001, TestSize.Level0)
{
    EXPECT_FALSE(IsWildcardPattern(""));
    EXPECT_FALSE(IsWildcardPattern("/data/a"));
    EXPECT_FALSE(IsWildcardPattern("/data/a b.jpg"));
    EXPECT_TRUE(IsWildcardPattern("/data/*"));
    EXPECT_TRUE(IsWildcardPattern("/data/**"));
    EXPECT_TRUE(IsWildcardPattern("/data/**/*.jpg"));
}

/**
 * @tc.name: ParseFilePattern001
 * @tc.desc: A valid pattern splits into the fd path before '**' and the SUFFIX
 *           after it. An empty tail and the star-led empty literal both fold into
 *           an empty suffix; a literal tail keeps its slash; the star-led literal
 *           drops the star and the separating slash.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxGlobPatternTest, ParseFilePattern001, TestSize.Level0)
{
    const ValidPattern cases[] = {
        {"/**", "/", ""},
        {"/data/**", "/data/", ""},
        {"/data/**/*", "/data/", ""},
        {"/data/**/config.json", "/data/", "/config.json"},
        {"/data/**/a/b", "/data/", "/a/b"},
        {"/data/**/*.jpg", "/data/", ".jpg"},
        {"/data/**/*ll.jpg", "/data/", "ll.jpg"},
        {"/a/b/**/c", "/a/b/", "/c"},
    };
    for (const ValidPattern &c : cases) {
        FilePattern out;
        std::string why;
        EXPECT_EQ(SANDBOX_SUCCESS, ParseFilePattern(c.pattern, out, why)) << c.pattern;
        EXPECT_EQ(c.prefix, out.prefix) << c.pattern;
        EXPECT_EQ(c.suffix, out.suffix) << c.pattern;
        EXPECT_TRUE(why.empty()) << c.pattern;
    }
}

/**
 * @tc.name: ParseFilePattern002
 * @tc.desc: Every input outside the grammar is refused instead of being treated
 *           as a literal path or a partial pattern.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxGlobPatternTest, ParseFilePattern002, TestSize.Level0)
{
    const char *invalid[] = {
        "",
        "data/**",
        "/data/*",
        "/data/**/",
        "/data/**/b/",
        "/data/**abc",
        "/data/a**/b",
        "/data/**/**/b",
        "/data/**/*a/b",
        "/data/**/*l*l.jpg",
        "/data/**/foo*",
        "/data/**/b?",
        "/data/**/b[0]",
        "/data/**/b{c}",
        "/data/**/b\\c",
        "/data/../**/b",
        "/data/./**/b",
        "/data//b/**",
        "/data/**/b//c",
    };
    for (const char *pattern : invalid) {
        FilePattern out;
        std::string why;
        EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ParseFilePattern(pattern, out, why)) << pattern;
        EXPECT_FALSE(why.empty()) << pattern;
    }
}

/**
 * @tc.name: ParseFilePattern003
 * @tc.desc: A failed parse leaves the output untouched, so a caller that ignores
 *           the return code cannot act on a partially filled pattern.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxGlobPatternTest, ParseFilePattern003, TestSize.Level0)
{
    FilePattern out;
    out.prefix = "sentinel-prefix";
    out.suffix = "sentinel-suffix";
    std::string why;

    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ParseFilePattern("/data/**abc", out, why));
    EXPECT_EQ("sentinel-prefix", out.prefix);
    EXPECT_EQ("sentinel-suffix", out.suffix);
    EXPECT_FALSE(why.empty());
}

/**
 * @tc.name: ParseFilePattern004
 * @tc.desc: Each rule reports the reason it refused the pattern, so the config
 *           error is actionable.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxGlobPatternTest, ParseFilePattern004, TestSize.Level0)
{
    struct InvalidCase {
        const char *pattern;
        const char *reason;
    };
    const InvalidCase cases[] = {
        {"data/**", "must be an absolute path"},
        {"/data/**abc", "the '**' must be followed by '/' or the end of the pattern"},
        {"/data/**/**/b", "must contain exactly one '**'"},
        {"/data/**/b?", "unsupported glob metacharacter '?'"},
        {"/data/../**/b", "must not contain a '.' or '..' path component"},
    };
    for (const InvalidCase &c : cases) {
        FilePattern out;
        std::string why;
        EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ParseFilePattern(c.pattern, out, why)) << c.pattern;
        EXPECT_EQ(c.reason, why) << c.pattern;
    }
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
