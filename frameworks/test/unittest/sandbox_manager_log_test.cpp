/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <string>
#include "sandbox_manager_log.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

class MaskRealPathTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void MaskRealPathTest::SetUpTestCase(void)
{}

void MaskRealPathTest::TearDownTestCase(void)
{}

void MaskRealPathTest::SetUp(void)
{}

void MaskRealPathTest::TearDown(void)
{}

/**
 * @tc.name: MaskRealPath001
 * @tc.desc: Test MaskRealPath with various paths: empty, slashes,
 *           segments of length 1-4, single-char segments, typical paths,
 *           trailing slash, no slash, deeply nested, long segment boundary.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MaskRealPathTest, MaskRealPath001, TestSize.Level0)
{
    // empty string
    EXPECT_EQ(SandboxManagerLog::MaskRealPath(""), "");

    // slash-only paths (no non-slash segments)
    EXPECT_EQ(SandboxManagerLog::MaskRealPath("/"), "/");
    EXPECT_EQ(SandboxManagerLog::MaskRealPath("//"), "//");

    // single segment, length 1-4
    EXPECT_EQ(SandboxManagerLog::MaskRealPath("a"), "*");
    EXPECT_EQ(SandboxManagerLog::MaskRealPath("ab"), "a*");
    EXPECT_EQ(SandboxManagerLog::MaskRealPath("abc"), "a**");
    EXPECT_EQ(SandboxManagerLog::MaskRealPath("abcd"), "a**d");

    // single-char segments with slashes
    EXPECT_EQ(SandboxManagerLog::MaskRealPath("/a/b"), "/*/*");
    EXPECT_EQ(SandboxManagerLog::MaskRealPath("/a/b/"), "/*/*/");

    // single-segment path, total length 6-13
    EXPECT_EQ(SandboxManagerLog::MaskRealPath("/abcde"), "/a***e");
    EXPECT_EQ(SandboxManagerLog::MaskRealPath("/abcdef"), "/ab***f");
    EXPECT_EQ(SandboxManagerLog::MaskRealPath("/abcdefg"), "/ab****g");
    EXPECT_EQ(SandboxManagerLog::MaskRealPath("/abcdefgh"), "/ab****gh");
    EXPECT_EQ(SandboxManagerLog::MaskRealPath("/abcdefghi"), "/ab*****hi");
    EXPECT_EQ(SandboxManagerLog::MaskRealPath("/abcdefghij"), "/abc*****ij");
    EXPECT_EQ(SandboxManagerLog::MaskRealPath("/abcdefghijk"), "/abc******jk");
    EXPECT_EQ(SandboxManagerLog::MaskRealPath("/abcdefghijkl"), "/abc******jkl");
    EXPECT_EQ(SandboxManagerLog::MaskRealPath("/abcdefghijklm"), "/abc*******klm");
}

} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
