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

#include "claw_sandbox_aids_test.h"
#include "sandbox_aids.h"
#include "sandbox_error.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

void ClawSandboxAidsTest::SetUpTestCase() {}
void ClawSandboxAidsTest::TearDownTestCase() {}
void ClawSandboxAidsTest::SetUp() {}
void ClawSandboxAidsTest::TearDown() {}

/**
 * @tc.name: AidsSetLabel001
 * @tc.desc: Test calling the setLabel interface with the default valid device path, expecting a successful return.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel001, TestSize.Level0) {
    AidsClient aids;
    int ret = aids.setLabel();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: AidsSetLabel002
 * @tc.desc: Test calling the addBlacklist interface with the default valid device path to
 * add a cmdblacklist entry, expecting a successful return.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel002, TestSize.Level0) {
    AidsClient aids;
    int ret = aids.addBlacklist("date", "", 0);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: AidsSetLabel003
 * @tc.desc: Test calling the delBlacklist interface with the default valid device path to
 * delete an added cmdblacklist entry, expecting a successful return.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel003, TestSize.Level0) {
    AidsClient aids;
    int ret = aids.addBlacklist("date", "", 0);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ret = aids.delBlacklist("date", "", 0);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: AidsSetLabel004
 * @tc.desc: Test calling the clrBlacklist interface with the default valid device path to
 * clear the cmdblacklist, expecting a successful return.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel004, TestSize.Level0) {
    AidsClient aids;
    int ret = aids.clrBlacklist();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: AidsSetLabel005
 * @tc.desc: Test calling the setLabel interface with an invalid device path
 * (/dev/hkids_err), expecting a failure return.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel005, TestSize.Level0) {
    AidsClient aids("/dev/hkids_err");
    int ret = aids.setLabel();
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel006
 * @tc.desc: Test calling the addBlacklist interface with an invalid device path
 * (/dev/hkids_err), expecting a failure return.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel006, TestSize.Level0) {
    AidsClient aids("/dev/hkids_err");
    int ret = aids.addBlacklist("date", "", 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel007
 * @tc.desc: Test calling the delBlacklist interface with an invalid device path
 * (/dev/hkids_err), expecting a failure return.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel007, TestSize.Level0) {
    AidsClient aids("/dev/hkids_err");
    int ret = aids.delBlacklist("date", "", 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel008
 * @tc.desc: Test calling the clrBlacklist interface with an invalid device path
 * (/dev/hkids_err), expecting a failure return.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel008, TestSize.Level0) {
    AidsClient aids("/dev/hkids_err");
    int ret = aids.clrBlacklist();
    EXPECT_EQ(-1, ret);
}


/**
 * @tc.name: AidsSetLabel009
 * @tc.desc: Test calling delBlacklist with an oversized 'cmd' parameter, expecting it to
 * be intercepted by parameter validation and return a failure.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel009, TestSize.Level0) {
    AidsClient aids;
    std::string cmd = std::string(64, 'a');
    int ret = aids.delBlacklist(cmd, "", 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel010
 * @tc.desc: Test calling delBlacklist with an oversized 'subcmd' parameter, expecting
 * it to be intercepted by parameter validation and return a failure.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel010, TestSize.Level0) {
    AidsClient aids;
    std::string subcmd = std::string(64, 'a');
    int ret = aids.delBlacklist("date", subcmd, 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel011
 * @tc.desc: Test calling addBlacklist with an oversized 'cmd' parameter, expecting it to
 * be intercepted by parameter validation and return a failure.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel011, TestSize.Level0) {
    AidsClient aids;
    std::string cmd = std::string(64, 'a');
    int ret = aids.addBlacklist(cmd, "", 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel012
 * @tc.desc: Test calling addBlacklist with an oversized 'subcmd' parameter, expecting it to
 * be intercepted by parameter validation and return a failure.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel012, TestSize.Level0) {
    AidsClient aids;
    std::string subcmd = std::string(64, 'a');
    int ret = aids.addBlacklist("date", subcmd, 0);
    EXPECT_EQ(-1, ret);
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
