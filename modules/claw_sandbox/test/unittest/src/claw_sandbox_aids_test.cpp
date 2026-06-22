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
#define private public
#include "sandbox_aids.h"
#undef private
#include "sandbox_error.h"
#include <fcntl.h>
#include <unistd.h>

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

// ==================== AidsClient isOpen + ioctl path coverage ====================
// The tests below use a mock fd (from open("/dev/null")) to bypass the isOpen() check,
// so that strncpy_s overflow paths and ioctl paths are exercised regardless of
// whether the real /dev/hkids device exists in the test environment.
// The mock fd does not support hkids ioctls, so all ioctl() calls return -1.
// The AidsClient destructor closes the mock fd, covering the fd_ >= 0 branch.

/**
 * @tc.name: AidsSetLabel013
 * @tc.desc: When isOpen() passes, setLabel reaches the ioctl call and returns its
 *          failure result (non-zero).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel013, TestSize.Level0) {
    int mockFd = open("/dev/null", O_RDWR);
    ASSERT_GE(mockFd, 0);
    AidsClient aids("/dev/hkids_err");
    aids.fd_ = mockFd;
    int ret = aids.setLabel();
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel014
 * @tc.desc: When isOpen() passes with normal-length strings, addBlacklist reaches
 *          the ioctl call and returns its failure result (non-zero).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel014, TestSize.Level0) {
    int mockFd = open("/dev/null", O_RDWR);
    ASSERT_GE(mockFd, 0);
    AidsClient aids("/dev/hkids_err");
    aids.fd_ = mockFd;
    int ret = aids.addBlacklist("date", "", 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel015
 * @tc.desc: When isOpen() passes with normal-length strings, delBlacklist reaches
 *          the ioctl call and returns its failure result (non-zero).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel015, TestSize.Level0) {
    int mockFd = open("/dev/null", O_RDWR);
    ASSERT_GE(mockFd, 0);
    AidsClient aids("/dev/hkids_err");
    aids.fd_ = mockFd;
    int ret = aids.delBlacklist("date", "", 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel016
 * @tc.desc: When isOpen() passes, clrBlacklist reaches the ioctl call and returns
 *          its failure result (non-zero).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel016, TestSize.Level0) {
    int mockFd = open("/dev/null", O_RDWR);
    ASSERT_GE(mockFd, 0);
    AidsClient aids("/dev/hkids_err");
    aids.fd_ = mockFd;
    int ret = aids.clrBlacklist();
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel017
 * @tc.desc: addBlacklist with isOpen()=true and cmd >= HKIDS_CMD_MAX_SIZE triggers
 *          strncpy_s truncation error and returns -1 BEFORE reaching ioctl.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel017, TestSize.Level0) {
    int mockFd = open("/dev/null", O_RDWR);
    ASSERT_GE(mockFd, 0);
    AidsClient aids("/dev/hkids_err");
    aids.fd_ = mockFd;
    std::string overflowCmd(HKIDS_CMD_MAX_SIZE, 'a');
    int ret = aids.addBlacklist(overflowCmd, "", 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel018
 * @tc.desc: addBlacklist with isOpen()=true and subcmd >= HKIDS_CMD_MAX_SIZE triggers
 *          strncpy_s truncation error and returns -1 BEFORE reaching ioctl.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel018, TestSize.Level0) {
    int mockFd = open("/dev/null", O_RDWR);
    ASSERT_GE(mockFd, 0);
    AidsClient aids("/dev/hkids_err");
    aids.fd_ = mockFd;
    std::string overflowSubcmd(HKIDS_CMD_MAX_SIZE, 'a');
    int ret = aids.addBlacklist("date", overflowSubcmd, 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel019
 * @tc.desc: delBlacklist with isOpen()=true and cmd >= HKIDS_CMD_MAX_SIZE triggers
 *          strncpy_s truncation error and returns -1 BEFORE reaching ioctl.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel019, TestSize.Level0) {
    int mockFd = open("/dev/null", O_RDWR);
    ASSERT_GE(mockFd, 0);
    AidsClient aids("/dev/hkids_err");
    aids.fd_ = mockFd;
    std::string overflowCmd(HKIDS_CMD_MAX_SIZE, 'a');
    int ret = aids.delBlacklist(overflowCmd, "", 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel020
 * @tc.desc: delBlacklist with isOpen()=true and subcmd >= HKIDS_CMD_MAX_SIZE triggers
 *          strncpy_s truncation error and returns -1 BEFORE reaching ioctl.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel020, TestSize.Level0) {
    int mockFd = open("/dev/null", O_RDWR);
    ASSERT_GE(mockFd, 0);
    AidsClient aids("/dev/hkids_err");
    aids.fd_ = mockFd;
    std::string overflowSubcmd(HKIDS_CMD_MAX_SIZE, 'a');
    int ret = aids.delBlacklist("date", overflowSubcmd, 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsIsOpenFalse001
 * @tc.desc: After constructing AidsClient without a valid device, isOpen() and fd_
 *          both confirm the device is not open.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsIsOpenFalse001, TestSize.Level0) {
    AidsClient aids("/dev/hkids_err");
    EXPECT_FALSE(aids.isOpen());
    EXPECT_LT(aids.fd_, 0);
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
