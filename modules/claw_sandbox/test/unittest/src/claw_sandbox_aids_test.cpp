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

/*
 * Last on purpose. sandbox_log.h #undefs LOG_TAG and LOG_DOMAIN and redefines
 * them, and those are plain macros read where SANDBOX_LOGx is written, not
 * settings applied once. Any header included after this one that defines its own
 * LOG_TAG silently takes over, and the log lines go out under someone else's tag
 * and domain - which looks exactly like logging being broken.
 */
#include "sandbox_log.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

void ClawSandboxAidsTest::SetUpTestCase() {}
void ClawSandboxAidsTest::TearDownTestCase() {}
void ClawSandboxAidsTest::SetUp() {}
void ClawSandboxAidsTest::TearDown() {}

// Any appIdentifier will do: the kernel only echoes it back into the label.
static constexpr uint64_t TEST_APP_IDENTIFIER = 1001;

/**
 * @tc.name: AidsSetLabel001
 * @tc.desc: Test calling the SetLabel interface with the default valid device path, expecting a successful return.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel001, TestSize.Level0) {
    AidsClient aids;
    int ret = aids.SetLabel(0, TEST_APP_IDENTIFIER);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: AidsSetLabel002
 * @tc.desc: Test calling the AddBlacklist interface with the default valid device path to
 * add a cmdblacklist entry, expecting a successful return.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel002, TestSize.Level0) {
    AidsClient aids;
    int ret = aids.AddBlacklist("date", "", 0);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: AidsSetLabel003
 * @tc.desc: Test calling the DelBlacklist interface with the default valid device path to
 * delete an added cmdblacklist entry, expecting a successful return.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel003, TestSize.Level0) {
    AidsClient aids;
    int ret = aids.AddBlacklist("date", "", 0);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ret = aids.DelBlacklist("date", "", 0);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: AidsSetLabel004
 * @tc.desc: Test calling the ClearBlacklist interface with the default valid device path to
 * clear the cmdblacklist, expecting a successful return.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel004, TestSize.Level0) {
    AidsClient aids;
    int ret = aids.ClearBlacklist();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: AidsSetLabel005
 * @tc.desc: Test calling the SetLabel interface with an invalid device path
 * (/dev/hkids_err), expecting a failure return.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel005, TestSize.Level0) {
    AidsClient aids("/dev/hkids_err");
    int ret = aids.SetLabel(0, TEST_APP_IDENTIFIER);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel006
 * @tc.desc: Test calling the AddBlacklist interface with an invalid device path
 * (/dev/hkids_err), expecting a failure return.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel006, TestSize.Level0) {
    AidsClient aids("/dev/hkids_err");
    int ret = aids.AddBlacklist("date", "", 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel007
 * @tc.desc: Test calling the DelBlacklist interface with an invalid device path
 * (/dev/hkids_err), expecting a failure return.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel007, TestSize.Level0) {
    AidsClient aids("/dev/hkids_err");
    int ret = aids.DelBlacklist("date", "", 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel008
 * @tc.desc: Test calling the ClearBlacklist interface with an invalid device path
 * (/dev/hkids_err), expecting a failure return.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel008, TestSize.Level0) {
    AidsClient aids("/dev/hkids_err");
    int ret = aids.ClearBlacklist();
    EXPECT_EQ(-1, ret);
}


/**
 * @tc.name: AidsSetLabel009
 * @tc.desc: Test calling DelBlacklist with an oversized 'cmd' parameter, expecting it to
 * be intercepted by parameter validation and return a failure.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel009, TestSize.Level0) {
    AidsClient aids;
    std::string cmd = std::string(64, 'a');
    int ret = aids.DelBlacklist(cmd, "", 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel010
 * @tc.desc: Test calling DelBlacklist with an oversized 'subcmd' parameter, expecting
 * it to be intercepted by parameter validation and return a failure.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel010, TestSize.Level0) {
    AidsClient aids;
    std::string subcmd = std::string(64, 'a');
    int ret = aids.DelBlacklist("date", subcmd, 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel011
 * @tc.desc: Test calling AddBlacklist with an oversized 'cmd' parameter, expecting it to
 * be intercepted by parameter validation and return a failure.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel011, TestSize.Level0) {
    AidsClient aids;
    std::string cmd = std::string(64, 'a');
    int ret = aids.AddBlacklist(cmd, "", 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel012
 * @tc.desc: Test calling AddBlacklist with an oversized 'subcmd' parameter, expecting it to
 * be intercepted by parameter validation and return a failure.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel012, TestSize.Level0) {
    AidsClient aids;
    std::string subcmd = std::string(64, 'a');
    int ret = aids.AddBlacklist("date", subcmd, 0);
    EXPECT_EQ(-1, ret);
}

// ==================== AidsClient IsOpen + ioctl path coverage ====================
// The tests below use a mock fd (from open("/dev/null")) to bypass the IsOpen() check,
// so that strncpy_s overflow paths and ioctl paths are exercised regardless of
// whether the real /dev/hkids device exists in the test environment.
// The mock fd does not support hkids ioctls, so all ioctl() calls return -1.
// The AidsClient destructor closes the mock fd, covering the fd_ >= 0 branch.
// fd_ is assigned directly here, which skips the constructor - and the constructor
// is the only place fd_ would normally carry its fdsan tag. Mark the mock fd with
// the same site code the destructor closes with, otherwise the tagged close sees an
// unowned descriptor and fdsan aborts ("closing an fd you do not own") instead of
// reporting the leak this suite is actually exercising.
static int OpenMockFd()
{
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        SANDBOX_FDSAN_MARK(fd, SANDBOX_FDSAN_SITE_AIDS_DEVICE);
    }
    return fd;
}

/**
 * @tc.name: AidsSetLabel013
 * @tc.desc: When IsOpen() passes, SetLabel reaches the ioctl call and returns its
 *          failure result (non-zero).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel013, TestSize.Level0) {
    int mockFd = OpenMockFd();
    ASSERT_GE(mockFd, 0);
    AidsClient aids("/dev/hkids_err");
    aids.fd_ = mockFd;
    int ret = aids.SetLabel(0, TEST_APP_IDENTIFIER);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel014
 * @tc.desc: When IsOpen() passes with normal-length strings, AddBlacklist reaches
 *          the ioctl call and returns its failure result (non-zero).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel014, TestSize.Level0) {
    int mockFd = OpenMockFd();
    ASSERT_GE(mockFd, 0);
    AidsClient aids("/dev/hkids_err");
    aids.fd_ = mockFd;
    int ret = aids.AddBlacklist("date", "", 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel015
 * @tc.desc: When IsOpen() passes with normal-length strings, DelBlacklist reaches
 *          the ioctl call and returns its failure result (non-zero).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel015, TestSize.Level0) {
    int mockFd = OpenMockFd();
    ASSERT_GE(mockFd, 0);
    AidsClient aids("/dev/hkids_err");
    aids.fd_ = mockFd;
    int ret = aids.DelBlacklist("date", "", 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel016
 * @tc.desc: When IsOpen() passes, ClearBlacklist reaches the ioctl call and returns
 *          its failure result (non-zero).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel016, TestSize.Level0) {
    int mockFd = OpenMockFd();
    ASSERT_GE(mockFd, 0);
    AidsClient aids("/dev/hkids_err");
    aids.fd_ = mockFd;
    int ret = aids.ClearBlacklist();
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel017
 * @tc.desc: AddBlacklist with IsOpen()=true and cmd >= HKIDS_CMD_MAX_SIZE triggers
 *          strncpy_s truncation error and returns -1 BEFORE reaching ioctl.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel017, TestSize.Level0) {
    int mockFd = OpenMockFd();
    ASSERT_GE(mockFd, 0);
    AidsClient aids("/dev/hkids_err");
    aids.fd_ = mockFd;
    std::string overflowCmd(HKIDS_CMD_MAX_SIZE, 'a');
    int ret = aids.AddBlacklist(overflowCmd, "", 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel018
 * @tc.desc: AddBlacklist with IsOpen()=true and subcmd >= HKIDS_CMD_MAX_SIZE triggers
 *          strncpy_s truncation error and returns -1 BEFORE reaching ioctl.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel018, TestSize.Level0) {
    int mockFd = OpenMockFd();
    ASSERT_GE(mockFd, 0);
    AidsClient aids("/dev/hkids_err");
    aids.fd_ = mockFd;
    std::string overflowSubcmd(HKIDS_CMD_MAX_SIZE, 'a');
    int ret = aids.AddBlacklist("date", overflowSubcmd, 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel019
 * @tc.desc: DelBlacklist with IsOpen()=true and cmd >= HKIDS_CMD_MAX_SIZE triggers
 *          strncpy_s truncation error and returns -1 BEFORE reaching ioctl.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel019, TestSize.Level0) {
    int mockFd = OpenMockFd();
    ASSERT_GE(mockFd, 0);
    AidsClient aids("/dev/hkids_err");
    aids.fd_ = mockFd;
    std::string overflowCmd(HKIDS_CMD_MAX_SIZE, 'a');
    int ret = aids.DelBlacklist(overflowCmd, "", 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsSetLabel020
 * @tc.desc: DelBlacklist with IsOpen()=true and subcmd >= HKIDS_CMD_MAX_SIZE triggers
 *          strncpy_s truncation error and returns -1 BEFORE reaching ioctl.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsSetLabel020, TestSize.Level0) {
    int mockFd = OpenMockFd();
    ASSERT_GE(mockFd, 0);
    AidsClient aids("/dev/hkids_err");
    aids.fd_ = mockFd;
    std::string overflowSubcmd(HKIDS_CMD_MAX_SIZE, 'a');
    int ret = aids.DelBlacklist("date", overflowSubcmd, 0);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: AidsIsOpenFalse001
 * @tc.desc: After constructing AidsClient without a valid device, IsOpen() and fd_
 *          both confirm the device is not open.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxAidsTest, AidsIsOpenFalse001, TestSize.Level0) {
    AidsClient aids("/dev/hkids_err");
    EXPECT_FALSE(aids.IsOpen());
    EXPECT_LT(aids.fd_, 0);
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
