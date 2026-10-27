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

/*
 * The cases in this file drive kernel device nodes that a real device kernel
 * provides but the emulator kernel does not: /dev/hkids and its cmdblacklist
 * (AIDS), and /dev/xpm (XPM owner id). test/BUILD.gn only adds this source
 * when !is_emulator, so the emulator build never compiles or runs them.
 */

#include "claw_sandbox_aids_test.h"
#include "claw_sandbox_manager_test.h"
#define private public
#include "sandbox_aids.h"
#include "sandbox_manager.h"
#undef private
#include "sandbox_error.h"
#include <cstdint>
#include <string>
#include <utility>

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

// Kept in sync with the constants of the same name in the sibling test files.
// Any appIdentifier will do: the kernel only echoes it back into the label.
static constexpr uint64_t TEST_APP_IDENTIFIER = 1001;

// The high half of an AccessTokenIDEx. It gates nothing - ValidateTokenType
// masks it off - so it is here only to keep the test tokens shaped like real ones.
static constexpr uint64_t TEST_TOKEN_ID_HIGH_BIT = (static_cast<uint64_t>(1) << 32);

// A callerTokenId with a non-zero low 32-bit token ID.
static constexpr uint64_t TEST_HAP_TOKEN_ID = TEST_TOKEN_ID_HIGH_BIT | 0x200D000D;

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
 * @tc.name: SetXpmOwnerId003
 * @tc.desc: Validate SetXpmOwnerId logic with valid shell type and normal appIdentifier.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetXpmOwnerId003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.type = "shell";
    config.appIdentifier = "20020026";
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    // In a typical UT environment, /dev/xpm might not exist, so open() fails,
    // which correctly logs a warning and returns SANDBOX_SUCCESS.
    // If mocked or run on a real device, ioctl executes and also returns SANDBOX_SUCCESS.
    EXPECT_EQ(SANDBOX_SUCCESS, manager.SetXpmOwnerId());
}

/**
 * @tc.name: SetXpmOwnerId004
 * @tc.desc: Validate SetXpmOwnerId safely handles appIdentifier lengths exceeding MAX_OWNERID_LEN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetXpmOwnerId004, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.type = "shell";
    // Create a string longer than MAX_OWNERID_LEN (64)
    config.appIdentifier = std::string(100, 'A');
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    // The truncation logic (std::min) should prevent memcpy_s from failing.
    EXPECT_EQ(SANDBOX_SUCCESS, manager.SetXpmOwnerId());
}

/**
 * @tc.name: SetAinfo002
 * @tc.desc: SetAinfo returns success for a shell sandbox too - the label is
 *           optional, so a missing /dev/hkids must not fail the launch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxManagerTest, SetAinfo002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    config.type = "shell";
    config.appIdentifier = "20020026";
    config.appIdentifierU64 = 20020026;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    EXPECT_EQ(SANDBOX_SUCCESS, manager.SetAinfo());
}

} // SANDBOX
} // AccessControl
} // OHOS
