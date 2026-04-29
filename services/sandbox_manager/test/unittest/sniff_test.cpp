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

#include "dec_test.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#ifdef DEC_ENABLED

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
constexpr uint32_t TOKEN_ID = 2145839127U;
constexpr uint32_t ANOTHER_TOKEN_ID = 2145839128U;
constexpr int32_t USER_ID = 100;
constexpr int32_t EL1_PATH = 0;
constexpr int32_t EL2_PATH_BASE = 1;
constexpr int32_t EL2_PATH_CLOUD = 2;
constexpr int32_t EL2_PATH_DIS = 3;
constexpr int32_t EL5_PATH = 4;
const std::string APPDATA_ROOT = "/storage/Users/currentUser/appdata";

std::vector<std::string> GetSniffPaths(const std::string &name)
{
    return {
        APPDATA_ROOT + "/el1/base/" + name,
        APPDATA_ROOT + "/el2/base/" + name,
        APPDATA_ROOT + "/el2/cloud/" + name,
        APPDATA_ROOT + "/el2/distributedfiles/" + name,
        APPDATA_ROOT + "/el5/base/" + name,
    };
}

std::vector<std::string> GetSourcePaths(const std::string &name)
{
    return {
        "/data/sniff_source/el1/base/" + name,
        "/data/sniff_source/el2/base/" + name,
        "/data/sniff_source/el2/cloud/" + name,
        "/data/sniff_source/el2/distributedfiles/" + name,
        "/data/sniff_source/el5/base/" + name,
    };
}

void ExpectAccessResult(uint32_t tokenId, const std::vector<std::string> &paths, int32_t expected)
{
    for (const auto &path : paths) {
        EXPECT_EQ(expected, TestAccess(tokenId, path, 0)) << path;
    }
}
}

class SniffTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
    static bool PrepareMountEnv();
    static void CleanupMountEnv();
};

void SniffTest::SetUpTestCase(void)
{
    OpenDevDec();
    PrepareMountEnv();
}

void SniffTest::TearDownTestCase(void)
{
    CleanupMountEnv();
    DecTestClose();
}

void SniffTest::SetUp()
{
    (void)DestroyByTokenid(TOKEN_ID, 0);
}

void SniffTest::TearDown()
{
    (void)DestroyByTokenid(TOKEN_ID, 0);
}

bool SniffTest::PrepareMountEnv()
{
    const auto alphaSourcePaths = GetSourcePaths("alpha");
    const auto barSourcePaths = GetSourcePaths("bar");
    return ExcuteCmd("[ -d /data/sniff_source ] && rm -rf /data/sniff_source || true") &&
        ExcuteCmd("umount /storage/Users/currentUser/appdata -l || true") &&
        ExcuteCmd("[ -d /storage/Users/currentUser/appdata ] && rm -rf /storage/Users/currentUser/appdata || true") &&
        ExcuteCmd("mkdir -p /data/sniff_source") &&
        ExcuteCmd("mkdir -p /data/sniff_source/el1/base") &&
        ExcuteCmd("mkdir -p /data/sniff_source/el2/base") &&
        ExcuteCmd("mkdir -p /data/sniff_source/el2/cloud") &&
        ExcuteCmd("mkdir -p /data/sniff_source/el2/distributedfiles") &&
        ExcuteCmd("mkdir -p /data/sniff_source/el5/base") &&
        ExcuteCmd(("mkdir -p " + alphaSourcePaths[EL1_PATH]).c_str()) &&
        ExcuteCmd(("mkdir -p " + alphaSourcePaths[EL2_PATH_BASE]).c_str()) &&
        ExcuteCmd(("mkdir -p " + alphaSourcePaths[EL2_PATH_CLOUD]).c_str()) &&
        ExcuteCmd(("mkdir -p " + alphaSourcePaths[EL2_PATH_DIS]).c_str()) &&
        ExcuteCmd(("mkdir -p " + alphaSourcePaths[EL5_PATH]).c_str()) &&
        ExcuteCmd(("mkdir -p " + alphaSourcePaths[EL1_PATH] + "/docs").c_str()) &&
        ExcuteCmd(("mkdir -p " + barSourcePaths[EL1_PATH]).c_str()) &&
        ExcuteCmd(("mkdir -p " + barSourcePaths[EL2_PATH_BASE]).c_str()) &&
        ExcuteCmd(("mkdir -p " + barSourcePaths[EL2_PATH_CLOUD]).c_str()) &&
        ExcuteCmd(("mkdir -p " + barSourcePaths[EL2_PATH_DIS]).c_str()) &&
        ExcuteCmd(("mkdir -p " + barSourcePaths[EL5_PATH]).c_str()) &&
        ExcuteCmd("mkdir -p /storage/Users/currentUser/appdata") &&
        ExcuteCmd("mount -t sharefs /data/sniff_source /storage/Users/currentUser/appdata "
            "-o override_support_delete -o sniffer -o user_id=100");
}

void SniffTest::CleanupMountEnv()
{
    (void)ExcuteCmd("umount /storage/Users/currentUser/appdata -l || true");
    (void)ExcuteCmd("[ -d /storage/Users/currentUser/appdata ] && rm -rf /storage/Users/currentUser/appdata || true");
    (void)ExcuteCmd("[ -d /storage/Users/currentUser ] && rmdir /storage/Users/currentUser || true");
    (void)ExcuteCmd("[ -d /storage/Users ] && rmdir /storage/Users || true");
    (void)ExcuteCmd("[ -d /data/sniff_source ] && rm -rf /data/sniff_source || true");
}

/**
 * @tc.name: SniffTest001
 * @tc.desc: All supported sniff paths are denied before authorization.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SniffTest, SniffTest001, TestSize.Level0)
{
    ExpectAccessResult(TOKEN_ID, GetSniffPaths("alpha"), -1);
}

/**
 * @tc.name: SniffTest002
 * @tc.desc: Exact path authorization grants access to the target path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SniffTest, SniffTest002, TestSize.Level0)
{
    const auto alphaPaths = GetSniffPaths("alpha");

    EXPECT_EQ(-1, TestAccess(TOKEN_ID, alphaPaths[EL2_PATH_BASE], 0));
    ASSERT_EQ(RET_OK,
        SetPath(TOKEN_ID, alphaPaths[EL2_PATH_BASE], DEC_MODE_RW, true, 0, USER_ID));
    ExpectAccessResult(TOKEN_ID, alphaPaths, 0);
    ExpectAccessResult(ANOTHER_TOKEN_ID, alphaPaths, -1);
}

/**
 * @tc.name: SniffTest003
 * @tc.desc: Authorization rooted at elx/base/name covers access under that name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SniffTest, SniffTest003, TestSize.Level0)
{
    const auto alphaPaths = GetSniffPaths("alpha");
    const std::string childPath = alphaPaths[EL1_PATH] + "/docs";

    EXPECT_EQ(-1, TestAccess(TOKEN_ID, childPath, 0));
    ASSERT_EQ(RET_OK, SetPath(TOKEN_ID, alphaPaths[EL1_PATH], DEC_MODE_RW, true, 0, USER_ID));
    EXPECT_EQ(RET_OK, TestAccess(TOKEN_ID, childPath, 0));
}

#ifdef DEC_EXT
/**
 * @tc.name: SniffTest004
 * @tc.desc: Authorizing the appdata root grants access to all supported sniff paths.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SniffTest, SniffTest004, TestSize.Level0)
{
    const auto alphaPaths = GetSniffPaths("alpha");

    ExpectAccessResult(TOKEN_ID, alphaPaths, -1);
    ASSERT_EQ(RET_OK, SetPath(TOKEN_ID, APPDATA_ROOT, DEC_MODE_RW, true, 0, USER_ID));
    ExpectAccessResult(TOKEN_ID, alphaPaths, RET_OK);
}
#endif // DEC_EXT

/**
 * @tc.name: SniffTest005
 * @tc.desc: Authorizing foo does not grant access to bar.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SniffTest, SniffTest005, TestSize.Level0)
{
    const auto fooPaths = GetSniffPaths("alpha");
    const auto barPaths = GetSniffPaths("bar");

    ASSERT_EQ(RET_OK, SetPath(TOKEN_ID, fooPaths[EL2_PATH_BASE], DEC_MODE_RW, true, 0, USER_ID));
    ExpectAccessResult(TOKEN_ID, fooPaths, 0);
    ExpectAccessResult(TOKEN_ID, barPaths, -1);
}

#ifdef DEC_EXT
/**
 * @tc.name: SniffTest006
 * @tc.desc: DestroyByTokenid revokes previously granted sniff access.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SniffTest, SniffTest006, TestSize.Level0)
{
    const auto alphaPaths = GetSniffPaths("alpha");

    ASSERT_EQ(RET_OK, SetPath(TOKEN_ID, APPDATA_ROOT, DEC_MODE_RW, true, 0, USER_ID));
    ExpectAccessResult(TOKEN_ID, alphaPaths, RET_OK);

    ASSERT_EQ(RET_OK, DestroyByTokenid(TOKEN_ID, 0));
    ExpectAccessResult(TOKEN_ID, alphaPaths, -1);

    ASSERT_EQ(RET_OK, SetPath(TOKEN_ID, alphaPaths[EL1_PATH], DEC_MODE_RW, true, 0, USER_ID));
    ExpectAccessResult(TOKEN_ID, alphaPaths, 0);
    ASSERT_EQ(RET_OK, DestroyByTokenid(TOKEN_ID, 0));
    ExpectAccessResult(TOKEN_ID, alphaPaths, -1);

    ASSERT_EQ(RET_OK, SetPath(TOKEN_ID, alphaPaths[EL2_PATH_BASE], DEC_MODE_RW, true, 0, USER_ID));
    ExpectAccessResult(TOKEN_ID, alphaPaths, 0);
    ASSERT_EQ(RET_OK, DestroyByTokenid(TOKEN_ID, 0));
    ExpectAccessResult(TOKEN_ID, alphaPaths, -1);

    ASSERT_EQ(RET_OK, SetPath(TOKEN_ID, alphaPaths[EL2_PATH_CLOUD], DEC_MODE_RW, true, 0, USER_ID));
    ExpectAccessResult(TOKEN_ID, alphaPaths, 0);
    ASSERT_EQ(RET_OK, DestroyByTokenid(TOKEN_ID, 0));
    ExpectAccessResult(TOKEN_ID, alphaPaths, -1);

    ASSERT_EQ(RET_OK, SetPath(TOKEN_ID, alphaPaths[EL2_PATH_DIS], DEC_MODE_RW, true, 0, USER_ID));
    ExpectAccessResult(TOKEN_ID, alphaPaths, 0);
    ASSERT_EQ(RET_OK, DestroyByTokenid(TOKEN_ID, 0));
    ExpectAccessResult(TOKEN_ID, alphaPaths, -1);

    ASSERT_EQ(RET_OK, SetPath(TOKEN_ID, alphaPaths[EL5_PATH], DEC_MODE_RW, true, 0, USER_ID));
    ExpectAccessResult(TOKEN_ID, alphaPaths, 0);
    ASSERT_EQ(RET_OK, DestroyByTokenid(TOKEN_ID, 0));
    ExpectAccessResult(TOKEN_ID, alphaPaths, -1);
}
#endif // DEC_EXT

/**
 * @tc.name: SniffTest007
 * @tc.desc: DeletePathByUser removes el1 base authorization and access fails again.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SniffTest, SniffTest007, TestSize.Level0)
{
    const auto alphaPaths = GetSniffPaths("alpha");

    ASSERT_EQ(RET_OK, SetPath(TOKEN_ID, alphaPaths[EL1_PATH], DEC_MODE_RW, true, 0, USER_ID));
    EXPECT_EQ(RET_OK, TestAccess(TOKEN_ID, alphaPaths[EL1_PATH], 0));

    ASSERT_EQ(RET_OK, DeletePathByUser(USER_ID, alphaPaths[EL1_PATH]));
    EXPECT_EQ(-1, TestAccess(TOKEN_ID, alphaPaths[EL1_PATH], 0));
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS

#endif
