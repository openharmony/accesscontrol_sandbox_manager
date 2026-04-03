/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include <vector>
#include <gtest/gtest.h>
#include <mac_adapter.h>
#include "sandbox_manager_err_code.h"
#include "policy_info.h"

#ifdef DEC_ENABLED
const uint64_t TOKEN_ID = 123;
const uint64_t TOKEN_ID_SET_DENY_CFG = 124;
const uint64_t TOKEN_ID_ALLOW_MODE = 125;
const uint64_t TOKEN_ID_DENY_MODE = 126;
const uint64_t TOKEN_ID_EXISTING_RULE = 127;
const uint64_t TOKEN_ID_NEW_RULE = 128;
const int32_t USER_ID = 100;

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
const std::vector<uint32_t> ALLOW_MODES = {
    DEC_MODE_READ,
    DEC_MODE_WRITE,
    DEC_CREATE_MODE,
    DEC_DELETE_MODE,
    DEC_RENAME_MODE,
    DEC_MODE_READ | DEC_MODE_WRITE,
    DEC_MODE_READ | DEC_CREATE_MODE | DEC_DELETE_MODE,
    DEC_MODE_WRITE | DEC_RENAME_MODE,
    DEC_MODE_READ | DEC_MODE_WRITE | DEC_CREATE_MODE | DEC_DELETE_MODE | DEC_RENAME_MODE,
};

const std::vector<uint32_t> DENY_MODES = {
    OperateMode::DENY_READ_MODE,
    OperateMode::DENY_WRITE_MODE,
    OperateMode::DENY_READ_MODE | OperateMode::DENY_WRITE_MODE,
    OperateMode::DENY_READ_MODE | DEC_DENY_RENAME,
    OperateMode::DENY_WRITE_MODE | DEC_DENY_REMOVE,
};
} // namespace

class MacAdapterTestCase : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void MacAdapterTestCase::SetUpTestCase(void)
{
    OpenDevDec();
}

void MacAdapterTestCase::TearDownTestCase(void)
{
    DecTestClose();
}

void MacAdapterTestCase::SetUp(void)
{}

void MacAdapterTestCase::TearDown(void)
{}

/**
 * @tc.name: MacAdapterTestCase001
 * @tc.desc: Test set deny
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MacAdapterTestCase, MacAdapterTestCase001, TestSize.Level0)
{
    EXPECT_EQ(SetPath(TOKEN_ID, "/testpath_001/non_persist_dir", DEC_MODE_RW, false, 0, USER_ID), 0);
    EXPECT_EQ(SetPath(TOKEN_ID, "/testpath_001/persist_dir", DEC_MODE_RW, true, 0, USER_ID), 0);
    EXPECT_EQ(SetPath(TOKEN_ID, "/testpath_001/dir/non_persist_file", DEC_MODE_RW, false, 0, USER_ID), 0);
    EXPECT_EQ(SetPath(TOKEN_ID, "/testpath_001/dir/persist_file", DEC_MODE_RW, false, 0, USER_ID), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID, 0), 0);

    EXPECT_EQ(DenyPath(0, "/testpath_001/non_persist_dir", DEC_DENY_SET, 0, USER_ID), 0);
    EXPECT_EQ(DenyPath(0, "/testpath_001/persist_dir", DEC_DENY_SET, 0, USER_ID), 0);
    EXPECT_EQ(DenyPath(0, "/testpath_001/dir", DEC_DENY_SET_ALL, 0, USER_ID), 0);

    EXPECT_EQ(SetPath(TOKEN_ID, "/testpath_001/non_persist_dir", DEC_MODE_RW, false, 0, USER_ID), -1);
    EXPECT_EQ(SetPath(TOKEN_ID, "/testpath_001/persist_dir", DEC_MODE_RW, true, 0, USER_ID), -1);
    EXPECT_EQ(SetPath(TOKEN_ID, "/testpath_001/non_persist_dir/file", DEC_MODE_RW, false, 0, USER_ID), 0);
    EXPECT_EQ(SetPath(TOKEN_ID, "/testpath_001/persist_dir/file", DEC_MODE_RW, true, 0, USER_ID), 0);
    EXPECT_EQ(SetPath(TOKEN_ID, "/testpath_001/dir", DEC_MODE_RW, false, 0, USER_ID), -1);
    EXPECT_EQ(SetPath(TOKEN_ID, "/testpath_001/dir", DEC_MODE_RW, true, 0, USER_ID), -1);
    EXPECT_EQ(SetPath(TOKEN_ID, "/testpath_001/dir/non_persist_file", DEC_MODE_RW, false, 0, USER_ID), -1);
    EXPECT_EQ(SetPath(TOKEN_ID, "/testpath_001/dir/persist_file", DEC_MODE_RW, true, 0, USER_ID), -1);

    EXPECT_EQ(DelDenyPath(0, "/testpath_001/non_persist_dir"), 0);
    EXPECT_EQ(DelDenyPath(0, "/testpath_001/persist_dir"), 0);
    EXPECT_EQ(DelDenyPath(0, "/testpath_001/dir"), 0);
}

/**
 * @tc.name: MacAdapterTestCase002
 * @tc.desc: Test SetDenyCfg applies set_policy and set_policy_all deny bits
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MacAdapterTestCase, MacAdapterTestCase002, TestSize.Level0)
{
    MacAdapter macAdapter;
    macAdapter.Init();

    std::string denyCfg = R"([
        {"path":"/testpath_002/non_persist_dir", "rename":0, "delete":0, "inherit":0, "set_policy":1},
        {"path":"/testpath_002/dir", "rename":0, "delete":0, "inherit":0, "set_policy_all":1}
    ])";
    EXPECT_EQ(macAdapter.SetDenyCfg(denyCfg), SANDBOX_MANAGER_OK);

    EXPECT_EQ(DestroyByTokenid(TOKEN_ID_SET_DENY_CFG, 0), 0);
    EXPECT_EQ(SetPath(TOKEN_ID_SET_DENY_CFG, "/testpath_002/non_persist_dir", DEC_MODE_RW, false, 0, USER_ID), -1);
    EXPECT_EQ(SetPath(TOKEN_ID_SET_DENY_CFG, "/testpath_002/non_persist_dir/file", DEC_MODE_RW, false, 0, USER_ID), 0);
    EXPECT_EQ(SetPath(TOKEN_ID_SET_DENY_CFG, "/testpath_002/dir", DEC_MODE_RW, false, 0, USER_ID), -1);
    EXPECT_EQ(SetPath(TOKEN_ID_SET_DENY_CFG, "/testpath_002/dir/file", DEC_MODE_RW, false, 0, USER_ID), -1);

    EXPECT_EQ(DelDenyPath(0, "/testpath_002/non_persist_dir"), 0);
    EXPECT_EQ(DelDenyPath(0, "/testpath_002/dir"), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID_SET_DENY_CFG, 0), 0);
}

/**
 * @tc.name: MacAdapterTestCase003
 * @tc.desc: Test SetDenyCfg rejects non-numeric set_policy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MacAdapterTestCase, MacAdapterTestCase003, TestSize.Level0)
{
    MacAdapter macAdapter;
    macAdapter.Init();

    std::string denyCfg = R"([
        {"path":"/testpath_003/non_persist_dir", "rename":0, "delete":0, "inherit":0, "set_policy":"test"}
    ])";
    EXPECT_EQ(macAdapter.SetDenyCfg(denyCfg), SANDBOX_MANAGER_DENY_ERR);
}

/**
 * @tc.name: MacAdapterTestCase004
 * @tc.desc: Test SetDenyCfg rejects non-numeric set_policy_all
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MacAdapterTestCase, MacAdapterTestCase004, TestSize.Level0)
{
    MacAdapter macAdapter;
    macAdapter.Init();

    std::string denyCfg = R"([
        {"path":"/testpath_004/dir", "rename":0, "delete":0, "inherit":0, "set_policy_all":"test"}
    ])";
    EXPECT_EQ(macAdapter.SetDenyCfg(denyCfg), SANDBOX_MANAGER_DENY_ERR);
}

/**
 * @tc.name: MacAdapterTestCase005
 * @tc.desc: Test deny_set and deny_set_all reject allow modes and their combinations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MacAdapterTestCase, MacAdapterTestCase005, TestSize.Level0)
{
    const std::string denySetPath = "/testpath_005/deny_set_path";
    const std::string denySetAllPath = "/testpath_005/deny_set_all_path";
    const std::string denySetAllChildPath = denySetAllPath + "/child";

    EXPECT_EQ(DestroyByTokenid(TOKEN_ID_ALLOW_MODE, 0), 0);
    EXPECT_EQ(DenyPath(0, denySetPath, DEC_DENY_SET, 0, USER_ID), 0);
    EXPECT_EQ(DenyPath(0, denySetAllPath, DEC_DENY_SET_ALL, 0, USER_ID), 0);

    for (uint32_t mode : ALLOW_MODES) {
        EXPECT_EQ(SetPath(TOKEN_ID_ALLOW_MODE, denySetPath, mode, false, 0, USER_ID), -1);
        EXPECT_EQ(SetPath(TOKEN_ID_ALLOW_MODE, denySetAllPath, mode, false, 0, USER_ID), -1);
        EXPECT_EQ(SetPath(TOKEN_ID_ALLOW_MODE, denySetAllChildPath, mode, false, 0, USER_ID), -1);
    }

    EXPECT_EQ(DelDenyPath(0, denySetPath), 0);
    EXPECT_EQ(DelDenyPath(0, denySetAllPath), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID_ALLOW_MODE, 0), 0);
}

/**
 * @tc.name: MacAdapterTestCase006
 * @tc.desc: Test deny_set and deny_set_all do not reject deny modes and their combinations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MacAdapterTestCase, MacAdapterTestCase006, TestSize.Level0)
{
    const std::string denySetPath = "/testpath_006/deny_set_path";
    const std::string denySetAllPath = "/testpath_006/deny_set_all_path";

    EXPECT_EQ(DestroyByTokenid(TOKEN_ID_DENY_MODE, 0), 0);
    EXPECT_EQ(DenyPath(0, denySetPath, DEC_DENY_SET, 0, USER_ID), 0);
    EXPECT_EQ(DenyPath(0, denySetAllPath, DEC_DENY_SET_ALL, 0, USER_ID), 0);

    for (size_t i = 0; i < DENY_MODES.size(); ++i) {
        const uint32_t mode = DENY_MODES[i];
        const uint64_t tokenId = TOKEN_ID_DENY_MODE + i;
        const std::string denySetAllChildPath = denySetAllPath + "/child_" + std::to_string(i);

        EXPECT_EQ(DestroyByTokenid(tokenId, 0), 0);
        EXPECT_EQ(SetPath(tokenId, denySetPath, mode, false, 0, USER_ID), 0);
        EXPECT_EQ(SetPath(tokenId, denySetAllPath, mode, false, 0, USER_ID), 0);
        EXPECT_EQ(SetPath(tokenId, denySetAllChildPath, mode, false, 0, USER_ID), 0);
        EXPECT_EQ(DestroyByTokenid(tokenId, 0), 0);
    }

    EXPECT_EQ(DelDenyPath(0, denySetPath), 0);
    EXPECT_EQ(DelDenyPath(0, denySetAllPath), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID_DENY_MODE, 0), 0);
}

/**
 * @tc.name: MacAdapterTestCase007
 * @tc.desc: Test rules set before deny_set and deny_set_all remain valid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MacAdapterTestCase, MacAdapterTestCase007, TestSize.Level0)
{
    const std::string denySetPath = "/testpath_007/existing_rule";
    const std::string denySetAllPath = "/testpath_007/existing_parent";
    const std::string denySetAllChildPath = denySetAllPath + "/child";

    EXPECT_EQ(DestroyByTokenid(TOKEN_ID_EXISTING_RULE, 0), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID_NEW_RULE, 0), 0);

    EXPECT_EQ(SetPath(TOKEN_ID_EXISTING_RULE, denySetPath, DEC_MODE_READ, false, 0, USER_ID), 0);
    EXPECT_EQ(SetPath(TOKEN_ID_EXISTING_RULE, denySetAllChildPath, DEC_MODE_WRITE, false, 0, USER_ID), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID_EXISTING_RULE, denySetPath, DEC_MODE_READ), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID_EXISTING_RULE, denySetAllChildPath, DEC_MODE_WRITE), 0);

    EXPECT_EQ(DenyPath(0, denySetPath, DEC_DENY_SET, 0, USER_ID), 0);
    EXPECT_EQ(DenyPath(0, denySetAllPath, DEC_DENY_SET_ALL, 0, USER_ID), 0);

    EXPECT_EQ(CheckPath(TOKEN_ID_EXISTING_RULE, denySetPath, DEC_MODE_READ), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID_EXISTING_RULE, denySetAllChildPath, DEC_MODE_WRITE), 0);
    EXPECT_EQ(SetPath(TOKEN_ID_NEW_RULE, denySetPath, DEC_MODE_READ, false, 0, USER_ID), -1);
    EXPECT_EQ(SetPath(TOKEN_ID_NEW_RULE, denySetAllChildPath, DEC_MODE_WRITE, false, 0, USER_ID), -1);

    EXPECT_EQ(DelDenyPath(0, denySetPath), 0);
    EXPECT_EQ(DelDenyPath(0, denySetAllPath), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID_EXISTING_RULE, 0), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID_NEW_RULE, 0), 0);
}
} // SandboxManager
} // AccessControl
} // OHOS
#endif
