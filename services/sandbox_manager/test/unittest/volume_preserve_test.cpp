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

#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>
#include <gtest/gtest.h>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "hap_token_info.h"
#include "generic_values.h"
#include "policy_field_const.h"
#include "policy_info.h"
#define private public
#include "policy_info_manager.h"
#include "volume_preserve_manager.h"
#undef private
#include "sandbox_manager_const.h"
#include "sandbox_manager_rdb.h"
#include "sandbox_manager_log.h"
#include "sandbox_manager_err_code.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
constexpr int64_t TEST_AGING_TTL_MS = 2000;
constexpr int64_t TEST_WAIT_EXPIRED_MS = 3000;
constexpr int64_t TEST_WAIT_WITHIN_TTL_MS = 1000;

Security::AccessToken::HapInfoParams g_testInfoParms = {
    .userID = 100,
    .bundleName = "volume_preserve_test",
    .instIndex = 0,
    .appIDDesc = "test"
};
Security::AccessToken::HapPolicyParams g_testPolicyPrams = {
    .apl = Security::AccessToken::APL_NORMAL,
    .domain = "test.domain",
    .permList = {},
    .permStateList = {}
};
uint32_t g_volTestToken = 0;
} // namespace

class VolumePreserveTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void VolumePreserveTest::SetUpTestCase(void)
{
    GenericValues conditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, conditions);
}

void VolumePreserveTest::TearDownTestCase(void)
{
    GenericValues conditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, conditions);
}

void VolumePreserveTest::SetUp(void)
{
    GenericValues conditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, conditions);
    PolicyInfoManager::GetInstance().Init();
    VolumePreserveManager::GetInstance().SetAgingTtlMs(TEST_AGING_TTL_MS);
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
    g_volTestToken = tokenIdEx.tokenIdExStruct.tokenID;
}

void VolumePreserveTest::TearDown(void)
{
    if (PolicyInfoManager::GetInstance().macAdapter_.fd_ > 0) {
        close(PolicyInfoManager::GetInstance().macAdapter_.fd_);
        PolicyInfoManager::GetInstance().macAdapter_.fd_ = -1;
        PolicyInfoManager::GetInstance().macAdapter_.isMacSupport_ = false;
    }
    if (g_volTestToken != 0) {
        Security::AccessToken::AccessTokenKit::DeleteToken(g_volTestToken);
        g_volTestToken = 0;
    }
    VolumePreserveManager::GetInstance().SetAgingTtlMs(VOLUME_POLICY_AGING_TTL_MS);
    GenericValues conditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, conditions);
}

static void InsertPersistedPolicy(uint32_t tokenId, const std::string &path, uint32_t mode)
{
    GenericValues policy;
    policy.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int32_t>(tokenId));
    policy.Put(PolicyFiledConst::FIELD_PATH, path);
    policy.Put(PolicyFiledConst::FIELD_MODE, static_cast<int32_t>(mode));
    policy.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int32_t>(0));
    policy.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int32_t>(0));
    policy.Put(PolicyFiledConst::FIELD_VOLUME_UNMOUNT_TS, static_cast<int64_t>(0));
    SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY, {policy});
}

static int64_t GetVolumeUnmountTs(uint32_t tokenId, const std::string &path)
{
    GenericValues conditions;
    GenericValues symbols;
    conditions.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int32_t>(tokenId));
    conditions.Put(PolicyFiledConst::FIELD_PATH, path);
    symbols.Put(PolicyFiledConst::FIELD_TOKENID, std::string("="));
    symbols.Put(PolicyFiledConst::FIELD_PATH, std::string("="));
    std::vector<GenericValues> results;
    int32_t ret = SandboxManagerRdb::GetInstance().Find(SANDBOX_MANAGER_PERSISTED_POLICY,
        conditions, symbols, results);
    if (ret != SandboxManagerRdb::SUCCESS || results.empty()) {
        return -1;
    }
    return results[0].GetInt64(PolicyFiledConst::FIELD_VOLUME_UNMOUNT_TS);
}

static int32_t GetRecordCount()
{
    GenericValues conditions;
    GenericValues symbols;
    std::vector<GenericValues> results;
    int32_t ret = SandboxManagerRdb::GetInstance().Find(SANDBOX_MANAGER_PERSISTED_POLICY,
        conditions, symbols, results);
    if (ret != SandboxManagerRdb::SUCCESS) {
        return -1;
    }
    return static_cast<int32_t>(results.size());
}

/**
 * @tc.name: VolumePreserveTest001
 * @tc.desc: Test DeactivePolicyByPath - records get timestamp, not deleted
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest001, TestSize.Level0)
{
    uint32_t tokenId = 100;
    InsertPersistedPolicy(tokenId, "/storage/External/uuid_001/dir1", 1);
    InsertPersistedPolicy(tokenId, "/storage/External/uuid_001/dir2", 1);
    InsertPersistedPolicy(200, "/data/app/internal", 1);

    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath("/storage/External/uuid_001");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    EXPECT_GT(GetVolumeUnmountTs(tokenId, "/storage/External/uuid_001/dir1"), 0);
    EXPECT_GT(GetVolumeUnmountTs(tokenId, "/storage/External/uuid_001/dir2"), 0);
    EXPECT_EQ(GetVolumeUnmountTs(200, "/data/app/internal"), 0);

    EXPECT_EQ(3, GetRecordCount());
}

/**
 * @tc.name: VolumePreserveTest002
 * @tc.desc: Test DeactivePolicyByPath - empty path returns INVALID_PARAMTER
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest002, TestSize.Level0)
{
    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath("");
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: VolumePreserveTest003
 * @tc.desc: Test DeactivePolicyByPath - no match returns OK
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest003, TestSize.Level0)
{
    InsertPersistedPolicy(100, "/data/app/internal", 1);

    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath("/storage/External/nonexistent");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    EXPECT_EQ(1, GetRecordCount());
}

/**
 * @tc.name: VolumePreserveTest004
 * @tc.desc: Test ActivePolicyByPath - restores within TTL
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest004, TestSize.Level0)
{
    uint32_t tokenId = 100;
    InsertPersistedPolicy(tokenId, "/storage/External/uuid_002/dir1", 1);

    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath("/storage/External/uuid_002");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    EXPECT_GT(GetVolumeUnmountTs(tokenId, "/storage/External/uuid_002/dir1"), 0);

    ret = VolumePreserveManager::GetInstance().ActivePolicyByPath("/storage/External/uuid_002");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    EXPECT_EQ(0, GetVolumeUnmountTs(tokenId, "/storage/External/uuid_002/dir1"));
    EXPECT_EQ(1, GetRecordCount());
}

/**
 * @tc.name: VolumePreserveTest005
 * @tc.desc: Test ActivePolicyByPath - empty path returns INVALID_PARAMTER
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest005, TestSize.Level0)
{
    int32_t ret = VolumePreserveManager::GetInstance().ActivePolicyByPath("");
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: VolumePreserveTest006
 * @tc.desc: Test ActivePolicyByPath - different volume no restore
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest006, TestSize.Level0)
{
    uint32_t tokenId = 100;
    InsertPersistedPolicy(tokenId, "/storage/External/uuid_003/dir1", 1);

    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath("/storage/External/uuid_003");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    ret = VolumePreserveManager::GetInstance().ActivePolicyByPath("/storage/External/uuid_999");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    EXPECT_GT(GetVolumeUnmountTs(tokenId, "/storage/External/uuid_003/dir1"), 0);
    EXPECT_EQ(1, GetRecordCount());
}

/**
 * @tc.name: VolumePreserveTest007
 * @tc.desc: Test ActivePolicyByPath - already cleaned no restore
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest007, TestSize.Level0)
{
    uint32_t tokenId = 100;
    InsertPersistedPolicy(tokenId, "/storage/External/uuid_004/dir1", 1);

    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath("/storage/External/uuid_004");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    std::vector<std::string> paths = {"/storage/External/uuid_004"};
    ret = PolicyInfoManager::GetInstance().CleanPolicyByUserId(100, paths);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    ret = VolumePreserveManager::GetInstance().ActivePolicyByPath("/storage/External/uuid_004");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    EXPECT_EQ(0, GetRecordCount());
}

/**
 * @tc.name: VolumePreserveTest008
 * @tc.desc: Test full cycle - preserve then restore
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest008, TestSize.Level0)
{
    uint32_t tokenId = 100;
    InsertPersistedPolicy(tokenId, "/storage/External/uuid_005/dir1", 1);
    InsertPersistedPolicy(tokenId, "/storage/External/uuid_005/dir2", 1);

    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath("/storage/External/uuid_005");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    EXPECT_EQ(2, GetRecordCount());
    EXPECT_GT(GetVolumeUnmountTs(tokenId, "/storage/External/uuid_005/dir1"), 0);
    EXPECT_GT(GetVolumeUnmountTs(tokenId, "/storage/External/uuid_005/dir2"), 0);

    ret = VolumePreserveManager::GetInstance().ActivePolicyByPath("/storage/External/uuid_005");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    EXPECT_EQ(2, GetRecordCount());
    EXPECT_EQ(0, GetVolumeUnmountTs(tokenId, "/storage/External/uuid_005/dir1"));
    EXPECT_EQ(0, GetVolumeUnmountTs(tokenId, "/storage/External/uuid_005/dir2"));
}

/**
 * @tc.name: VolumePreserveTest009
 * @tc.desc: Test aging - deactive then wait TTL expiry then active, record deleted
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest009, TestSize.Level0)
{
    uint32_t tokenId = 100;
    InsertPersistedPolicy(tokenId, "/storage/External/uuid_006/dir1", 1);

    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath("/storage/External/uuid_006");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    EXPECT_EQ(1, GetRecordCount());
    EXPECT_GT(GetVolumeUnmountTs(tokenId, "/storage/External/uuid_006/dir1"), 0);

    // Wait for TTL to expire
    std::this_thread::sleep_for(std::chrono::milliseconds(TEST_WAIT_EXPIRED_MS));

    ret = VolumePreserveManager::GetInstance().ActivePolicyByPath("/storage/External/uuid_006");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    // Record should be deleted by aging scan
    EXPECT_EQ(0, GetRecordCount());
}

/**
 * @tc.name: VolumePreserveTest010
 * @tc.desc: Test aging - expired records from OTHER volumes also deleted on insert
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest010, TestSize.Level0)
{
    // Insert and deactive volume A
    uint32_t tokenIdA = 100;
    InsertPersistedPolicy(tokenIdA, "/storage/External/uuid_A/dir1", 1);
    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath("/storage/External/uuid_A");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    // Insert and deactive volume B
    uint32_t tokenIdB = 200;
    InsertPersistedPolicy(tokenIdB, "/storage/External/uuid_B/dir2", 1);
    ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath("/storage/External/uuid_B");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    EXPECT_EQ(2, GetRecordCount());

    // Wait for TTL to expire
    std::this_thread::sleep_for(std::chrono::milliseconds(TEST_WAIT_EXPIRED_MS));

    // Insert volume C — aging scan should delete expired records from A and B
    InsertPersistedPolicy(300, "/storage/External/uuid_C/dir3", 1);
    ret = VolumePreserveManager::GetInstance().ActivePolicyByPath("/storage/External/uuid_C");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    // A and B expired records deleted; C record has volumeUnmountTs=0 (never deactivated), not affected
    EXPECT_EQ(1, GetRecordCount());
}

/**
 * @tc.name: VolumePreserveTest012
 * @tc.desc: Test aging - within TTL, record restored not deleted
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest012, TestSize.Level0)
{
    uint32_t tokenId = 100;
    InsertPersistedPolicy(tokenId, "/storage/External/uuid_008/dir1", 1);

    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath("/storage/External/uuid_008");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    EXPECT_GT(GetVolumeUnmountTs(tokenId, "/storage/External/uuid_008/dir1"), 0);

    // Active immediately (within TTL)
    ret = VolumePreserveManager::GetInstance().ActivePolicyByPath("/storage/External/uuid_008");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    // Record should be restored, not deleted
    EXPECT_EQ(1, GetRecordCount());
    EXPECT_EQ(0, GetVolumeUnmountTs(tokenId, "/storage/External/uuid_008/dir1"));
}

/**
 * @tc.name: VolumePreserveTest013
 * @tc.desc: Test aging - border case: active right before TTL expires
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest013, TestSize.Level0)
{
    uint32_t tokenId = 100;
    InsertPersistedPolicy(tokenId, "/storage/External/uuid_009/dir1", 1);

    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath("/storage/External/uuid_009");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    // Wait less than TTL
    std::this_thread::sleep_for(std::chrono::milliseconds(TEST_WAIT_WITHIN_TTL_MS));

    ret = VolumePreserveManager::GetInstance().ActivePolicyByPath("/storage/External/uuid_009");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    // Still within TTL, record should be restored
    EXPECT_EQ(1, GetRecordCount());
    EXPECT_EQ(0, GetVolumeUnmountTs(tokenId, "/storage/External/uuid_009/dir1"));
}

/**
 * @tc.name: VolumePreserveTest011
 * @tc.desc: Test DeactivePolicyByPath - path with trailing slash
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest011, TestSize.Level0)
{
    uint32_t tokenId = 100;
    InsertPersistedPolicy(tokenId, "/storage/External/uuid_007/dir1", 1);

    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath("/storage/External/uuid_007/");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    EXPECT_GT(GetVolumeUnmountTs(tokenId, "/storage/External/uuid_007/dir1"), 0);
}

/**
 * @tc.name: VolumePreserveTest014
 * @tc.desc: Test path traversal rejected
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest014, TestSize.Level0)
{
    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath(
        "/storage/External/uuid_A/../uuid_B/dir1");
    EXPECT_EQ(INVALID_PARAMTER, ret);

    ret = VolumePreserveManager::GetInstance().ActivePolicyByPath(
        "/storage/External/uuid_A/../uuid_B/dir1");
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: VolumePreserveTest015
 * @tc.desc: Test embedded null byte rejected
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest015, TestSize.Level0)
{
    std::string path = "/storage/External/uuid_008/dir1";
    path.push_back('\0');
    path.append("/evil");

    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath(path);
    EXPECT_EQ(INVALID_PARAMTER, ret);

    ret = VolumePreserveManager::GetInstance().ActivePolicyByPath(path);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: VolumePreserveTest016
 * @tc.desc: Test non /storage/ prefix rejected
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest016, TestSize.Level0)
{
    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath("/mnt/usb-uuid/dir1");
    EXPECT_EQ(INVALID_PARAMTER, ret);

    ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath("/data/app/internal");
    EXPECT_EQ(INVALID_PARAMTER, ret);

    ret = VolumePreserveManager::GetInstance().ActivePolicyByPath("/mnt/usb-uuid/dir1");
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: VolumePreserveTest017
 * @tc.desc: Test /storage/ with less than 3 layers rejected
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest017, TestSize.Level0)
{
    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath("/storage");
    EXPECT_EQ(INVALID_PARAMTER, ret);

    ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath("/storage/External");
    EXPECT_EQ(INVALID_PARAMTER, ret);

    ret = VolumePreserveManager::GetInstance().ActivePolicyByPath("/storage");
    EXPECT_EQ(INVALID_PARAMTER, ret);

    ret = VolumePreserveManager::GetInstance().ActivePolicyByPath("/storage/External");
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: VolumePreserveTest018
 * @tc.desc: Test double slash rejected
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest018, TestSize.Level0)
{
    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath(
        "/storage//External/uuid_001/dir1");
    EXPECT_EQ(INVALID_PARAMTER, ret);

    ret = VolumePreserveManager::GetInstance().ActivePolicyByPath(
        "/storage//External/uuid_001/dir1");
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: VolumePreserveTest022
 * @tc.desc: Test /storage/voldata/ prefix accepted
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest022, TestSize.Level0)
{
    uint32_t tokenId = 100;
    InsertPersistedPolicy(tokenId, "/storage/voldata/uuid_022/dir1", 1);

    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath(
        "/storage/voldata/uuid_022");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    EXPECT_GT(GetVolumeUnmountTs(tokenId, "/storage/voldata/uuid_022/dir1"), 0);

    ret = VolumePreserveManager::GetInstance().ActivePolicyByPath(
        "/storage/voldata/uuid_022");
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    EXPECT_EQ(0, GetVolumeUnmountTs(tokenId, "/storage/voldata/uuid_022/dir1"));
}

/**
 * @tc.name: VolumePreserveTest023
 * @tc.desc: Test /storage/voldata/ with less than 3 layers rejected
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest023, TestSize.Level0)
{
    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath(
        "/storage/voldata");
    EXPECT_EQ(INVALID_PARAMTER, ret);

    ret = VolumePreserveManager::GetInstance().ActivePolicyByPath(
        "/storage/voldata");
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: VolumePreserveTest024
 * @tc.desc: Test /storage/unsupported/ prefix rejected
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest024, TestSize.Level0)
{
    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath(
        "/storage/unsupported/uuid_024");
    EXPECT_EQ(INVALID_PARAMTER, ret);

    ret = VolumePreserveManager::GetInstance().ActivePolicyByPath(
        "/storage/unsupported/uuid_024");
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: VolumePreserveTest019
 * @tc.desc: Test temp policy cleaned on deactive, not restored on active
 * @tc.type: FUNC
 */
HWTEST_F(VolumePreserveTest, VolumePreserveTest019, TestSize.Level0)
{
    uint32_t tokenId = g_volTestToken;
    std::string volPath = "/storage/External/uuid_019";
    std::string dirPath = volPath + "/dir1";
    PolicyInfo info;
    info.path = dirPath;
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    std::vector<PolicyInfo> policy = {info};

    std::vector<uint32_t> setResult;
    SetInfo setInfo;
    setInfo.userId = 100;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(tokenId, policy, 1, setResult, setInfo));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);

    std::vector<uint32_t> persistResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(tokenId, policy, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<bool> checkResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().CheckPolicy(tokenId, policy, checkResult));
    ASSERT_EQ(1, checkResult.size());
    EXPECT_EQ(true, checkResult[0]);

    int32_t ret = VolumePreserveManager::GetInstance().DeactivePolicyByPath(volPath);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    checkResult.clear();
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().CheckPolicy(tokenId, policy, checkResult));
    ASSERT_EQ(1, checkResult.size());
    EXPECT_EQ(false, checkResult[0]);

    EXPECT_GT(GetVolumeUnmountTs(tokenId, dirPath), 0);
    EXPECT_EQ(1, GetRecordCount());

    ret = VolumePreserveManager::GetInstance().ActivePolicyByPath(volPath);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    checkResult.clear();
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().CheckPolicy(tokenId, policy, checkResult));
    ASSERT_EQ(1, checkResult.size());
    EXPECT_EQ(true, checkResult[0]);

    EXPECT_EQ(0, GetVolumeUnmountTs(tokenId, dirPath));
}
} // SandboxManager
} // AccessControl
} // OHOS
