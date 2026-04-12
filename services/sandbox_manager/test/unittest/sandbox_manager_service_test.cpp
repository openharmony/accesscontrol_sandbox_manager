/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <gtest/gtest.h>
#include <sstream>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#define private public
#include "event_handler.h"
#undef private
#include "hap_token_info.h"
#include "nativetoken_kit.h"
#include "policy_info.h"
#include "policy_info_parcel.h"
#include "policy_info_vector_parcel.h"
#include "sandbox_manager_const.h"
#include "sandbox_manager_rdb.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_event_subscriber.h"
#define private public
#include "sandbox_manager_event_subscriber.h"
#include "policy_info_manager.h"
#include "sandbox_manager_service.h"
#ifdef MEMORY_MANAGER_ENABLE
#include "sandbox_memory_manager.h"
#endif // MEMORY_MANAGER_ENABLE
#undef private
#include "sandbox_manager_dfx_helper.h"
#include "system_ability_definition.h"
#include "sandbox_test_common.h"
#include "token_setproc.h"
#include "os_account_manager.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
const std::string SET_POLICY_PERMISSION = "ohos.permission.SET_SANDBOX_POLICY";
const std::string CHECK_POLICY_PERMISSION = "ohos.permission.CHECK_SANDBOX_POLICY";
const std::string ACCESS_PERSIST_PERMISSION = "ohos.permission.FILE_ACCESS_PERSIST";
const std::string FILE_ACCESS_PERMISSION_NAME = "ohos.permission.FILE_ACCESS_MANAGER";
const std::string KILL_APP_PROCESS_PERMISSION_NAME = "ohos.permission.KILL_APP_PROCESSES";
const uint64_t POLICY_VECTOR_SIZE = 5000;
const uint64_t POLICY_VECTOR_LARGE_SIZE = 400000;
#ifdef MEMORY_MANAGER_ENABLE
constexpr int32_t MAX_RUNNING_NUM = 256;
constexpr int64_t EXTRA_PARAM = 3;
constexpr int32_t SA_READY_TO_UNLOAD = 0;
constexpr int32_t SA_REFUSE_TO_UNLOAD = -1;
#endif
Security::AccessToken::PermissionStateFull g_testState1 = {
    .permissionName = SET_POLICY_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_testState2 = {
    .permissionName = ACCESS_PERSIST_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_testState3 = {
    .permissionName = CHECK_POLICY_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_testState4 = {
    .permissionName = FILE_ACCESS_PERMISSION_NAME,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_testState5 = {
    .permissionName = KILL_APP_PROCESS_PERMISSION_NAME,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::HapInfoParams g_testInfoParms = {
    .userID = 1,
    .bundleName = "sandbox_manager_test",
    .instIndex = 0,
    .appIDDesc = "test"
};

Security::AccessToken::HapPolicyParams g_testPolicyPrams = {
    .apl = Security::AccessToken::APL_NORMAL,
    .domain = "test.domain",
    .permList = {},
    .permStateList = {g_testState1, g_testState2, g_testState3, g_testState4, g_testState5}
};

void AppendRawUint32(std::stringstream &ss, uint32_t value)
{
    ss.write(reinterpret_cast<const char *>(&value), sizeof(value));
}

void AppendRawUint64(std::stringstream &ss, uint64_t value)
{
    ss.write(reinterpret_cast<const char *>(&value), sizeof(value));
}

void AppendRawPolicy(std::stringstream &ss, const PolicyInfo &policy)
{
    uint32_t pathLen = static_cast<uint32_t>(policy.path.length());
    AppendRawUint32(ss, pathLen);
    ss.write(policy.path.c_str(), pathLen);
    AppendRawUint64(ss, policy.mode);
    ss.write(reinterpret_cast<const char *>(&policy.type), sizeof(policy.type));
}

PolicyVecRawData BuildRawDataFromStream(const std::stringstream &ss)
{
    PolicyVecRawData rawData;
    rawData.serializedData = ss.str();
    rawData.data = reinterpret_cast<const void *>(rawData.serializedData.data());
    rawData.size = static_cast<uint32_t>(rawData.serializedData.size());
    return rawData;
}

PolicyVecRawData BuildRawDataWithCount(uint32_t policyNum)
{
    std::stringstream ss;
    AppendRawUint32(ss, policyNum);
    return BuildRawDataFromStream(ss);
}

PolicyVecRawData BuildRawDataFromPolicies(const std::vector<PolicyInfo> &policies)
{
    PolicyVecRawData rawData;
    rawData.Marshalling(policies);
    return rawData;
}
};

class SandboxManagerServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void GetTokenid();
    std::shared_ptr<SandboxManagerService> sandboxManagerService_;
    uint64_t selfTokenId_ = 1; // test token
    uint64_t sysGrantToken_;
};

void SandboxManagerServiceTest::SetUpTestCase(void)
{
    if (PolicyInfoManager::GetInstance().macAdapter_.fd_ > 0) {
        close(PolicyInfoManager::GetInstance().macAdapter_.fd_);
        PolicyInfoManager::GetInstance().macAdapter_.fd_ = -1;
        PolicyInfoManager::GetInstance().macAdapter_.isMacSupport_ = false;
    }
    PolicyInfoManager::GetInstance().macAdapter_.Init();
}

void SandboxManagerServiceTest::TearDownTestCase(void)
{}

void SandboxManagerServiceTest::SetUp(void)
{
    int mockRet = MockTokenId("foundation");
    EXPECT_NE(0, mockRet);
    sandboxManagerService_ = DelayedSingleton<SandboxManagerService>::GetInstance();
    ASSERT_NE(nullptr, sandboxManagerService_);

    selfTokenId_ = GetSelfTokenID();
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
    ASSERT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    sysGrantToken_ = tokenIdEx.tokenIdExStruct.tokenID;
}

void SandboxManagerServiceTest::TearDown(void)
{
    sandboxManagerService_ = nullptr;
    Security::AccessToken::AccessTokenKit::DeleteToken(sysGrantToken_);
}

/**
 * @tc.name: SandboxManagerServiceTest001
 * @tc.desc: Test PersistPolicy - invalid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policy);
    Uint32VecRawData resultRawData;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->PersistPolicy(policyRawData, resultRawData));
    uint64_t sizeLimit = 0;

    policy.resize(POLICY_VECTOR_SIZE + 1);
    PolicyVecRawData policyRawData1;
    policyRawData1.Marshalling(policy);
    std::vector<uint32_t> result1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->PersistPolicy(policyRawData1, resultRawData));
    sizeLimit = POLICY_VECTOR_SIZE + 1;
    resultRawData.Unmarshalling(result1);
    EXPECT_EQ(sizeLimit, result1.size());
}

/**
 * @tc.name: SandboxManagerServiceTest002
 * @tc.desc: Test SetPolicy - invalid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest002, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policy);
    Uint32VecRawData resultRawData;
    uint64_t policyFlag = 0;
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->SetPolicy(selfTokenId_, policyRawData, policyFlag, resultRawData));
    uint64_t sizeLimit = 0;

    policy.resize(POLICY_VECTOR_SIZE + 1);
    PolicyVecRawData policyRawData1;
    policyRawData1.Marshalling(policy);
    std::vector<uint32_t> result1;
    Uint32VecRawData resultRawData1;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->SetPolicy(selfTokenId_, policyRawData1, policyFlag, resultRawData1));
    resultRawData1.Unmarshalling(result1);
    sizeLimit = POLICY_VECTOR_SIZE + 1;
    EXPECT_EQ(sizeLimit, result1.size());

    policy.resize(1);
    PolicyVecRawData policyRawData2;
    policyRawData2.Marshalling(policy);
    Uint32VecRawData resultRawData2;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->SetPolicy(selfTokenId_, policyRawData2, policyFlag, resultRawData2));
    policyFlag = 1;
    Uint32VecRawData resultRawData3;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->SetPolicy(selfTokenId_, policyRawData2, policyFlag, resultRawData3));
    Uint32VecRawData resultRawData4;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->SetPolicy(0, policyRawData2, policyFlag, resultRawData4));
}

/**
 * @tc.name: SandboxManagerServiceTest003
 * @tc.desc: Test StartAccessingPolicy - invalid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest003, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policy);
    Uint32VecRawData resultRawData;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->StartAccessingPolicy(policyRawData, resultRawData));
    uint64_t sizeLimit = 0;

    policy.resize(POLICY_VECTOR_SIZE + 1);
    PolicyVecRawData policyRawData1;
    policyRawData1.Marshalling(policy);
    std::vector<uint32_t> result1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->StartAccessingPolicy(policyRawData1, resultRawData));
    resultRawData.Unmarshalling(result1);
    sizeLimit = POLICY_VECTOR_SIZE + 1;
    EXPECT_EQ(sizeLimit, result1.size());
}


/**
 * @tc.name: SandboxManagerServiceTest004
 * @tc.desc: Test StopAccessingPolicy - invalid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest004, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policy);
    Uint32VecRawData resultRawData;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->StopAccessingPolicy(policyRawData, resultRawData));
    uint64_t sizeLimit = 0;

    policy.resize(POLICY_VECTOR_SIZE + 1);
    PolicyVecRawData policyRawData1;
    policyRawData1.Marshalling(policy);
    std::vector<uint32_t> result1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->StopAccessingPolicy(policyRawData1, resultRawData));
    resultRawData.Unmarshalling(result1);
    sizeLimit = POLICY_VECTOR_SIZE + 1;
    EXPECT_EQ(sizeLimit, result1.size());
}

/**
 * @tc.name: SandboxManagerServiceTest005
 * @tc.desc: Test CheckPersistPolicy - invalid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest005, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policy);
    BoolVecRawData resultRawData;
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->CheckPersistPolicy(selfTokenId_, policyRawData, resultRawData));
    uint64_t sizeLimit = 0;

    policy.resize(POLICY_VECTOR_SIZE + 1);
    PolicyVecRawData policyRawData1;
    policyRawData1.Marshalling(policy);
    std::vector<bool> result1;
    BoolVecRawData resultRawData1;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->CheckPersistPolicy(selfTokenId_, policyRawData1, resultRawData1));
    resultRawData1.Unmarshalling(result1);
    sizeLimit = POLICY_VECTOR_SIZE + 1;
    EXPECT_EQ(sizeLimit, result1.size());
}

/**
 * @tc.name: SandboxManagerServiceTest006
 * @tc.desc: Test UnPersistPolicy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest006, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policy);
    Uint32VecRawData resultRawData;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->UnPersistPolicy(policyRawData, resultRawData));
    uint64_t sizeLimit = 0;

    policy.resize(POLICY_VECTOR_SIZE + 1);
    PolicyVecRawData policyRawData1;
    policyRawData1.Marshalling(policy);
    std::vector<uint32_t> result1;
    Uint32VecRawData resultRawData1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->UnPersistPolicy(policyRawData1, resultRawData1));
    resultRawData1.Unmarshalling(result1);
    sizeLimit = POLICY_VECTOR_SIZE + 1;
    EXPECT_EQ(sizeLimit, result1.size());
}

/**
 * @tc.name: SandboxManagerServiceTest007
 * @tc.desc: Test PersistPolicy UnPersistPolicy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest007, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    policy.resize(1);
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policy);
    Uint32VecRawData resultRawData;
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->PersistPolicy(policyRawData, resultRawData));
    Uint32VecRawData resultRawData1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->UnPersistPolicy(policyRawData, resultRawData1));
}

/**
 * @tc.name: SandboxManagerServiceTest008
 * @tc.desc: Test PersistPolicyByTokenId UnPersistPolicyByTokenId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest008, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
    std::vector<PolicyInfo> policy;
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policy);
    Uint32VecRawData resultRawData;
    uint64_t tokenId = 0;
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->PersistPolicyByTokenId(tokenId, policyRawData, resultRawData));

    setuid(uid);
    Security::AccessToken::AccessTokenID tokenID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->UnPersistPolicyByTokenId(tokenId, policyRawData, resultRawData));
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
    setuid(FOUNDATION_UID);
    tokenId = 1;
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->PersistPolicyByTokenId(tokenId, policyRawData, resultRawData));
    setuid(uid);
    tokenID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->UnPersistPolicyByTokenId(tokenId, policyRawData, resultRawData));
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
    setuid(FOUNDATION_UID);
    policy.resize(POLICY_VECTOR_SIZE + 1);
    PolicyVecRawData policyRawData1;
    policyRawData1.Marshalling(policy);
    Uint32VecRawData resultRawData1;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->PersistPolicyByTokenId(tokenId, policyRawData1, resultRawData1));
    setuid(uid);
    tokenID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    Uint32VecRawData resultRawData2;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->UnPersistPolicyByTokenId(tokenId, policyRawData1, resultRawData2));
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
    setuid(FOUNDATION_UID);
    tokenId = 0;
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->PersistPolicyByTokenId(tokenId, policyRawData1, resultRawData));
    setuid(uid);
    tokenID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->UnPersistPolicyByTokenId(tokenId, policyRawData1, resultRawData));
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
    setuid(FOUNDATION_UID);
    policy.resize(1);
    PolicyVecRawData policyRawData2;
    policyRawData2.Marshalling(policy);
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->PersistPolicyByTokenId(tokenId, policyRawData2, resultRawData));
    setuid(uid);
    tokenID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->UnPersistPolicyByTokenId(tokenId, policyRawData2, resultRawData));
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
    setuid(FOUNDATION_UID);
    tokenId = 1;
    Uint32VecRawData resultRawData3;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->PersistPolicyByTokenId(tokenId, policyRawData2, resultRawData3));
    setuid(uid);
    tokenID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    Uint32VecRawData resultRawData4;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->UnPersistPolicyByTokenId(tokenId, policyRawData2, resultRawData4));
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: SandboxManagerServiceTest009
 * @tc.desc: Test StartAccessingPolicy StopAccessingPolicy CheckPersistPolicy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest009, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    policy.resize(1);
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policy);
    Uint32VecRawData resultRawData;
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->StartAccessingPolicy(policyRawData, resultRawData));
    Uint32VecRawData resultRawData1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->StopAccessingPolicy(policyRawData, resultRawData1));

    BoolVecRawData resultRawData2;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->CheckPersistPolicy(selfTokenId_, policyRawData, resultRawData2));
}

/**
 * @tc.name: SandboxManagerServiceTest010
 * @tc.desc: Test StartByEventAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest010, TestSize.Level0)
{
    ASSERT_TRUE(sandboxManagerService_->Initialize());
    sandboxManagerService_->OnAddSystemAbility(COMMON_EVENT_SERVICE_ID, "test");
    sandboxManagerService_->OnAddSystemAbility(0, "test");
    SystemAbilityOnDemandReason startReason;
    startReason.SetName("test");
    EXPECT_TRUE(sandboxManagerService_->StartByEventAction(startReason));
    startReason.SetName(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    std::map<std::string, std::string> want = {{"testKey", "testVal"}}; // test input
    OnDemandReasonExtraData extraData1(0, "test", want);
    startReason.SetExtraData(extraData1);
    // accessTokenId not found
    EXPECT_FALSE(sandboxManagerService_->StartByEventAction(startReason));
    // accessTokenId is empty
    want = {{"accessTokenId", ""}};
    OnDemandReasonExtraData extraData2(0, "test", want);
    startReason.SetExtraData(extraData2);
    EXPECT_FALSE(sandboxManagerService_->StartByEventAction(startReason));
    // accessTokenId all text
    want = {{"accessTokenId", "test"}}; // this is a test input
    OnDemandReasonExtraData extraData3(0, "test", want);
    startReason.SetExtraData(extraData3);
    EXPECT_FALSE(sandboxManagerService_->StartByEventAction(startReason));
    // accessTokenId first char is digit
    want = {{"accessTokenId", "0test"}}; // this is a test input
    OnDemandReasonExtraData extraData4(0, "test", want);
    startReason.SetExtraData(extraData4);
    EXPECT_FALSE(sandboxManagerService_->StartByEventAction(startReason));
    // accessTokenId is 0
    want = {{"accessTokenId", "0"}};
    OnDemandReasonExtraData extraData5(0, "test", want);
    startReason.SetExtraData(extraData5);
    EXPECT_FALSE(sandboxManagerService_->StartByEventAction(startReason));
    // normal call
    want = {{"accessTokenId", "1"}};
    OnDemandReasonExtraData extraData6(0, "test", want);
    startReason.SetExtraData(extraData6);
    EXPECT_TRUE(sandboxManagerService_->StartByEventAction(startReason));

    startReason.SetName(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_FULLY_REMOVED);
    EXPECT_TRUE(sandboxManagerService_->StartByEventAction(startReason));
}

/**
 * @tc.name: SandboxManagerServiceTest011
 * @tc.desc: Test StartAccessingByTokenId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest011, TestSize.Level0)
{
    uint32_t selfUid = getuid();
    EXPECT_EQ(PERMISSION_DENIED, sandboxManagerService_->StartAccessingByTokenId(0, 1));
    setuid(FOUNDATION_UID);
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->StartAccessingByTokenId(0, 1));
    setuid(selfUid);
}

/**
 * @tc.name: SandboxManagerServiceTest011A
 * @tc.desc: Test StartAccessingByTokenId success path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest011A, TestSize.Level0)
{
    uint32_t selfUid = getuid();
    setuid(FOUNDATION_UID);
    int result = sandboxManagerService_->StartAccessingByTokenId(selfTokenId_, 1);
    bool pass = (result == SANDBOX_MANAGER_OK || result == SANDBOX_MANAGER_DB_RETURN_EMPTY);
    EXPECT_TRUE(pass);
    setuid(selfUid);
}

/**
 * @tc.name: SandboxManagerServiceTest012
 * @tc.desc: Test StartAccessingByTokenId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest012, TestSize.Level0)
{
    SetSelfTokenID(sysGrantToken_);
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->UnSetAllPolicyByToken(0, 1));
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->UnSetAllPolicyByToken(selfTokenId_, 1));
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: SandboxManagerServiceTest013
 * @tc.desc: Test UnSetPolicy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest013, TestSize.Level0)
{
    SetSelfTokenID(sysGrantToken_);
    PolicyInfo policy {
        .mode = OperateMode::READ_MODE,
        .path = "/test",
    };
    PolicyInfoParcel policyInfoParcel;
    policyInfoParcel.policyInfo = policy;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->UnSetPolicy(0, policyInfoParcel));
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->UnSetPolicy(selfTokenId_, policyInfoParcel));
    PolicyInfo policy1 {
        .mode = OperateMode::READ_MODE,
        .path = "",
    };
    policyInfoParcel.policyInfo = policy1;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->UnSetPolicy(selfTokenId_, policyInfoParcel));
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: SandboxManagerServiceTest014
 * @tc.desc: Test COMMON_EVENT_PACKAGE_CHANGED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest014, TestSize.Level0)
{
    ASSERT_TRUE(sandboxManagerService_->Initialize());
    sandboxManagerService_->OnAddSystemAbility(COMMON_EVENT_SERVICE_ID, "test");
    sandboxManagerService_->OnAddSystemAbility(0, "test");
    SystemAbilityOnDemandReason startReason;
    startReason.SetName(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    std::map<std::string, std::string> want = {{"test", ""}};
    OnDemandReasonExtraData extraData1(0, "test", want);
    startReason.SetExtraData(extraData1);
    EXPECT_FALSE(sandboxManagerService_->StartByEventAction(startReason));

    want = {{"bundleName", ""}};
    OnDemandReasonExtraData extraData2(0, "test", want);
    startReason.SetExtraData(extraData2);
    EXPECT_FALSE(sandboxManagerService_->StartByEventAction(startReason));

    want = {{"userId", "test"}};
    OnDemandReasonExtraData extraData3(0, "test", want);
    startReason.SetExtraData(extraData3);
    EXPECT_FALSE(sandboxManagerService_->StartByEventAction(startReason));

    want = {{"userId", "0"}};
    OnDemandReasonExtraData extraData4(0, "test", want);
    startReason.SetExtraData(extraData4);
    EXPECT_FALSE(sandboxManagerService_->StartByEventAction(startReason));
}

/**
 * @tc.name: SandboxManagerServiceBundleNameTest001
 * @tc.desc: Test SetPolicy - with input BundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceBundleNameTest001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    policy.resize(POLICY_VECTOR_SIZE + 1);
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policy);
    Uint32VecRawData resultRawData;
    uint64_t policyFlag = 0;
    uint64_t sizeLimit = POLICY_VECTOR_SIZE + 1;

    SetInfo setInfo = SetInfo();
    SetInfoParcel setInfoParcel;
    setInfoParcel.setInfo = setInfo;
    std::vector<uint32_t> result;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->SetPolicy(selfTokenId_, policyRawData, policyFlag, resultRawData, setInfoParcel));
    resultRawData.Unmarshalling(result);
    EXPECT_EQ(sizeLimit, result.size());
}

/**
 * @tc.name: SandboxManagerStub001
 * @tc.desc: Test CleanPersistPolicyByPath
 * @tc.type: FUNC
 * @tc.require:
 */
 HWTEST_F(SandboxManagerServiceTest, SandboxManagerStub001, TestSize.Level0)
{
    std::vector<std::string> paths = {};
    uint32_t fileManagerToken = Security::AccessToken::AccessTokenKit::GetNativeTokenId("file_manager_service");
    EXPECT_EQ(PERMISSION_DENIED, sandboxManagerService_->CleanPersistPolicyByPath(paths));
    SetSelfTokenID(fileManagerToken);
    // string vector size error
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->CleanPersistPolicyByPath(paths));
    // success
    std::vector<std::string> paths1 = {"/A/B" };
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->CleanPersistPolicyByPath(paths1));
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: SandboxManagerStub002
 * @tc.desc: Test CleanPolicyByUserId
 * @tc.type: FUNC
 * @tc.require:
 */
 HWTEST_F(SandboxManagerServiceTest, SandboxManagerStub002, TestSize.Level0)
{
    std::vector<std::string> paths = {};
    int32_t userId = 0;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        userId = 0; // set default userId
    }
    uint32_t fileManagerToken = Security::AccessToken::AccessTokenKit::GetNativeTokenId("file_manager_service");
    EXPECT_EQ(PERMISSION_DENIED, sandboxManagerService_->CleanPolicyByUserId(userId, paths));
    SetSelfTokenID(fileManagerToken);

    int32_t otherUserId = userId++;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->CleanPolicyByUserId(otherUserId, paths));
    // success
    std::vector<std::string> paths1 = {"/A/B" };
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->CleanPolicyByUserId(userId, paths1));
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: SandboxManagerSubscriberTest001
 * @tc.desc: Test SandboxManagerCommonEventSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerSubscriberTest001, TestSize.Level0)
{
    ASSERT_EQ(true, SandboxManagerCommonEventSubscriber::RegisterEvent());
    ASSERT_EQ(true, SandboxManagerCommonEventSubscriber::RegisterEvent());
    ASSERT_EQ(true, SandboxManagerCommonEventSubscriber::UnRegisterEvent());
    ASSERT_EQ(false, SandboxManagerCommonEventSubscriber::UnRegisterEvent());
}

#ifdef MEMORY_MANAGER_ENABLE
/**
 * @tc.name: MemoryManagerTest001
 * @tc.desc: test AddFunctionRuningNum and DecreaseFunctionRuningNum.
 * @tc.type: FUNC
 * @tc.require: issueICIZZE
 */
HWTEST_F(SandboxManagerServiceTest, MemoryManagerTest001, TestSize.Level1)
{
    SandboxMemoryManager::GetInstance().SetIsDelayedToUnload(false);
    SystemAbilityOnDemandReason reason(OnDemandReasonId::PARAM, "test", "true", EXTRA_PARAM);
    for (int32_t i = 0; i <= MAX_RUNNING_NUM + 1; i++) {
        SandboxMemoryManager::GetInstance().AddFunctionRuningNum();
    }
    EXPECT_EQ(SA_REFUSE_TO_UNLOAD, sandboxManagerService_->OnIdle(reason));
    for (int32_t i = 0; i <= MAX_RUNNING_NUM + 1; i++) {
        SandboxMemoryManager::GetInstance().DecreaseFunctionRuningNum();
    }
    EXPECT_EQ(SA_READY_TO_UNLOAD, sandboxManagerService_->OnIdle(reason));
}

/**
 * @tc.name: MemoryManagerTest002
 * @tc.desc: test SetIsDelayedToUnload and IsDelayedToUnload.
 * @tc.type: FUNC
 * @tc.require: issueICIZZE
 */
HWTEST_F(SandboxManagerServiceTest, MemoryManagerTest002, TestSize.Level1)
{
    SandboxMemoryManager::GetInstance().SetIsDelayedToUnload(true);
    SystemAbilityOnDemandReason reason(OnDemandReasonId::PARAM, "test", "true", EXTRA_PARAM);
    EXPECT_EQ(SA_READY_TO_UNLOAD, sandboxManagerService_->OnIdle(reason));
    SandboxMemoryManager::GetInstance().SetIsDelayedToUnload(false);
}
#endif

/**
 * @tc.name: SandboxManagerServiceRawDataTest001
 * @tc.desc: Test Marshalling - large input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceRawDataTest001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    policy.resize(POLICY_VECTOR_SIZE + 1);
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policy);
    Uint32VecRawData resultRawData;
    uint64_t policyFlag = 0;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->SetPolicy(selfTokenId_, policyRawData, policyFlag, resultRawData));

    policy.resize(POLICY_VECTOR_LARGE_SIZE + 1);
    PolicyVecRawData policyRawData1;
    policyRawData1.Marshalling(policy);
    std::vector<uint32_t> result1;
    Uint32VecRawData resultRawData1;
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR,
        sandboxManagerService_->SetPolicy(selfTokenId_, policyRawData1, policyFlag, resultRawData1));
}

/**
 * @tc.name: SandboxManagerServiceRawDataTest002
 * @tc.desc: Test Marshalling - large input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceRawDataTest002, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    policy.resize(POLICY_VECTOR_SIZE + 1);
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policy);
    Uint32VecRawData resultRawData;
    uint64_t policyFlag = 0;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->SetPolicy(selfTokenId_, policyRawData, policyFlag, resultRawData));

    PolicyVecRawData policyRawData1;
    std::stringstream ss;
    uint32_t policyNum = POLICY_VECTOR_SIZE;
    ss.write(reinterpret_cast<const char *>(&policyNum), sizeof(policyNum));
    PolicyInfo info;
    info.path = "/data/log";
    info.mode = OperateMode::READ_MODE;
    for (uint32_t i = 0; i < POLICY_VECTOR_SIZE; i++) {
        uint32_t pathLen = info.path.length() * POLICY_VECTOR_SIZE;
        ss.write(reinterpret_cast<const char *>(&pathLen), sizeof(pathLen));
        pathLen = info.path.length();
        ss.write(info.path.c_str(), pathLen);
        ss.write(reinterpret_cast<const char *>(&info.mode), sizeof(info.mode));
    }
    policyRawData1.serializedData = ss.str();
    policyRawData1.data = reinterpret_cast<const void *>(policyRawData1.serializedData.data());
    policyRawData1.size = policyRawData1.serializedData.length();

    std::vector<uint32_t> result1;
    Uint32VecRawData resultRawData1;
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR,
        sandboxManagerService_->SetPolicy(selfTokenId_, policyRawData1, policyFlag, resultRawData1));
}

/**
 * @tc.name: SandboxManagerServiceRawDataTest003
 * @tc.desc: Test Marshalling - large input coverage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceRawDataTest003, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    policy.resize(POLICY_VECTOR_LARGE_SIZE + 1);
    PolicyVecRawData policyRawData1;
    Uint32VecRawData resultRawData1;
    BoolVecRawData resultRawData2;
    policyRawData1.Marshalling(policy);
    uint64_t tokenId = 1;
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR,
        sandboxManagerService_->PersistPolicy(policyRawData1, resultRawData1));
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR,
        sandboxManagerService_->UnPersistPolicy(policyRawData1, resultRawData1));
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR,
        sandboxManagerService_->PersistPolicyByTokenId(tokenId, policyRawData1, resultRawData1));
    setuid(uid);
    Security::AccessToken::AccessTokenID tokenID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR,
        sandboxManagerService_->UnPersistPolicyByTokenId(tokenId, policyRawData1, resultRawData1));
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR,
        sandboxManagerService_->CheckPolicy(selfTokenId_, policyRawData1, resultRawData2));
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR,
        sandboxManagerService_->CheckPersistPolicy(selfTokenId_, policyRawData1, resultRawData2));
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR,
        sandboxManagerService_->StartAccessingPolicy(policyRawData1, resultRawData1));
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR,
        sandboxManagerService_->StopAccessingPolicy(policyRawData1, resultRawData1));
}

/**
 * @tc.name: SandboxManagerServiceRawDataTest004
 * @tc.desc: Test PolicyVecBatchReader success and insufficient batch data branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceRawDataTest004, TestSize.Level0)
{
    std::vector<PolicyInfo> policy(2);
    policy[0].path = "/data/test/0";
    policy[0].mode = OperateMode::READ_MODE;
    policy[1].path = "/data/test/1";
    policy[1].mode = OperateMode::WRITE_MODE;

    PolicyVecRawData rawData;
    ASSERT_EQ(SANDBOX_MANAGER_OK, rawData.Marshalling(policy));
    PolicyVecBatchReader reader(rawData);
    ASSERT_TRUE(reader.IsValid());
    EXPECT_EQ(policy.size(), reader.GetPolicyCount());

    std::vector<PolicyInfo> batchPolicy;
    EXPECT_EQ(SANDBOX_MANAGER_OK, reader.ReadNextBatch(1, batchPolicy));
    ASSERT_EQ(1, batchPolicy.size());
    EXPECT_EQ(policy[0].path, batchPolicy[0].path);
    EXPECT_EQ(policy[0].mode, batchPolicy[0].mode);

    std::stringstream ss;
    uint32_t policyNum = 2;
    ss.write(reinterpret_cast<const char *>(&policyNum), sizeof(policyNum));
    uint32_t pathLen = static_cast<uint32_t>(policy[0].path.length());
    ss.write(reinterpret_cast<const char *>(&pathLen), sizeof(pathLen));
    ss.write(policy[0].path.c_str(), pathLen);
    ss.write(reinterpret_cast<const char *>(&policy[0].mode), sizeof(policy[0].mode));
    ss.write(reinterpret_cast<const char *>(&policy[0].type), sizeof(policy[0].type));

    PolicyVecRawData shortRawData;
    shortRawData.serializedData = ss.str();
    shortRawData.data = reinterpret_cast<const void *>(shortRawData.serializedData.data());
    shortRawData.size = static_cast<uint32_t>(shortRawData.serializedData.size());
    PolicyVecBatchReader shortReader(shortRawData);
    ASSERT_TRUE(shortReader.IsValid());
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, shortReader.ReadNextBatch(policyNum, batchPolicy));
}

/**
 * @tc.name: SandboxManagerServiceRawDataTest005
 * @tc.desc: Test PolicyVecBatchReader rejects oversized policy count
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceRawDataTest005, TestSize.Level0)
{
    std::stringstream ss;
    uint32_t policyNum = POLICY_VEC_MAX_NUM + 1;
    ss.write(reinterpret_cast<const char *>(&policyNum), sizeof(policyNum));

    PolicyVecRawData rawData;
    rawData.serializedData = ss.str();
    rawData.data = reinterpret_cast<const void *>(rawData.serializedData.data());
    rawData.size = static_cast<uint32_t>(rawData.serializedData.size());

    PolicyVecBatchReader reader(rawData);
    EXPECT_FALSE(reader.IsValid());
    std::vector<PolicyInfo> batchPolicy;
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, reader.ReadNextBatch(1, batchPolicy));
}

/**
 * @tc.name: SandboxManagerServiceRawDataTest006
 * @tc.desc: Test PolicyVecBatchReader rejects incomplete count header payloads
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceRawDataTest006, TestSize.Level0)
{
    for (uint32_t size = 0; size < sizeof(uint32_t); ++size) {
        PolicyVecRawData rawData;
        rawData.serializedData.assign(size, 'A');
        rawData.data = reinterpret_cast<const void *>(rawData.serializedData.data());
        rawData.size = size;

        PolicyVecBatchReader reader(rawData);
        EXPECT_FALSE(reader.IsValid());
        EXPECT_EQ(0, reader.GetPolicyCount());

        std::vector<PolicyInfo> batchPolicy(1);
        batchPolicy[0].path = "/data/stale";
        batchPolicy[0].mode = OperateMode::READ_MODE;
        batchPolicy[0].type = PolicyType::SELF_PATH;
        EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, reader.ReadNextBatch(1, batchPolicy));
        EXPECT_EQ(1, batchPolicy.size());
        EXPECT_EQ("/data/stale", batchPolicy[0].path);
    }
}

/**
 * @tc.name: SandboxManagerServiceRawDataTest007
 * @tc.desc: Test PolicyVecBatchReader rejects null raw data source
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceRawDataTest007, TestSize.Level0)
{
    PolicyVecRawData rawData;
    rawData.data = nullptr;
    rawData.size = sizeof(uint32_t);

    PolicyVecBatchReader reader(rawData);
    EXPECT_FALSE(reader.IsValid());
    EXPECT_EQ(0, reader.GetPolicyCount());

    std::vector<PolicyInfo> batchPolicy;
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, reader.ReadNextBatch(1, batchPolicy));
    EXPECT_TRUE(batchPolicy.empty());
}

/**
 * @tc.name: SandboxManagerServiceRawDataTest008
 * @tc.desc: Test PolicyVecBatchReader zero policy count and zero batch behavior
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceRawDataTest008, TestSize.Level0)
{
    PolicyVecRawData rawData = BuildRawDataWithCount(0);
    PolicyVecBatchReader reader(rawData);
    ASSERT_TRUE(reader.IsValid());
    EXPECT_EQ(0, reader.GetPolicyCount());

    std::vector<PolicyInfo> batchPolicy(1);
    batchPolicy[0].path = "/data/will/clear";
    batchPolicy[0].mode = OperateMode::WRITE_MODE;
    batchPolicy[0].type = PolicyType::AUTHORIZATION_PATH;
    EXPECT_EQ(SANDBOX_MANAGER_OK, reader.ReadNextBatch(0, batchPolicy));
    EXPECT_TRUE(batchPolicy.empty());

    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, reader.ReadNextBatch(1, batchPolicy));
    EXPECT_TRUE(batchPolicy.empty());
}

/**
 * @tc.name: SandboxManagerServiceRawDataTest009
 * @tc.desc: Test PolicyVecBatchReader zero batch request does not consume next policy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceRawDataTest009, TestSize.Level0)
{
    std::vector<PolicyInfo> policy(2);
    policy[0].path = "";
    policy[0].mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
    policy[0].type = PolicyType::AUTHORIZATION_PATH;
    policy[1].path = "/data/test/after_zero_batch";
    policy[1].mode = OperateMode::DELETE_MODE;
    policy[1].type = PolicyType::OTHERS_PATH;

    PolicyVecRawData rawData = BuildRawDataFromPolicies(policy);
    PolicyVecBatchReader reader(rawData);
    ASSERT_TRUE(reader.IsValid());
    EXPECT_EQ(policy.size(), reader.GetPolicyCount());

    std::vector<PolicyInfo> batchPolicy(1);
    batchPolicy[0].path = "/data/stale/entry";
    batchPolicy[0].mode = OperateMode::CREATE_MODE;
    batchPolicy[0].type = PolicyType::SELF_PATH;
    EXPECT_EQ(SANDBOX_MANAGER_OK, reader.ReadNextBatch(0, batchPolicy));
    EXPECT_TRUE(batchPolicy.empty());

    EXPECT_EQ(SANDBOX_MANAGER_OK, reader.ReadNextBatch(1, batchPolicy));
    ASSERT_EQ(1, batchPolicy.size());
    EXPECT_EQ(policy[0].path, batchPolicy[0].path);
    EXPECT_EQ(policy[0].mode, batchPolicy[0].mode);
    EXPECT_EQ(policy[0].type, batchPolicy[0].type);

    EXPECT_EQ(SANDBOX_MANAGER_OK, reader.ReadNextBatch(1, batchPolicy));
    ASSERT_EQ(1, batchPolicy.size());
    EXPECT_EQ(policy[1].path, batchPolicy[0].path);
    EXPECT_EQ(policy[1].mode, batchPolicy[0].mode);
    EXPECT_EQ(policy[1].type, batchPolicy[0].type);
}

/**
 * @tc.name: SandboxManagerServiceRawDataTest010
 * @tc.desc: Test PolicyVecBatchReader preserves order across sequential batch reads
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceRawDataTest010, TestSize.Level0)
{
    std::vector<PolicyInfo> policy(4);
    policy[0].path = "/data/test/order/0";
    policy[0].mode = OperateMode::READ_MODE;
    policy[0].type = PolicyType::SELF_PATH;
    policy[1].path = "/data/test/order/1";
    policy[1].mode = OperateMode::WRITE_MODE;
    policy[1].type = PolicyType::AUTHORIZATION_PATH;
    policy[2].path = "/data/test/order/2";
    policy[2].mode = OperateMode::CREATE_MODE | OperateMode::DELETE_MODE;
    policy[2].type = PolicyType::OTHERS_PATH;
    policy[3].path = "";
    policy[3].mode = OperateMode::DENY_READ_MODE | OperateMode::DENY_WRITE_MODE;
    policy[3].type = PolicyType::UNKNOWN;

    PolicyVecRawData rawData = BuildRawDataFromPolicies(policy);
    PolicyVecBatchReader reader(rawData);
    ASSERT_TRUE(reader.IsValid());
    EXPECT_EQ(policy.size(), reader.GetPolicyCount());

    std::vector<PolicyInfo> batchPolicy;
    EXPECT_EQ(SANDBOX_MANAGER_OK, reader.ReadNextBatch(2, batchPolicy));
    ASSERT_EQ(2, batchPolicy.size());
    EXPECT_EQ(policy[0].path, batchPolicy[0].path);
    EXPECT_EQ(policy[0].mode, batchPolicy[0].mode);
    EXPECT_EQ(policy[0].type, batchPolicy[0].type);
    EXPECT_EQ(policy[1].path, batchPolicy[1].path);
    EXPECT_EQ(policy[1].mode, batchPolicy[1].mode);
    EXPECT_EQ(policy[1].type, batchPolicy[1].type);

    EXPECT_EQ(SANDBOX_MANAGER_OK, reader.ReadNextBatch(2, batchPolicy));
    ASSERT_EQ(2, batchPolicy.size());
    EXPECT_EQ(policy[2].path, batchPolicy[0].path);
    EXPECT_EQ(policy[2].mode, batchPolicy[0].mode);
    EXPECT_EQ(policy[2].type, batchPolicy[0].type);
    EXPECT_EQ(policy[3].path, batchPolicy[1].path);
    EXPECT_EQ(policy[3].mode, batchPolicy[1].mode);
    EXPECT_EQ(policy[3].type, batchPolicy[1].type);

    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, reader.ReadNextBatch(1, batchPolicy));
    EXPECT_TRUE(batchPolicy.empty());
}

/**
 * @tc.name: SandboxManagerServiceRawDataTest011
 * @tc.desc: Test PolicyVecBatchReader returns partial batch when request exceeds remaining policies
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceRawDataTest011, TestSize.Level0)
{
    std::vector<PolicyInfo> policy(1);
    policy[0].path = "/data/test/single";
    policy[0].mode = OperateMode::RENAME_MODE;
    policy[0].type = PolicyType::AUTHORIZATION_PATH;

    PolicyVecRawData rawData = BuildRawDataFromPolicies(policy);
    PolicyVecBatchReader reader(rawData);
    ASSERT_TRUE(reader.IsValid());
    EXPECT_EQ(1, reader.GetPolicyCount());

    std::vector<PolicyInfo> batchPolicy(1);
    batchPolicy[0].path = "/data/stale";
    batchPolicy[0].mode = OperateMode::READ_MODE;
    batchPolicy[0].type = PolicyType::UNKNOWN;
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, reader.ReadNextBatch(2, batchPolicy));
    ASSERT_EQ(1, batchPolicy.size());
    EXPECT_EQ(policy[0].path, batchPolicy[0].path);
    EXPECT_EQ(policy[0].mode, batchPolicy[0].mode);
    EXPECT_EQ(policy[0].type, batchPolicy[0].type);
}

/**
 * @tc.name: SandboxManagerServiceRawDataTest012
 * @tc.desc: Test PolicyVecBatchReader rejects policy with missing path length field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceRawDataTest012, TestSize.Level0)
{
    std::stringstream ss;
    AppendRawUint32(ss, 1);
    ss.put('X');
    ss.put('Y');

    PolicyVecRawData rawData = BuildRawDataFromStream(ss);
    PolicyVecBatchReader reader(rawData);
    ASSERT_TRUE(reader.IsValid());
    EXPECT_EQ(1, reader.GetPolicyCount());

    std::vector<PolicyInfo> batchPolicy(1);
    batchPolicy[0].path = "/data/should_be_cleared";
    batchPolicy[0].mode = OperateMode::WRITE_MODE;
    batchPolicy[0].type = PolicyType::SELF_PATH;
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, reader.ReadNextBatch(1, batchPolicy));
    EXPECT_TRUE(batchPolicy.empty());
}

/**
 * @tc.name: SandboxManagerServiceRawDataTest013
 * @tc.desc: Test PolicyVecBatchReader rejects path length beyond remaining bytes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceRawDataTest013, TestSize.Level0)
{
    std::stringstream ss;
    AppendRawUint32(ss, 1);
    AppendRawUint32(ss, 64);
    ss.write("tiny", 4);

    PolicyVecRawData rawData = BuildRawDataFromStream(ss);
    PolicyVecBatchReader reader(rawData);
    ASSERT_TRUE(reader.IsValid());
    EXPECT_EQ(1, reader.GetPolicyCount());

    std::vector<PolicyInfo> batchPolicy;
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, reader.ReadNextBatch(1, batchPolicy));
    EXPECT_TRUE(batchPolicy.empty());
}

/**
 * @tc.name: SandboxManagerServiceRawDataTest014
 * @tc.desc: Test PolicyVecBatchReader rejects policy with truncated mode field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceRawDataTest014, TestSize.Level0)
{
    std::stringstream ss;
    AppendRawUint32(ss, 1);
    AppendRawUint32(ss, 5);
    ss.write("/data", 5);
    ss.put('M');
    ss.put('O');
    ss.put('D');

    PolicyVecRawData rawData = BuildRawDataFromStream(ss);
    PolicyVecBatchReader reader(rawData);
    ASSERT_TRUE(reader.IsValid());
    EXPECT_EQ(1, reader.GetPolicyCount());

    std::vector<PolicyInfo> batchPolicy(1);
    batchPolicy[0].path = "/data/clear/me";
    batchPolicy[0].mode = OperateMode::DELETE_MODE;
    batchPolicy[0].type = PolicyType::OTHERS_PATH;
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, reader.ReadNextBatch(1, batchPolicy));
    EXPECT_TRUE(batchPolicy.empty());
}

/**
 * @tc.name: SandboxManagerServiceRawDataTest015
 * @tc.desc: Test PolicyVecBatchReader rejects policy with truncated type field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceRawDataTest015, TestSize.Level0)
{
    std::stringstream ss;
    AppendRawUint32(ss, 1);
    AppendRawUint32(ss, 10);
    ss.write("/data/type", 10);
    AppendRawUint64(ss, OperateMode::READ_MODE | OperateMode::CREATE_MODE);
    ss.put('T');

    PolicyVecRawData rawData = BuildRawDataFromStream(ss);
    PolicyVecBatchReader reader(rawData);
    ASSERT_TRUE(reader.IsValid());
    EXPECT_EQ(1, reader.GetPolicyCount());

    std::vector<PolicyInfo> batchPolicy;
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, reader.ReadNextBatch(1, batchPolicy));
    EXPECT_TRUE(batchPolicy.empty());
}

/**
 * @tc.name: SandboxManagerServiceRawDataTest016
 * @tc.desc: Test PolicyVecBatchReader returns parsed prefix before malformed second policy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceRawDataTest016, TestSize.Level0)
{
    PolicyInfo firstPolicy;
    firstPolicy.path = "/data/test/first";
    firstPolicy.mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
    firstPolicy.type = PolicyType::SELF_PATH;

    std::stringstream ss;
    AppendRawUint32(ss, 2);
    AppendRawPolicy(ss, firstPolicy);
    AppendRawUint32(ss, 32);
    ss.write("bad", 3);

    PolicyVecRawData rawData = BuildRawDataFromStream(ss);
    PolicyVecBatchReader reader(rawData);
    ASSERT_TRUE(reader.IsValid());
    EXPECT_EQ(2, reader.GetPolicyCount());

    std::vector<PolicyInfo> batchPolicy;
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, reader.ReadNextBatch(2, batchPolicy));
    ASSERT_EQ(1, batchPolicy.size());
    EXPECT_EQ(firstPolicy.path, batchPolicy[0].path);
    EXPECT_EQ(firstPolicy.mode, batchPolicy[0].mode);
    EXPECT_EQ(firstPolicy.type, batchPolicy[0].type);
}

/**
 * @tc.name: SandboxManagerServiceRawDataTest017
 * @tc.desc: Test PolicyVecBatchReader handles exact boundary payload sizes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceRawDataTest017, TestSize.Level0)
{
    PolicyInfo policyInfo;
    policyInfo.path = "A";
    policyInfo.mode = OperateMode::MAX_MODE - 1;
    policyInfo.type = PolicyType::OTHERS_PATH;

    std::stringstream ss;
    AppendRawUint32(ss, 1);
    AppendRawPolicy(ss, policyInfo);

    PolicyVecRawData rawData = BuildRawDataFromStream(ss);
    ASSERT_EQ(rawData.size, sizeof(uint32_t) + sizeof(uint32_t) + 1 + sizeof(uint64_t) + sizeof(PolicyType));

    PolicyVecBatchReader reader(rawData);
    ASSERT_TRUE(reader.IsValid());
    EXPECT_EQ(1, reader.GetPolicyCount());

    std::vector<PolicyInfo> batchPolicy;
    EXPECT_EQ(SANDBOX_MANAGER_OK, reader.ReadNextBatch(1, batchPolicy));
    ASSERT_EQ(1, batchPolicy.size());
    EXPECT_EQ(policyInfo.path, batchPolicy[0].path);
    EXPECT_EQ(policyInfo.mode, batchPolicy[0].mode);
    EXPECT_EQ(policyInfo.type, batchPolicy[0].type);
}

/**
 * @tc.name: SandboxManagerServiceRawDataTest018
 * @tc.desc: Test PolicyVecBatchReader sequential failure on malformed later batch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceRawDataTest018, TestSize.Level0)
{
    PolicyInfo firstPolicy;
    firstPolicy.path = "/data/test/batch0";
    firstPolicy.mode = OperateMode::READ_MODE;
    firstPolicy.type = PolicyType::AUTHORIZATION_PATH;

    std::stringstream ss;
    AppendRawUint32(ss, 2);
    AppendRawPolicy(ss, firstPolicy);
    AppendRawUint32(ss, 5);
    ss.write("abc", 3);

    PolicyVecRawData rawData = BuildRawDataFromStream(ss);
    PolicyVecBatchReader reader(rawData);
    ASSERT_TRUE(reader.IsValid());
    EXPECT_EQ(2, reader.GetPolicyCount());

    std::vector<PolicyInfo> batchPolicy;
    EXPECT_EQ(SANDBOX_MANAGER_OK, reader.ReadNextBatch(1, batchPolicy));
    ASSERT_EQ(1, batchPolicy.size());
    EXPECT_EQ(firstPolicy.path, batchPolicy[0].path);
    EXPECT_EQ(firstPolicy.mode, batchPolicy[0].mode);
    EXPECT_EQ(firstPolicy.type, batchPolicy[0].type);

    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, reader.ReadNextBatch(1, batchPolicy));
    EXPECT_TRUE(batchPolicy.empty());
}

/**
 * @tc.name: SandboxManagerServiceRawDataTest019
 * @tc.desc: Test PolicyVecBatchReader supports empty path policy in standalone payload
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceRawDataTest019, TestSize.Level0)
{
    PolicyInfo policyInfo;
    policyInfo.path = "";
    policyInfo.mode = OperateMode::DENY_READ_MODE;
    policyInfo.type = PolicyType::UNKNOWN;

    std::stringstream ss;
    AppendRawUint32(ss, 1);
    AppendRawPolicy(ss, policyInfo);

    PolicyVecRawData rawData = BuildRawDataFromStream(ss);
    PolicyVecBatchReader reader(rawData);
    ASSERT_TRUE(reader.IsValid());
    EXPECT_EQ(1, reader.GetPolicyCount());

    std::vector<PolicyInfo> batchPolicy;
    EXPECT_EQ(SANDBOX_MANAGER_OK, reader.ReadNextBatch(1, batchPolicy));
    ASSERT_EQ(1, batchPolicy.size());
    EXPECT_TRUE(batchPolicy[0].path.empty());
    EXPECT_EQ(policyInfo.mode, batchPolicy[0].mode);
    EXPECT_EQ(policyInfo.type, batchPolicy[0].type);
}

#ifdef DEC_ENABLED
/**
 * @tc.name: SandboxManagerServiceNew001
 * @tc.desc: Test SetPolicyByBundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceNew001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policy);
    Uint32VecRawData resultRawData;

    std::string bundleName = "sandbox_manager_test";
    int32_t index = 0;
    uint64_t policyFlag = 0;
    EXPECT_EQ(PERMISSION_DENIED,
        sandboxManagerService_->SetPolicyByBundleName(bundleName, index, policyRawData, policyFlag, resultRawData));

    SetSelfTokenID(sysGrantToken_);
    PolicyVecRawData policyRawData1;
    EXPECT_EQ(INVALID_PARAMETER,
        sandboxManagerService_->SetPolicyByBundleName(bundleName, index, policyRawData1, policyFlag, resultRawData));

    policy.resize(1);
    policyRawData1.Marshalling(policy);
    Uint32VecRawData resultRawData2;
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->SetPolicyByBundleName(bundleName, index, policyRawData1, policyFlag, resultRawData2));
    policyFlag = 2;
    Uint32VecRawData resultRawData3;
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->SetPolicyByBundleName(bundleName, index, policyRawData1, policyFlag, resultRawData3));

    index = -1;
    Uint32VecRawData resultRawData4;
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->SetPolicyByBundleName(bundleName, index, policyRawData1, policyFlag, resultRawData4));
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: SandboxManagerServiceNew002
 * @tc.desc: Test SetDenyPolicy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceNew002, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(SPACE_MGR_SERVICE_UID);
    std::vector<PolicyInfo> policy;
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policy);
    Uint32VecRawData resultRawData;
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->SetDenyPolicy(selfTokenId_, policyRawData, resultRawData));
    uint64_t sizeLimit = 0;

    policy.resize(POLICY_VECTOR_SIZE + 1);
    PolicyVecRawData policyRawData1;
    policyRawData1.Marshalling(policy);
    std::vector<uint32_t> result1;
    Uint32VecRawData resultRawData1;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->SetDenyPolicy(selfTokenId_, policyRawData1, resultRawData1));
    resultRawData1.Unmarshalling(result1);
    sizeLimit = POLICY_VECTOR_SIZE + 1;
    EXPECT_EQ(sizeLimit, result1.size());

    policy.resize(1);
    PolicyVecRawData policyRawData2;
    policyRawData2.Marshalling(policy);
    Uint32VecRawData resultRawData2;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->SetDenyPolicy(selfTokenId_, policyRawData2, resultRawData2));
    Uint32VecRawData resultRawData3;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->SetDenyPolicy(0, policyRawData2, resultRawData3));
    setuid(uid);
    Uint32VecRawData resultRawData4;
    EXPECT_EQ(PERMISSION_DENIED, sandboxManagerService_->SetDenyPolicy(selfTokenId_, policyRawData2, resultRawData4));
}

/**
 * @tc.name: SandboxManagerServiceNew003
 * @tc.desc: Test UnSetPolicy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceNew003, TestSize.Level0)
{
    PolicyInfo policy {
        .mode = OperateMode::READ_MODE,
        .path = "/test",
    };
    PolicyInfoParcel policyInfoParcel;
    policyInfoParcel.policyInfo = policy;
    EXPECT_EQ(PERMISSION_DENIED, sandboxManagerService_->UnSetDenyPolicy(0, policyInfoParcel));
    int32_t uid = getuid();
    setuid(SPACE_MGR_SERVICE_UID);
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->UnSetDenyPolicy(0, policyInfoParcel));
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->UnSetDenyPolicy(selfTokenId_, policyInfoParcel));
    PolicyInfo policy1 {
        .mode = OperateMode::READ_MODE,
        .path = "",
    };
    policyInfoParcel.policyInfo = policy1;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->UnSetDenyPolicy(selfTokenId_, policyInfoParcel));
    PolicyInfo policy2 {
        .mode = OperateMode::DENY_READ_MODE,
        .path = "/test",
    };
    policyInfoParcel.policyInfo = policy2;
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->UnSetDenyPolicy(selfTokenId_, policyInfoParcel));
    setuid(uid);
}

/**
 * @tc.name: SandboxManagerServiceNew004
 * @tc.desc: Test UnSetPolicy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceNew004, TestSize.Level0)
{
    std::vector<PolicyInfo> policyInfo;
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policyInfo);
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->SetPolicyAsync(0, policyRawData, 0, 0));

    PolicyInfo policy {
        .mode = OperateMode::READ_MODE,
        .path = "/test",
    };
    PolicyInfoParcel policyInfoParcel;
    policyInfoParcel.policyInfo = policy;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->UnSetPolicyAsync(0, policyInfoParcel));
}

/**
 * @tc.name: SandboxManagerServiceNew005
 * @tc.desc: Test UnSetPolicy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceNew005, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policy);
    BoolVecRawData resultRawData;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->CheckPolicy(0, policyRawData, resultRawData));
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->CheckPolicy(1, policyRawData, resultRawData));
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->CheckPolicy(selfTokenId_, policyRawData, resultRawData));
    policy.resize(1);
    PolicyVecRawData policyRawData2;
    policyRawData2.Marshalling(policy);
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->CheckPolicy(selfTokenId_, policyRawData2, resultRawData));
}
/**
 * @tc.name: SandboxManagerDfxHelperReportPolicyViolateTest001
 * @tc.desc: Test ReportPolicyViolate basic functionality
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerDfxHelperReportPolicyViolateTest001, TestSize.Level1)
{
    // Test basic report functionality - should not crash
    uint32_t tokenId = 100001;
    std::string reason = "test violate";

    int32_t ret = SandboxManagerDfxHelper::ReportPolicyViolate(tokenId, reason);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: SandboxManagerDfxHelperReportPolicyViolateTest002
 * @tc.desc: Test ReportPolicyViolate with path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerDfxHelperReportPolicyViolateTest002, TestSize.Level1)
{
    uint32_t tokenId = 100002;
    std::string path = "/data/test/path";

    int32_t ret = SandboxManagerDfxHelper::ReportPolicyViolate(tokenId, "path test", path);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: SandboxManagerDfxHelperReportPolicyViolateTest003
 * @tc.desc: Test ReportPolicyViolate with path and bundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerDfxHelperReportPolicyViolateTest003, TestSize.Level1)
{
    uint32_t tokenId = 100003;
    std::string path = "/data/test/full/path";
    std::string bundleName = "com.example.test";

    int32_t ret = SandboxManagerDfxHelper::ReportPolicyViolate(tokenId, "full test", path, bundleName);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: SandboxManagerDfxHelperReportPolicyViolateTest004
 * @tc.desc: Test ReportPolicyViolate with errorCode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerDfxHelperReportPolicyViolateTest004, TestSize.Level1)
{
    uint32_t tokenId = 100004;
    int32_t errorCode = PERMISSION_DENIED;

    int32_t ret = SandboxManagerDfxHelper::ReportPolicyViolate(tokenId, "permission denied", errorCode);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: SandboxManagerDfxHelperReportPolicyViolateTest005
 * @tc.desc: Test ReportPolicyViolate with path, bundleName and errorCode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerDfxHelperReportPolicyViolateTest005, TestSize.Level1)
{
    uint32_t tokenId = 100005;
    std::string path = "/data/test/full/params";
    std::string bundleName = "com.example.test";
    int32_t errorCode = INVALID_PARAMTER;

    int32_t ret = SandboxManagerDfxHelper::ReportPolicyViolate(tokenId, "invalid param", path, bundleName, errorCode);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}
#endif

} // SandboxManager
} // AccessControl
} // OHOS
