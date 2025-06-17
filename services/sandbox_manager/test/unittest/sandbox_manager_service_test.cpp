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
#undef private
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
const uint64_t POLICY_VECTOR_SIZE = 5000;
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
    .permStateList = {g_testState1, g_testState2, g_testState3}
};
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
    std::vector<PolicyInfo> policy;
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policy);
    Uint32VecRawData resultRawData;
    uint64_t tokenId = 0;
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->PersistPolicyByTokenId(tokenId, policyRawData, resultRawData));
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->UnPersistPolicyByTokenId(tokenId, policyRawData, resultRawData));
    tokenId = 1;
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->PersistPolicyByTokenId(tokenId, policyRawData, resultRawData));
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->UnPersistPolicyByTokenId(tokenId, policyRawData, resultRawData));

    policy.resize(POLICY_VECTOR_SIZE + 1);
    PolicyVecRawData policyRawData1;
    policyRawData1.Marshalling(policy);
    Uint32VecRawData resultRawData1;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->PersistPolicyByTokenId(tokenId, policyRawData1, resultRawData1));
    Uint32VecRawData resultRawData2;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->UnPersistPolicyByTokenId(tokenId, policyRawData1, resultRawData2));
    tokenId = 0;
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->PersistPolicyByTokenId(tokenId, policyRawData1, resultRawData));
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->UnPersistPolicyByTokenId(tokenId, policyRawData1, resultRawData));

    policy.resize(1);
    PolicyVecRawData policyRawData2;
    policyRawData2.Marshalling(policy);
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->PersistPolicyByTokenId(tokenId, policyRawData2, resultRawData));
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->UnPersistPolicyByTokenId(tokenId, policyRawData2, resultRawData));
    tokenId = 1;
    Uint32VecRawData resultRawData3;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->PersistPolicyByTokenId(tokenId, policyRawData2, resultRawData3));
    Uint32VecRawData resultRawData4;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->UnPersistPolicyByTokenId(tokenId, policyRawData2, resultRawData4));
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
    SetSelfTokenID(selfTokenId_);
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
} // SandboxManager
} // AccessControl
} // OHOS