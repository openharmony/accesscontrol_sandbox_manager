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
#include "hap_token_info.h"
#include "nativetoken_kit.h"
#include "policy_info.h"
#include "policy_info_vector_parcel.h"
#include "sandbox_manager_const.h"
#include "sandbox_manager_db.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_event_subscriber.h"
#define private public
#include "sandbox_manager_event_subscriber.h"
#include "sandbox_manager_service.h"
#undef private
#include "sandboxmanager_service_ipc_interface_code.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
const std::string SET_POLICY_PERMISSION = "ohos.permission.SET_SANDBOX_POLICY";
const std::string ACCESS_PERSIST_PERMISSION = "ohos.permission.FILE_ACCESS_PERSIST";
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
    .permStateList = {g_testState1, g_testState2}
};
void NativeTokenGet()
{
    uint64_t fullTokenId;
    const char **perms = new const char *[1];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_core",
    };

    infoInstance.processName = "TestCase";
    fullTokenId = GetAccessTokenId(&infoInstance);
    EXPECT_EQ(0, SetSelfTokenID(fullTokenId));
    Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
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

PolicyInfo modeErr1, modeErr2, pathErr1, pathErr2, sysGrant, normal1, normal2, normal3;

void SandboxManagerServiceTest::SetUpTestCase(void)
{}

void SandboxManagerServiceTest::TearDownTestCase(void)
{}

void SandboxManagerServiceTest::SetUp(void)
{
    sandboxManagerService_ = DelayedSingleton<SandboxManagerService>::GetInstance();
    ASSERT_NE(nullptr, sandboxManagerService_);

    selfTokenId_ = GetSelfTokenID();
    NativeTokenGet();
    Security::AccessToken::AccessTokenID tokenID =
        Security::AccessToken::AccessTokenKit::GetNativeTokenId("foundation");
    ASSERT_NE(0, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));
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
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest001, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> result0;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->PersistPolicy(policy, result0));
    uint64_t sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result0.size());

    policy.resize(POLICY_VECTOR_SIZE_LIMIT + 1);
    std::vector<uint32_t> result1;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->PersistPolicy(policy, result1));
    sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result1.size());
}

/**
 * @tc.name: SandboxManagerServiceTest002
 * @tc.desc: Test SetPolicy - invalid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest002, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> result0;
    uint64_t policyFlag = 0;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->SetPolicy(selfTokenId_, policy, policyFlag));
    uint64_t sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result0.size());

    policy.resize(POLICY_VECTOR_SIZE_LIMIT + 1);
    std::vector<uint32_t> result;
    
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->SetPolicy(selfTokenId_, policy, policyFlag));
    sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result.size());

    policy.resize(1);
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->SetPolicy(selfTokenId_, policy, policyFlag));
    policyFlag = 1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->SetPolicy(selfTokenId_, policy, policyFlag));
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->SetPolicy(0, policy, policyFlag));
}

/**
 * @tc.name: SandboxManagerServiceTest003
 * @tc.desc: Test StartAccessingPolicy - invalid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest003, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> result0;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->StartAccessingPolicy(policy, result0));
    uint64_t sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result0.size());

    policy.resize(POLICY_VECTOR_SIZE_LIMIT + 1);
    std::vector<uint32_t> result1;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->StartAccessingPolicy(policy, result1));
    sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result1.size());
}


/**
 * @tc.name: SandboxManagerServiceTest004
 * @tc.desc: Test StopAccessingPolicy - invalid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest004, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> result0;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->StopAccessingPolicy(policy, result0));
    uint64_t sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result0.size());

    policy.resize(POLICY_VECTOR_SIZE_LIMIT + 1);
    std::vector<uint32_t> result1;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->StopAccessingPolicy(policy, result1));
    sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result1.size());
}

/**
 * @tc.name: SandboxManagerServiceTest005
 * @tc.desc: Test CheckPersistPolicy - invalid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest005, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<bool> result0;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->CheckPersistPolicy(selfTokenId_, policy, result0));
    uint64_t sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result0.size());

    policy.resize(POLICY_VECTOR_SIZE_LIMIT + 1);
    std::vector<bool> result1;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->CheckPersistPolicy(selfTokenId_, policy, result1));
    sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result1.size());

    policy.resize(0);
    std::vector<bool> result2;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->CheckPersistPolicy(0, policy, result2));
}

/**
 * @tc.name: SandboxManagerServiceTest006
 * @tc.desc: Test UnPersistPolicy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest006, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> result0;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->UnPersistPolicy(policy, result0));
    uint64_t sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result0.size());

    policy.resize(POLICY_VECTOR_SIZE_LIMIT + 1);
    std::vector<uint32_t> result1;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->UnPersistPolicy(policy, result1));
    sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result1.size());
}

/**
 * @tc.name: SandboxManagerServiceTest007
 * @tc.desc: Test PersistPolicy UnPersistPolicy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest007, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> result;
    policy.resize(1);
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->PersistPolicy(policy, result));
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->UnPersistPolicy(policy, result));
}
 
/**
 * @tc.name: SandboxManagerServiceTest008
 * @tc.desc: Test PersistPolicyByTokenId UnPersistPolicyByTokenId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest008, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> result;
    uint64_t tokenId = 0;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->PersistPolicyByTokenId(tokenId, policy, result));
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->UnPersistPolicyByTokenId(tokenId, policy, result));
    tokenId = 1;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->PersistPolicyByTokenId(tokenId, policy, result));
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->UnPersistPolicyByTokenId(tokenId, policy, result));
 
    policy.resize(POLICY_VECTOR_SIZE_LIMIT + 1);
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->PersistPolicyByTokenId(tokenId, policy, result));
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->UnPersistPolicyByTokenId(tokenId, policy, result));
    tokenId = 0;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->PersistPolicyByTokenId(tokenId, policy, result));
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->UnPersistPolicyByTokenId(tokenId, policy, result));
 
    policy.resize(1);
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->PersistPolicyByTokenId(tokenId, policy, result));
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->UnPersistPolicyByTokenId(tokenId, policy, result));
    tokenId = 1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->PersistPolicyByTokenId(tokenId, policy, result));
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->UnPersistPolicyByTokenId(tokenId, policy, result));
}
 
/**
 * @tc.name: SandboxManagerServiceTest009
 * @tc.desc: Test StartAccessingPolicy StopAccessingPolicy CheckPersistPolicy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest009, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> result;
    policy.resize(1);
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->StartAccessingPolicy(policy, result));
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->StopAccessingPolicy(policy, result));
 
    std::vector<bool> result1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->CheckPersistPolicy(selfTokenId_, policy, result1));
}

/**
 * @tc.name: SandboxManagerServiceTest010
 * @tc.desc: Test StartByEventAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest010, TestSize.Level1)
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
 * @tc.name: SandboxManagerStub001
 * @tc.desc: Test sandbox_manager_stub PersistPolicyInner UnPersistPolicyInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerStub001, TestSize.Level1)
{
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::string descriptor = "I don't know";
    data.WriteInterfaceToken(OHOS::Str8ToStr16(descriptor));
    EXPECT_EQ(-1, sandboxManagerService_->OnRemoteRequest(code, data, reply, option));
    data.WriteInterfaceToken(u"ohos.accesscontrol.sandbox_manager.ISandboxManager");
    EXPECT_NE(NO_ERROR, sandboxManagerService_->OnRemoteRequest(code, data, reply, option));
    data.WriteInterfaceToken(u"ohos.accesscontrol.sandbox_manager.ISandboxManager");
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->OnRemoteRequest(
        static_cast<uint32_t>(SandboxManagerInterfaceCode::PERSIST_PERMISSION), data, reply, option));

    sandboxManagerService_->requestFuncMap_.insert(
        std::pair<uint32_t, SandboxManagerStub::RequestFuncType>(code, nullptr));
    ASSERT_NE(sandboxManagerService_->requestFuncMap_.end(), sandboxManagerService_->requestFuncMap_.find(code));
    data.WriteInterfaceToken(u"ohos.accesscontrol.sandbox_manager.ISandboxManager");
    EXPECT_NE(NO_ERROR, sandboxManagerService_->OnRemoteRequest(code, data, reply, option));
    sandboxManagerService_->requestFuncMap_.erase(code);

    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->PersistPolicyInner(data, reply));
    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel;
    data.WriteParcelable(policyInfoVectorParcel);
    sandboxManagerService_->PersistPolicyInner(data, reply);

    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->UnPersistPolicyInner(data, reply));
    data.WriteParcelable(policyInfoVectorParcel);
    sandboxManagerService_->UnPersistPolicyInner(data, reply);
    uint64_t tokenId = 0;
    EXPECT_EQ(false, sandboxManagerService_->CheckPermission(tokenId, ACCESS_PERSIST_PERMISSION_NAME));
}

/**
 * @tc.name: SandboxManagerStub002
 * @tc.desc: Test sandbox_manager_stub PersistPolicyByTokenIdInner UnPersistPolicyByTokenIdInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerStub002, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->PersistPolicyByTokenIdInner(data, reply));
    data.WriteUint64(1);
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->PersistPolicyByTokenIdInner(data, reply));
    data.WriteUint64(1);
    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel;
    data.WriteParcelable(policyInfoVectorParcel);
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->PersistPolicyByTokenIdInner(data, reply));

    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->UnPersistPolicyByTokenIdInner(data, reply));
    data.WriteUint64(1);
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->UnPersistPolicyByTokenIdInner(data, reply));
    data.WriteUint64(1);
    data.WriteParcelable(policyInfoVectorParcel);
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->UnPersistPolicyByTokenIdInner(data, reply));
}

/**
 * @tc.name: SandboxManagerStub003
 * @tc.desc: Test sandbox_manager_stub, not granted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerStub003, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->SetPolicyInner(data, reply));
    data.WriteUint64(1);
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->SetPolicyInner(data, reply));
    data.WriteUint64(1);
    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel;
    data.WriteParcelable(policyInfoVectorParcel);
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->SetPolicyInner(data, reply));

    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->CheckPersistPolicyInner(data, reply));
    data.WriteUint64(1);
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->CheckPersistPolicyInner(data, reply));
    data.WriteUint64(1);
    data.WriteParcelable(policyInfoVectorParcel);
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->CheckPersistPolicyInner(data, reply));

    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->StartAccessingPolicyInner(data, reply));
    data.WriteUint64(1);
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->StartAccessingPolicyInner(data, reply));
    data.WriteUint64(1);
    data.WriteParcelable(policyInfoVectorParcel);
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->StartAccessingPolicyInner(data, reply));

    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->StopAccessingPolicyInner(data, reply));
    data.WriteUint64(1);
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->StopAccessingPolicyInner(data, reply));
    data.WriteUint64(1);
    data.WriteParcelable(policyInfoVectorParcel);
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->StopAccessingPolicyInner(data, reply));
}

/**
 * @tc.name: SandboxManagerStub004
 * @tc.desc: Test sandbox_manager_stub PersistPolicyInner Granted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerStub004, TestSize.Level1)
{
    SetSelfTokenID(sysGrantToken_);
    MessageParcel data, reply;
    data.WriteUint32(POLICY_VECTOR_SIZE_LIMIT + 1);
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->PersistPolicyInner(data, reply));

    std::vector<PolicyInfo> policy;
    policy.emplace_back(PolicyInfo {
        .path = "",
        .mode = 0b01,
    });
    PolicyInfoVectorParcel policyInfoVectorParcel;
    policyInfoVectorParcel.policyVector = policy;
    data.WriteParcelable(&policyInfoVectorParcel);
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->PersistPolicyInner(data, reply));
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: SandboxManagerStub005
 * @tc.desc: Test sandbox_manager_stub UnPersistPolicyInner Granted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerStub005, TestSize.Level1)
{
    SetSelfTokenID(sysGrantToken_);
    MessageParcel data, reply;
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->UnPersistPolicyInner(data, reply));

    data.WriteUint32(POLICY_VECTOR_SIZE_LIMIT + 1);
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->UnPersistPolicyInner(data, reply));

    std::vector<PolicyInfo> policy;
    policy.emplace_back(PolicyInfo {
        .path = "",
        .mode = 0b01,
    });
    PolicyInfoVectorParcel policyInfoVectorParcel;
    policyInfoVectorParcel.policyVector = policy;
    data.WriteParcelable(&policyInfoVectorParcel);
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->UnPersistPolicyInner(data, reply));
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: SandboxManagerStub006
 * @tc.desc: Test sandbox_manager_stub PersistPolicyByTokenIdInner Granted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerStub006, TestSize.Level1)
{
    SetSelfTokenID(sysGrantToken_);
    MessageParcel data, reply;
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->PersistPolicyByTokenIdInner(data, reply));

    data.WriteUint64(0);
    data.WriteUint32(POLICY_VECTOR_SIZE_LIMIT + 1);
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->PersistPolicyByTokenIdInner(data, reply));

    data.WriteUint64(0);
    std::vector<PolicyInfo> policy;
    policy.emplace_back(PolicyInfo {
        .path = "",
        .mode = 0b01,
    });
    PolicyInfoVectorParcel policyInfoVectorParcel;
    policyInfoVectorParcel.policyVector = policy;
    data.WriteParcelable(&policyInfoVectorParcel);
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->PersistPolicyByTokenIdInner(data, reply));

    data.WriteUint64(1);
    policy.clear();
    policy.emplace_back(PolicyInfo {
        .path = "test path",
        .mode = 0b01,
    });
    policyInfoVectorParcel.policyVector = policy;
    data.WriteParcelable(&policyInfoVectorParcel);
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->PersistPolicyByTokenIdInner(data, reply));
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: SandboxManagerStub007
 * @tc.desc: Test sandbox_manager_stub UnPersistPolicyByTokenIdInner Granted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerStub007, TestSize.Level1)
{
    SetSelfTokenID(sysGrantToken_);
    MessageParcel data, reply;
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->UnPersistPolicyByTokenIdInner(data, reply));

    data.WriteUint64(0);
    data.WriteUint32(POLICY_VECTOR_SIZE_LIMIT + 1);
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->UnPersistPolicyByTokenIdInner(data, reply));

    data.WriteUint64(0);
    std::vector<PolicyInfo> policy;
    policy.emplace_back(PolicyInfo {
        .path = "",
        .mode = 0b01,
    });
    PolicyInfoVectorParcel policyInfoVectorParcel;
    policyInfoVectorParcel.policyVector = policy;
    data.WriteParcelable(&policyInfoVectorParcel);
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->UnPersistPolicyByTokenIdInner(data, reply));

    data.WriteUint64(1);
    policy.clear();
    policy.emplace_back(PolicyInfo {
        .path = "test path",
        .mode = 0b01,
    });
    policyInfoVectorParcel.policyVector = policy;
    data.WriteParcelable(&policyInfoVectorParcel);
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->PersistPolicyByTokenIdInner(data, reply));
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: SandboxManagerStub008
 * @tc.desc: Test sandbox_manager_stub SetPolicyInner Granted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerStub008, TestSize.Level1)
{
    SetSelfTokenID(sysGrantToken_);
    MessageParcel data, reply;
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->SetPolicyInner(data, reply));

    data.WriteUint64(sysGrantToken_);
    data.WriteUint32(POLICY_VECTOR_SIZE_LIMIT + 1);
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->SetPolicyInner(data, reply));

    data.WriteUint64(sysGrantToken_);
    std::vector<PolicyInfo> policy;
    policy.emplace_back(PolicyInfo {
        .path = "",
        .mode = 0b01,
    });
    PolicyInfoVectorParcel policyInfoVectorParcel;
    policyInfoVectorParcel.policyVector = policy;
    data.WriteParcelable(&policyInfoVectorParcel);
    data.WriteUint64(0);
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->SetPolicyInner(data, reply));
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: SandboxManagerStub009
 * @tc.desc: Test sandbox_manager_stub StartAccessingPolicyInner Granted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerStub009, TestSize.Level1)
{
    SetSelfTokenID(sysGrantToken_);
    MessageParcel data, reply;
    data.WriteUint32(POLICY_VECTOR_SIZE_LIMIT + 1);
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->StartAccessingPolicyInner(data, reply));

    std::vector<PolicyInfo> policy;
    policy.emplace_back(PolicyInfo {
        .path = "",
        .mode = 0b01,
    });
    PolicyInfoVectorParcel policyInfoVectorParcel;
    policyInfoVectorParcel.policyVector = policy;
    data.WriteParcelable(&policyInfoVectorParcel);
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->StartAccessingPolicyInner(data, reply));
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: SandboxManagerStub010
 * @tc.desc: Test sandbox_manager_stub StopAccessingPolicyInner Granted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerStub010, TestSize.Level1)
{
    SetSelfTokenID(sysGrantToken_);
    MessageParcel data, reply;
    data.WriteUint32(POLICY_VECTOR_SIZE_LIMIT + 1);
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->StopAccessingPolicyInner(data, reply));

    std::vector<PolicyInfo> policy;
    policy.emplace_back(PolicyInfo {
        .path = "",
        .mode = 0b01,
    });
    PolicyInfoVectorParcel policyInfoVectorParcel;
    policyInfoVectorParcel.policyVector = policy;
    data.WriteParcelable(&policyInfoVectorParcel);
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->StopAccessingPolicyInner(data, reply));
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: SandboxManagerStub011
 * @tc.desc: Test sandbox_manager_stub CheckPersistPolicyInner Granted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerStub011, TestSize.Level1)
{
    SetSelfTokenID(sysGrantToken_);
    MessageParcel data, reply1;
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->UnPersistPolicyByTokenIdInner(data, reply1));

    MessageParcel reply2;
    data.WriteUint64(0);
    data.WriteUint32(POLICY_VECTOR_SIZE_LIMIT + 1);
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, sandboxManagerService_->UnPersistPolicyByTokenIdInner(data, reply2));

    MessageParcel reply3;
    data.WriteUint64(1);
    std::vector<PolicyInfo> policy;
    policy.emplace_back(PolicyInfo {
        .path = "test",
        .mode = 0b01,
    });
    PolicyInfoVectorParcel policyInfoVectorParcel;
    policyInfoVectorParcel.policyVector = policy;
    data.WriteParcelable(&policyInfoVectorParcel);
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->UnPersistPolicyByTokenIdInner(data, reply3));

    MessageParcel reply4;
    data.WriteUint64(1);
    data.WriteParcelable(&policyInfoVectorParcel);
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->CheckPersistPolicyInner(data, reply4));

    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: SandboxManagerStub012
 * @tc.desc: Test sandbox_manager_stub ret err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerStub012, TestSize.Level1)
{
    SetSelfTokenID(sysGrantToken_);
    std::vector<PolicyInfo> policy;
    PolicyInfoVectorParcel policyInfoVectorParcel;
    policyInfoVectorParcel.policyVector = policy;
    MessageParcel data, reply;

    data.WriteParcelable(&policyInfoVectorParcel);
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->PersistPolicyInner(data, reply));

    data.WriteParcelable(&policyInfoVectorParcel);
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->UnPersistPolicyInner(data, reply));

    data.WriteParcelable(&policyInfoVectorParcel);
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->StartAccessingPolicyInner(data, reply));

    data.WriteParcelable(&policyInfoVectorParcel);
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->StopAccessingPolicyInner(data, reply));
    
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: SandboxManagerSubscriberTest001
 * @tc.desc: Test SandboxManagerCommonEventSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerSubscriberTest001, TestSize.Level1)
{
    ASSERT_EQ(true, SandboxManagerCommonEventSubscriber::RegisterEvent());
    ASSERT_EQ(true, SandboxManagerCommonEventSubscriber::RegisterEvent());
    ASSERT_EQ(true, SandboxManagerCommonEventSubscriber::UnRegisterEvent());
    ASSERT_EQ(false, SandboxManagerCommonEventSubscriber::UnRegisterEvent());
}
} // SandboxManager
} // AccessControl
} // OHOS