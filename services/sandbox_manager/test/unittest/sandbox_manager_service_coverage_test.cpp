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

#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "generic_values.h"
#include "hap_token_info.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "policy_field_const.h"
#include "policy_info.h"
#include "policy_info_parcel.h"
#include "sandbox_manager_const.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_rdb.h"
#include "sandbox_test_common.h"
#include "set_info_parcel.h"
#include "shared_directory_info_vec_raw_data.h"
#include "token_setproc.h"
#define private public
#include "policy_info_manager.h"
#include "policy_trie.h"
#include "sandbox_manager_service.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
const std::string SET_POLICY_PERMISSION = "ohos.permission.SET_SANDBOX_POLICY";
const std::string ACCESS_PERSIST_PERMISSION = "ohos.permission.FILE_ACCESS_PERSIST";
const std::string CHECK_POLICY_PERMISSION = "ohos.permission.CHECK_SANDBOX_POLICY";
const std::string FILE_ACCESS_PERMISSION = "ohos.permission.FILE_ACCESS_MANAGER";
const std::string REVOKE_PERSIST_PERMISSION = "ohos.permission.REVOKE_FILE_ACCESS_PERSIST";
const std::string ACCESS_SHARED_FILE_PERMISSION = "ohos.permission.ACCESS_SHARED_FILE";
const std::string GET_PERSIST_PERMISSION = "ohos.permission.GET_FILE_ACCESS_PERSIST";

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
    .permissionName = FILE_ACCESS_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_testState5 = {
    .permissionName = REVOKE_PERSIST_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_testState6 = {
    .permissionName = ACCESS_SHARED_FILE_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_testState7 = {
    .permissionName = GET_PERSIST_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};

Security::AccessToken::HapInfoParams g_testInfoParms = {
    .userID = 1,
    .bundleName = "sandbox_manager_test",
    .instIndex = 0,
    .appIDDesc = "test",
    .isSystemApp = true
};

Security::AccessToken::HapPolicyParams g_testPolicyPrams = {
    .apl = Security::AccessToken::APL_NORMAL,
    .domain = "test.domain",
    .permList = {},
    .permStateList = {g_testState1, g_testState2, g_testState3, g_testState4, g_testState5, g_testState6, g_testState7}
};
};

class SandboxManagerServiceCoverageTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<SandboxManagerService> sandboxManagerService_;
    uint64_t selfTokenId_ = 1;
    uint64_t sysGrantToken_;
};

void SandboxManagerServiceCoverageTest::SetUpTestCase(void)
{
    if (PolicyInfoManager::GetInstance().macAdapter_.fd_ > 0) {
        close(PolicyInfoManager::GetInstance().macAdapter_.fd_);
        PolicyInfoManager::GetInstance().macAdapter_.fd_ = -1;
        PolicyInfoManager::GetInstance().macAdapter_.isMacSupport_ = false;
    }
    PolicyInfoManager::GetInstance().Init();
}

void SandboxManagerServiceCoverageTest::TearDownTestCase(void) {}

void SandboxManagerServiceCoverageTest::SetUp(void)
{
    EXPECT_TRUE(MockTokenId("foundation"));
    sandboxManagerService_ = DelayedSingleton<SandboxManagerService>::GetInstance();
    ASSERT_NE(nullptr, sandboxManagerService_);
    sandboxManagerService_->Initialize();
    selfTokenId_ = GetSelfTokenID();
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
    ASSERT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    sysGrantToken_ = tokenIdEx.tokenIDEx;
}

void SandboxManagerServiceCoverageTest::TearDown(void)
{
    SetSelfTokenID(selfTokenId_);
    if (PolicyInfoManager::GetInstance().macAdapter_.fd_ > 0) {
        close(PolicyInfoManager::GetInstance().macAdapter_.fd_);
        PolicyInfoManager::GetInstance().macAdapter_.fd_ = -1;
        PolicyInfoManager::GetInstance().macAdapter_.isMacSupport_ = false;
    }
    sandboxManagerService_ = nullptr;
    Security::AccessToken::AccessTokenKit::DeleteToken(sysGrantToken_);
    GenericValues cleanConditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, cleanConditions);
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_SHARED_FILE_INFO, cleanConditions);
}

static void InsertSharedFileInfo(int32_t userId, const std::string &bundleName,
    const std::string &osPath, int64_t mode)
{
    GenericValues info;
    info.Put(PolicyFiledConst::FIELD_USER_ID, userId);
    info.Put(PolicyFiledConst::FIELD_BUNDLE_NAME, bundleName);
    info.Put(PolicyFiledConst::FIELD_SHARED_OS_PATH, osPath);
    info.Put(PolicyFiledConst::FIELD_SHARED_MODE, mode);
    std::vector<GenericValues> values = {info};
    SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_SHARED_FILE_INFO, values);
}

static PolicyVecRawData BuildPolicyRawData(const std::vector<PolicyInfo> &policies)
{
    PolicyVecRawData rawData;
    rawData.Marshalling(policies);
    return rawData;
}

/**
 * @tc.name: Coverage_Mgr_UnSetPolicy_Batch_001
 * @tc.desc: Cover PolicyInfoManager::UnSetPolicy batch overload (line 1084-1149)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceCoverageTest, Coverage_Mgr_UnSetPolicy_Batch_001, TestSize.Level0)
{
    uint32_t tokenId = static_cast<uint32_t>(sysGrantToken_);
    std::vector<PolicyInfo> policies;
    PolicyInfo info;
    info.path = "/data/coverage/unset_batch";
    info.mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
    policies.emplace_back(info);

    std::vector<uint32_t> setResult;
    SetInfo setInfo;
    setInfo.userId = 0;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().SetPolicy(tokenId, policies, 0, setResult, setInfo));

    std::vector<uint32_t> unsetResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().UnSetPolicy(tokenId, policies, unsetResult));
    ASSERT_EQ(1, unsetResult.size());

    PolicyInfoManager::GetInstance().UnSetAllPolicyByToken(tokenId);
}

/**
 * @tc.name: Coverage_Mgr_GetSharedDirectoryInfo_001
 * @tc.desc: Cover PolicyInfoManager::GetSharedDirectoryInfo + QuerySharedFileInfoByUserId (line 2173-2213)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceCoverageTest, Coverage_Mgr_GetSharedDirectoryInfo_001, TestSize.Level0)
{
    int32_t userId = 100;
    InsertSharedFileInfo(userId, "com.test.shared", "/base/files",
        static_cast<int64_t>(OperateMode::READ_MODE | OperateMode::WRITE_MODE));

    std::vector<SharedDirectoryInfo> result;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().GetSharedDirectoryInfo(result, userId));
    ASSERT_EQ(1, result.size());
    EXPECT_EQ("com.test.shared", result[0].bundleName);
    EXPECT_EQ("/base/files", result[0].path);

    std::vector<SharedDirectoryInfo> emptyResult;
    int32_t otherUserId = 999;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().GetSharedDirectoryInfo(emptyResult, otherUserId));
    EXPECT_EQ(0, emptyResult.size());
}

/**
 * @tc.name: Coverage_Mgr_GrantSharedDirectoryPermission_001
 * @tc.desc: Cover PolicyInfoManager::GrantSharedDirectoryPermission (line 2215-2252)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceCoverageTest, Coverage_Mgr_GrantSharedDirectoryPermission_001, TestSize.Level0)
{
    uint32_t tokenId = static_cast<uint32_t>(sysGrantToken_);
    int32_t userId = 100;

    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().GrantSharedDirectoryPermission(tokenId, userId));

    InsertSharedFileInfo(userId, "com.test.grant", "/base/files",
        static_cast<int64_t>(OperateMode::READ_MODE | OperateMode::WRITE_MODE));

    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().GrantSharedDirectoryPermission(tokenId, userId));

    PolicyInfoManager::GetInstance().UnSetAllPolicyByToken(tokenId);
}

/**
 * @tc.name: Coverage_Mgr_RevokeSharedDirectoryPermission_001
 * @tc.desc: Cover PolicyInfoManager::RevokeSharedDirectoryPermission + UnSetPolicy batch (line 2254-2288, 1084-1149)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceCoverageTest, Coverage_Mgr_RevokeSharedDirectoryPermission_001, TestSize.Level0)
{
    uint32_t tokenId = static_cast<uint32_t>(sysGrantToken_);
    int32_t userId = 100;

    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().RevokeSharedDirectoryPermission(tokenId, userId));

    InsertSharedFileInfo(userId, "com.test.revoke", "/base/files",
        static_cast<int64_t>(OperateMode::READ_MODE | OperateMode::WRITE_MODE));

    std::vector<PolicyInfo> policies;
    PolicyInfo info;
    info.path = "/base/files";
    info.mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
    policies.emplace_back(info);

    std::vector<uint32_t> setResult;
    SetInfo setInfo;
    setInfo.userId = userId;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().SetPolicy(tokenId, policies, 0, setResult, setInfo));

    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().RevokeSharedDirectoryPermission(tokenId, userId));
}

/**
 * @tc.name: Coverage_Mgr_BuildTrieWithAllRecords_001
 * @tc.desc: Cover PolicyInfoManager::BuildTrieWithAllRecords (line 550-572)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceCoverageTest, Coverage_Mgr_BuildTrieWithAllRecords_001, TestSize.Level0)
{
    PolicyTrie trieTree;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().BuildTrieWithAllRecords(trieTree));

    uint32_t tokenId = static_cast<uint32_t>(sysGrantToken_);
    PolicyInfo info;
    info.path = "/data/coverage/buildtrie";
    info.mode = OperateMode::READ_MODE;
    std::vector<PolicyInfo> policies = {info};
    std::vector<uint32_t> addResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().AddPolicy(tokenId, policies, addResult));

    PolicyTrie trieTree2;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().BuildTrieWithAllRecords(trieTree2));

    PolicyInfoManager::GetInstance().RemoveBundlePolicy(tokenId);
}

/**
 * @tc.name: Coverage_SetShareFileInfo_001
 * @tc.desc: Cover SandboxManagerService::SetShareFileInfo (line 1119-1128)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceCoverageTest, Coverage_SetShareFileInfo_001, TestSize.Level0)
{
    std::string cfginfo = R"({"share_files":{"scopes":[{"path":"/base/files","permission":"r+w"}],
        "sharingOSPath":"/base/files","sharingOSSubpath":"/test","sharingOSPermission":"r+w"}})";
    std::string bundleName = "com.test.svc.share";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t selfUid = getuid();
    EXPECT_EQ(PERMISSION_DENIED,
        sandboxManagerService_->SetShareFileInfo(cfginfo, bundleName, userId, tokenId));

    setuid(FOUNDATION_UID);
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->SetShareFileInfo(cfginfo, bundleName, userId, tokenId));
    setuid(selfUid);
}

/**
 * @tc.name: Coverage_UpdateShareFileInfo_001
 * @tc.desc: Cover SandboxManagerService::UpdateShareFileInfo (line 1130-1139)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceCoverageTest, Coverage_UpdateShareFileInfo_001, TestSize.Level0)
{
    std::string cfginfo = R"({"share_files":{"scopes":[{"path":"/base/files","permission":"r+w"}],
        "sharingOSPath":"/base/files","sharingOSSubpath":"/test","sharingOSPermission":"r+w"}})";
    std::string bundleName = "com.test.svc.update";
    uint32_t userId = 100;
    uint32_t tokenId = 12346;

    int32_t selfUid = getuid();
    EXPECT_EQ(PERMISSION_DENIED,
        sandboxManagerService_->UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId));

    setuid(FOUNDATION_UID);
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->SetShareFileInfo(cfginfo, bundleName, userId, tokenId));
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId));
    setuid(selfUid);
}

/**
 * @tc.name: Coverage_UnsetShareFileInfo_001
 * @tc.desc: Cover SandboxManagerService::UnsetShareFileInfo (line 1141-1149)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceCoverageTest, Coverage_UnsetShareFileInfo_001, TestSize.Level0)
{
    std::string bundleName = "com.test.svc.unset";
    uint32_t userId = 100;
    uint32_t tokenId = 12347;

    int32_t selfUid = getuid();
    EXPECT_EQ(PERMISSION_DENIED,
        sandboxManagerService_->UnsetShareFileInfo(tokenId, bundleName, userId));

    setuid(FOUNDATION_UID);
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->UnsetShareFileInfo(tokenId, bundleName, userId));
    setuid(selfUid);
}

/**
 * @tc.name: Coverage_GetSharedDirectoryInfo_001
 * @tc.desc: Cover SandboxManagerService::GetSharedDirectoryInfo (line 1156-1181)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceCoverageTest, Coverage_GetSharedDirectoryInfo_001, TestSize.Level0)
{
    int32_t userId = 100;
    InsertSharedFileInfo(userId, "com.test.svc.getdir", "/base/files",
        static_cast<int64_t>(OperateMode::READ_MODE | OperateMode::WRITE_MODE));

    SharedDirectoryInfoVecRawData resultRawData;
    EXPECT_EQ(SANDBOX_MANAGER_NOT_SYS_APP,
        sandboxManagerService_->GetSharedDirectoryInfo(resultRawData));

    SetSelfTokenID(sysGrantToken_);
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->GetSharedDirectoryInfo(resultRawData));
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: Coverage_GrantSharedDirectoryPermission_001
 * @tc.desc: Cover SandboxManagerService::GrantSharedDirectoryPermission (line 1183-1199)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceCoverageTest, Coverage_GrantSharedDirectoryPermission_001, TestSize.Level0)
{
    uint32_t tokenId = static_cast<uint32_t>(sysGrantToken_);
    int32_t userId = 100;
    InsertSharedFileInfo(userId, "com.test.svc.grant", "/base/files",
        static_cast<int64_t>(OperateMode::READ_MODE | OperateMode::WRITE_MODE));

    EXPECT_EQ(SANDBOX_MANAGER_NOT_SYS_APP,
        sandboxManagerService_->GrantSharedDirectoryPermission());

    SetSelfTokenID(sysGrantToken_);
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->GrantSharedDirectoryPermission());
    PolicyInfoManager::GetInstance().UnSetAllPolicyByToken(tokenId);
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: Coverage_RevokeSharedDirectoryPermission_001
 * @tc.desc: Cover SandboxManagerService::RevokeSharedDirectoryPermission (line 1201-1217)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceCoverageTest, Coverage_RevokeSharedDirectoryPermission_001, TestSize.Level0)
{
    uint32_t tokenId = static_cast<uint32_t>(sysGrantToken_);
    int32_t userId = 100;
    InsertSharedFileInfo(userId, "com.test.svc.revoke", "/base/files",
        static_cast<int64_t>(OperateMode::READ_MODE | OperateMode::WRITE_MODE));

    std::vector<PolicyInfo> policies;
    PolicyInfo info;
    info.path = "/base/files";
    info.mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
    policies.emplace_back(info);
    std::vector<uint32_t> setResult;
    SetInfo setInfo;
    setInfo.userId = userId;
    PolicyInfoManager::GetInstance().SetPolicy(tokenId, policies, 0, setResult, setInfo);

    EXPECT_EQ(SANDBOX_MANAGER_NOT_SYS_APP,
        sandboxManagerService_->RevokeSharedDirectoryPermission());

    SetSelfTokenID(sysGrantToken_);
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        sandboxManagerService_->RevokeSharedDirectoryPermission());
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: Coverage_SetPolicy_UserIdNegative_001
 * @tc.desc: Cover SetPolicy with setInfo.userId < 0 branch (line 483-492)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceCoverageTest, Coverage_SetPolicy_UserIdNegative_001, TestSize.Level0)
{
    uint32_t tokenId = static_cast<uint32_t>(sysGrantToken_);
    std::vector<PolicyInfo> policies;
    PolicyInfo info;
    info.path = "/data/coverage/userid_neg";
    info.mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
    policies.emplace_back(info);
    PolicyVecRawData policyRawData = BuildPolicyRawData(policies);
    Uint32VecRawData resultRawData;
    uint64_t policyFlag = 0;

    SetSelfTokenID(sysGrantToken_);
    SetInfoParcel setInfoParcel;
    setInfoParcel.setInfo.userId = -1;
    int32_t ret = sandboxManagerService_->SetPolicy(tokenId, policyRawData, policyFlag,
        resultRawData, setInfoParcel);
    EXPECT_TRUE(ret == SANDBOX_MANAGER_OK || ret == INVALID_PARAMTER);
    SetSelfTokenID(selfTokenId_);

    PolicyInfoManager::GetInstance().UnSetAllPolicyByToken(tokenId);
}

/**
 * @tc.name: Coverage_StartAccessingPolicy_UseCallerTokenFalse_001
 * @tc.desc: Cover StartAccessingPolicy with useCallerToken=false (line 622-628)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceCoverageTest, Coverage_StartAccessingPolicy_UseCallerTokenFalse_001, TestSize.Level0)
{
    uint32_t tokenId = static_cast<uint32_t>(sysGrantToken_);
    std::vector<PolicyInfo> policies;
    PolicyInfo info;
    info.path = "/data/coverage/startaccessing";
    info.mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
    policies.emplace_back(info);
    PolicyVecRawData policyRawData = BuildPolicyRawData(policies);
    Uint32VecRawData resultRawData;

    EXPECT_EQ(PERMISSION_DENIED,
        sandboxManagerService_->StartAccessingPolicy(policyRawData, resultRawData,
            false, tokenId, 0));

    int32_t selfUid = getuid();
    setuid(FOUNDATION_UID);
    int32_t ret = sandboxManagerService_->StartAccessingPolicy(policyRawData,
        resultRawData, false, tokenId, 0);
    EXPECT_TRUE(ret == SANDBOX_MANAGER_OK || ret == SANDBOX_MANAGER_DB_RETURN_EMPTY);
    setuid(selfUid);

    PolicyInfoManager::GetInstance().UnSetAllPolicyByToken(tokenId);
}

/**
 * @tc.name: Coverage_UnPersistPolicyByTokenId_HAP_001
 * @tc.desc: Cover UnPersistPolicyByTokenId HAP caller branch (line 417-433)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceCoverageTest, Coverage_UnPersistPolicyByTokenId_HAP_001, TestSize.Level0)
{
    uint32_t tokenId = static_cast<uint32_t>(sysGrantToken_);
    std::vector<PolicyInfo> policies;
    PolicyInfo info;
    info.path = "/data/coverage/unpersist_by_tokenid";
    info.mode = OperateMode::READ_MODE;
    policies.emplace_back(info);
    PolicyVecRawData policyRawData = BuildPolicyRawData(policies);
    Uint32VecRawData resultRawData;

    SetSelfTokenID(sysGrantToken_);
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->UnPersistPolicyByTokenId(0, policyRawData, resultRawData));

    uint32_t invalidTokenId = 0xFFFFFFFE;
    EXPECT_TRUE(sandboxManagerService_->UnPersistPolicyByTokenId(invalidTokenId,
        policyRawData, resultRawData) == INVALID_PARAMTER ||
        sandboxManagerService_->UnPersistPolicyByTokenId(invalidTokenId,
        policyRawData, resultRawData) == SANDBOX_MANAGER_OK);

    int32_t unpersistRet = sandboxManagerService_->UnPersistPolicyByTokenId(tokenId,
        policyRawData, resultRawData);
    EXPECT_TRUE(unpersistRet == SANDBOX_MANAGER_OK ||
        unpersistRet == SANDBOX_MANAGER_KILL_PROCESS_ERR);
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: Coverage_UnPersistPolicy_TokenInvalid_001
 * @tc.desc: Cover UnPersistPolicy(uint32_t tokenId) TOKEN_INVALID branch (line 335-339)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceCoverageTest, Coverage_UnPersistPolicy_TokenInvalid_001, TestSize.Level0)
{
    uint32_t invalidTokenId = 0xFFFFFFFD;

    SetSelfTokenID(sysGrantToken_);
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->UnPersistPolicy(0));
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->UnPersistPolicy(invalidTokenId));
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: Coverage_GetPersistPolicy_TokenInvalid_001
 * @tc.desc: Cover GetPersistPolicy TOKEN_INVALID branch (line 747-751)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceCoverageTest, Coverage_GetPersistPolicy_TokenInvalid_001, TestSize.Level0)
{
    uint32_t invalidTokenId = 0xFFFFFFFC;
    PolicyVecRawData policyRawData;

    SetSelfTokenID(sysGrantToken_);
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->GetPersistPolicy(0, policyRawData));
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->GetPersistPolicy(invalidTokenId, policyRawData));
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: Coverage_StartAccessingByTokenId_InvalidToken_001
 * @tc.desc: Cover StartAccessingByTokenId with non-zero invalid tokenId - GetUserIdByToken failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceCoverageTest, Coverage_StartAccessingByTokenId_InvalidToken_001, TestSize.Level0)
{
    uint32_t invalidTokenId = 0xFFFFFFFE;
    uint32_t selfUid = getuid();
    setuid(FOUNDATION_UID);
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->StartAccessingByTokenId(invalidTokenId, 1));
    setuid(selfUid);
}

/**
 * @tc.name: Coverage_StartAccessingPolicy_UseCallerTokenFalse_InvalidToken_001
 * @tc.desc: Cover StartAccessingPolicy with useCallerToken=false and invalid tokenId - GetUserIdByToken failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceCoverageTest, Coverage_StartAccessingPolicy_UseCallerTokenFalse_InvalidToken_001,
    TestSize.Level0)
{
    uint32_t invalidTokenId = 0xFFFFFFFE;
    std::vector<PolicyInfo> policies;
    PolicyInfo info;
    info.path = "/data/coverage/startaccessing_invalid_token";
    info.mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
    policies.emplace_back(info);
    PolicyVecRawData policyRawData = BuildPolicyRawData(policies);
    Uint32VecRawData resultRawData;

    SetSelfTokenID(sysGrantToken_);
    int32_t selfUid = getuid();
    setuid(FOUNDATION_UID);
    EXPECT_EQ(INVALID_PARAMTER,
        sandboxManagerService_->StartAccessingPolicy(policyRawData, resultRawData,
            false, invalidTokenId, 0));
    setuid(selfUid);
    SetSelfTokenID(selfTokenId_);
}

} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
