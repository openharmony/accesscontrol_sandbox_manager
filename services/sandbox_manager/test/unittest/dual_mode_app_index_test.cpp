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
#include <sstream>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "hap_token_info.h"
#include "nativetoken_kit.h"
#include "policy_info.h"
#include "policy_info_parcel.h"
#include "sandbox_manager_const.h"
#include "sandbox_manager_rdb.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_event_subscriber.h"
#define private public
#include "sandbox_manager_service.h"
#include "policy_info_manager.h"
#undef private
#include "sandbox_manager_dfx_helper.h"
#include "system_ability_definition.h"
#include "sandbox_test_common.h"
#include "token_setproc.h"
#include "os_account_manager.h"
#include "generic_values.h"
#include "policy_field_const.h"
#define private public
#include "persistent_preserve.h"
#include "share_files.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
const std::string SET_POLICY_PERMISSION = "ohos.permission.SET_SANDBOX_POLICY";
const std::string CHECK_POLICY_PERMISSION = "ohos.permission.CHECK_SANDBOX_POLICY";
const std::string ACCESS_PERSIST_PERMISSION = "ohos.permission.FILE_ACCESS_PERSIST";
const std::string FILE_ACCESS_PERMISSION = "ohos.permission.FILE_ACCESS_MANAGER";

Security::AccessToken::PermissionStateFull g_dualModeState1 = {
    .permissionName = SET_POLICY_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_dualModeState2 = {
    .permissionName = ACCESS_PERSIST_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_dualModeState3 = {
    .permissionName = CHECK_POLICY_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_dualModeState4 = {
    .permissionName = FILE_ACCESS_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::HapInfoParams g_dualModeInfoParms = {
    .userID = 1,
    .bundleName = "sandbox_manager_dualmode_test",
    .instIndex = 0,
    .appIDDesc = "test",
    .isSystemApp = true
};
Security::AccessToken::HapPolicyParams g_dualModePolicyPrams = {
    .apl = Security::AccessToken::APL_NORMAL,
    .domain = "test.domain",
    .permList = {},
    .permStateList = {g_dualModeState1, g_dualModeState2, g_dualModeState3, g_dualModeState4}
};
} // namespace

class DualModeAppIndexTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<SandboxManagerService> sandboxManagerService_;
    uint64_t sysGrantToken_;
    uint64_t selfTokenId_ = 1;
};

void DualModeAppIndexTest::SetUpTestCase(void)
{
    if (PolicyInfoManager::GetInstance().macAdapter_.fd_ > 0) {
        close(PolicyInfoManager::GetInstance().macAdapter_.fd_);
        PolicyInfoManager::GetInstance().macAdapter_.fd_ = -1;
        PolicyInfoManager::GetInstance().macAdapter_.isMacSupport_ = false;
    }
    PolicyInfoManager::GetInstance().macAdapter_.Init();
    SandboxManagerRdb::GetInstance().Init();
}

void DualModeAppIndexTest::TearDownTestCase(void) {}

void DualModeAppIndexTest::SetUp(void)
{
    EXPECT_TRUE(MockTokenId("foundation"));
    sandboxManagerService_ = DelayedSingleton<SandboxManagerService>::GetInstance();
    ASSERT_NE(nullptr, sandboxManagerService_);
    selfTokenId_ = GetSelfTokenID();
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_dualModeInfoParms, g_dualModePolicyPrams);
    ASSERT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    sysGrantToken_ = tokenIdEx.tokenIDEx;
    SetSelfTokenID(sysGrantToken_);
}

void DualModeAppIndexTest::TearDown(void)
{
    SetSelfTokenID(selfTokenId_);
    Security::AccessToken::AccessTokenKit::DeleteToken(sysGrantToken_);
    sandboxManagerService_ = nullptr;
}

HWTEST_F(DualModeAppIndexTest, IsMainApp_BoundaryValues_001, TestSize.Level0)
{
    EXPECT_TRUE(IsMainApp(MAIN_MODE_MAIN_APP_INDEX));
    EXPECT_TRUE(IsMainApp(SUB_MODE_MAIN_APP_INDEX));
    EXPECT_FALSE(IsMainApp(1));
    EXPECT_FALSE(IsMainApp(5));
    EXPECT_FALSE(IsMainApp(10001));
    EXPECT_FALSE(IsMainApp(10005));
    EXPECT_FALSE(IsMainApp(-1));
}

HWTEST_F(DualModeAppIndexTest, Rdb_AppIndexColumn_Exists_001, TestSize.Level1)
{
    GenericValues bundlePolicy;
    bundlePolicy.Put(PolicyFiledConst::FIELD_BUNDLENAME, std::string("test_dual_mode"));
    bundlePolicy.Put(PolicyFiledConst::FIELD_USERID, static_cast<int32_t>(100));
    bundlePolicy.Put(PolicyFiledConst::FIELD_APPIDENTIFIER, std::string("test.app.identifier"));
    bundlePolicy.Put(PolicyFiledConst::FIELD_ORIGINAL_TOKENID, static_cast<int32_t>(12345));
    bundlePolicy.Put(PolicyFiledConst::FIELD_TIMESTAMP, static_cast<int64_t>(1000));
    bundlePolicy.Put(PolicyFiledConst::FIELD_APPINDEX, SUB_MODE_MAIN_APP_INDEX);

    std::vector<GenericValues> values;
    values.push_back(bundlePolicy);
    int32_t ret = SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY, values);
    EXPECT_EQ(SandboxManagerRdb::SUCCESS, ret);

    GenericValues conditions;
    conditions.Put(PolicyFiledConst::FIELD_APPIDENTIFIER, std::string("test.app.identifier"));
    conditions.Put(PolicyFiledConst::FIELD_USERID, static_cast<int32_t>(100));
    conditions.Put(PolicyFiledConst::FIELD_APPINDEX, SUB_MODE_MAIN_APP_INDEX);
    GenericValues symbols;
    symbols.Put(PolicyFiledConst::FIELD_APPIDENTIFIER, std::string("="));
    symbols.Put(PolicyFiledConst::FIELD_USERID, std::string("="));
    symbols.Put(PolicyFiledConst::FIELD_APPINDEX, std::string("="));

    std::vector<GenericValues> results;
    ret = SandboxManagerRdb::GetInstance().Find(
        SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY, conditions, symbols, results);
    EXPECT_EQ(SandboxManagerRdb::SUCCESS, ret);
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(SUB_MODE_MAIN_APP_INDEX,
        results[0].GetInt(PolicyFiledConst::FIELD_APPINDEX));

    GenericValues delConditions;
    delConditions.Put(PolicyFiledConst::FIELD_APPIDENTIFIER, std::string("test.app.identifier"));
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY, delConditions);
}

HWTEST_F(DualModeAppIndexTest, Preserve_SameNameDiffPackage_Isolation_001, TestSize.Level1)
{
    const std::string appIdentifier = "com.example.sameapp";
    const std::string bundleName = "com.example.sameapp";
    int32_t userId = 100;
    uint32_t tokenIdA = 200001;
    uint32_t tokenIdB = 200002;

    PersistentPreserve::DeleteBundlePersistentPolicies(appIdentifier, userId, MAIN_MODE_MAIN_APP_INDEX);
    PersistentPreserve::DeleteBundlePersistentPolicies(appIdentifier, userId, SUB_MODE_MAIN_APP_INDEX);

    int32_t ret = PersistentPreserve::SaveBundlePersistentPolicies(
        bundleName, userId, appIdentifier, tokenIdA, MAIN_MODE_MAIN_APP_INDEX);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    ret = PersistentPreserve::SaveBundlePersistentPolicies(
        bundleName, userId, appIdentifier, tokenIdB, SUB_MODE_MAIN_APP_INDEX);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    ret = PersistentPreserve::DeleteBundlePersistentPolicies(appIdentifier, userId, MAIN_MODE_MAIN_APP_INDEX);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    GenericValues conditions;
    conditions.Put(PolicyFiledConst::FIELD_APPIDENTIFIER, appIdentifier);
    conditions.Put(PolicyFiledConst::FIELD_USERID, userId);
    conditions.Put(PolicyFiledConst::FIELD_APPINDEX, SUB_MODE_MAIN_APP_INDEX);
    GenericValues symbols;
    symbols.Put(PolicyFiledConst::FIELD_APPIDENTIFIER, std::string("="));
    symbols.Put(PolicyFiledConst::FIELD_USERID, std::string("="));
    symbols.Put(PolicyFiledConst::FIELD_APPINDEX, std::string("="));
    std::vector<GenericValues> results;
    ret = SandboxManagerRdb::GetInstance().Find(
        SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY, conditions, symbols, results);
    EXPECT_EQ(SandboxManagerRdb::SUCCESS, ret);
    EXPECT_EQ(1u, results.size());

    GenericValues conditionsMain = conditions;
    conditionsMain.Remove(PolicyFiledConst::FIELD_APPINDEX);
    conditionsMain.Put(PolicyFiledConst::FIELD_APPINDEX, MAIN_MODE_MAIN_APP_INDEX);
    std::vector<GenericValues> resultsMain;
    ret = SandboxManagerRdb::GetInstance().Find(
        SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY, conditionsMain, symbols, resultsMain);
    EXPECT_EQ(SandboxManagerRdb::SUCCESS, ret);
    EXPECT_EQ(0u, resultsMain.size());

    PersistentPreserve::DeleteBundlePersistentPolicies(appIdentifier, userId, SUB_MODE_MAIN_APP_INDEX);
}

HWTEST_F(DualModeAppIndexTest, Preserve_Restore_OnlyMatchesAppIndex_001, TestSize.Level1)
{
    const std::string appIdentifier = "com.example.restore_test";
    const std::string bundleName = "com.example.restore_test";
    int32_t userId = 100;
    uint32_t oldTokenA = 300001;
    uint32_t oldTokenB = 300002;
    uint32_t newTokenB = 300003;

    PersistentPreserve::DeleteBundlePersistentPolicies(appIdentifier, userId, MAIN_MODE_MAIN_APP_INDEX);
    PersistentPreserve::DeleteBundlePersistentPolicies(appIdentifier, userId, SUB_MODE_MAIN_APP_INDEX);

    PersistentPreserve::SaveBundlePersistentPolicies(
        bundleName, userId, appIdentifier, oldTokenA, MAIN_MODE_MAIN_APP_INDEX);
    PersistentPreserve::SaveBundlePersistentPolicies(
        bundleName, userId, appIdentifier, oldTokenB, SUB_MODE_MAIN_APP_INDEX);

    int32_t ret = PersistentPreserve::RestoreBundlePersistentPolicies(
        appIdentifier, userId, newTokenB, bundleName, SUB_MODE_MAIN_APP_INDEX);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    GenericValues conditions;
    conditions.Put(PolicyFiledConst::FIELD_APPIDENTIFIER, appIdentifier);
    conditions.Put(PolicyFiledConst::FIELD_USERID, userId);
    conditions.Put(PolicyFiledConst::FIELD_APPINDEX, SUB_MODE_MAIN_APP_INDEX);
    GenericValues symbols;
    symbols.Put(PolicyFiledConst::FIELD_APPIDENTIFIER, std::string("="));
    symbols.Put(PolicyFiledConst::FIELD_USERID, std::string("="));
    symbols.Put(PolicyFiledConst::FIELD_APPINDEX, std::string("="));
    std::vector<GenericValues> results;
    SandboxManagerRdb::GetInstance().Find(
        SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY, conditions, symbols, results);
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(static_cast<int32_t>(oldTokenB),
        results[0].GetInt(PolicyFiledConst::FIELD_ORIGINAL_TOKENID));

    GenericValues conditionsMain = conditions;
    conditionsMain.Remove(PolicyFiledConst::FIELD_APPINDEX);
    conditionsMain.Put(PolicyFiledConst::FIELD_APPINDEX, MAIN_MODE_MAIN_APP_INDEX);
    std::vector<GenericValues> resultsMain;
    SandboxManagerRdb::GetInstance().Find(
        SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY, conditionsMain, symbols, resultsMain);
    ASSERT_EQ(1u, resultsMain.size());
    EXPECT_EQ(static_cast<int32_t>(oldTokenA),
        resultsMain[0].GetInt(PolicyFiledConst::FIELD_ORIGINAL_TOKENID));

    PersistentPreserve::DeleteBundlePersistentPolicies(appIdentifier, userId, MAIN_MODE_MAIN_APP_INDEX);
    PersistentPreserve::DeleteBundlePersistentPolicies(appIdentifier, userId, SUB_MODE_MAIN_APP_INDEX);
}

HWTEST_F(DualModeAppIndexTest, IsSubModePath_MainModeClone_001, TestSize.Level0)
{
    EXPECT_FALSE(IsSubModePath("com.example.app"));
    EXPECT_FALSE(IsSubModePath("+clone-1+com.example.app"));
    EXPECT_FALSE(IsSubModePath("+clone-5+com.example.app"));
}

HWTEST_F(DualModeAppIndexTest, IsSubModePath_SubMode_001, TestSize.Level0)
{
    EXPECT_TRUE(IsSubModePath("+clone-10000+com.example.app"));
    EXPECT_TRUE(IsSubModePath("+clone-10001+com.example.app"));
    EXPECT_TRUE(IsSubModePath("+clone-10005+com.example.app"));
}

HWTEST_F(DualModeAppIndexTest, IsSubModePath_InvalidPrefix_001, TestSize.Level0)
{
    EXPECT_FALSE(IsSubModePath("com.example.app"));
    EXPECT_FALSE(IsSubModePath("+clone-abc+com.example.app"));
    EXPECT_FALSE(IsSubModePath("noclone"));
}

HWTEST_F(DualModeAppIndexTest, IsMainApp_CloneIndex_NotMainApp_001, TestSize.Level0)
{
    EXPECT_FALSE(IsMainApp(1));
    EXPECT_FALSE(IsMainApp(5));
    EXPECT_FALSE(IsMainApp(10001));
    EXPECT_FALSE(IsMainApp(10005));
}

HWTEST_F(DualModeAppIndexTest, ShareMap_CloneApp_FindPermission_001, TestSize.Level0)
{
    auto &share = SandboxManagerShare::GetInstance();
    std::string mainBundle = "com.example.sharetest";
    share.DeleteByBundleName(mainBundle);
    uint32_t userId = 100;
    std::string shareBase = "/storage/Users/currentUser/appdata/el2/base/"
        "com.example.sharetest/haps/entry/files";
    uint32_t mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
    EXPECT_TRUE(share.AddToMap(mainBundle, userId, shareBase, mode));

    PolicyInfo policy;
    policy.path = shareBase;
    policy.mode = OperateMode::READ_MODE;
    policy.type = PolicyType::AUTHORIZATION_PATH;
    int32_t ret = PolicyInfoManager::GetInstance().CheckPathIsBlocked(userId, policy);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    PolicyInfo clonePolicy;
    clonePolicy.path = "/storage/Users/currentUser/appdata/el2/base/"
        "+clone-1+com.example.sharetest/haps/entry/files";
    clonePolicy.mode = OperateMode::READ_MODE;
    clonePolicy.type = PolicyType::AUTHORIZATION_PATH;
    ret = PolicyInfoManager::GetInstance().CheckPathIsBlocked(userId, clonePolicy);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    share.DeleteByBundleName(mainBundle);
}

HWTEST_F(DualModeAppIndexTest, ShareMap_CloneApp_FindPermission_002, TestSize.Level0)
{
    std::string subBundle = "+clone-10000+com.example.sharetest";
    EXPECT_TRUE(IsSubModePath(subBundle));

    auto &share = SandboxManagerShare::GetInstance();
    share.DeleteByBundleName("com.example.sharetest");
    uint32_t userId = 100;
    std::string subPath = "/storage/Users/currentUser/appdata/el2/base/"
        "+clone-10000+com.example.sharetest/haps/entry/files/share";
    // g_shareMap has no +clone-10000+ key, FindPermission returns SHARE_BUNDLE_UNSET
    uint32_t perm = share.FindPermission(subBundle, userId, subPath);
    EXPECT_EQ(SHARE_BUNDLE_UNSET, perm);

    share.DeleteByBundleName("com.example.sharetest");
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
