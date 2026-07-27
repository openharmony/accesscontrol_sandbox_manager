/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "sandbox_manager_kit_sys_noperm_test.h"

#include <cstdint>
#include <string>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "permission_def.h"
#include "permission_state_full.h"
#include "policy_info.h"
#include "sandbox_manager_client.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_kit.h"
#include "sandbox_test_common.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
uint32_t g_selfTokenId;
uint64_t g_mockToken;

Security::AccessToken::HapInfoParams g_sysAppInfoParams = {
    .userID = 100,
    .bundleName = "sandbox_manager_sys_app_test",
    .instIndex = 0,
    .appIDDesc = "test",
    .isSystemApp = true
};

Security::AccessToken::HapPolicyParams g_sysAppPolicyParams = {
    .apl = Security::AccessToken::APL_NORMAL,
    .domain = "test.domain",
    .permList = {},
    .permStateList = {}
};
};

void SandboxManagerKitSysNopermTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
}

void SandboxManagerKitSysNopermTest::TearDownTestCase()
{
    Security::AccessToken::AccessTokenKit::DeleteToken(g_mockToken);
}

void SandboxManagerKitSysNopermTest::SetUp()
{
    EXPECT_TRUE(MockTokenId("foundation"));
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(
        g_sysAppInfoParams, g_sysAppPolicyParams);
    EXPECT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    g_mockToken = tokenIdEx.tokenIDEx;
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
}

void SandboxManagerKitSysNopermTest::TearDown()
{
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
}

static std::vector<PolicyInfo> MakeSinglePolicy()
{
    std::vector<PolicyInfo> policy;
    PolicyInfo info = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policy.emplace_back(info);
    return policy;
}

// ======== SetPolicy ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppSetPolicy001, TestSize.Level0)
{
    auto policy = MakeSinglePolicy();
    std::vector<uint32_t> result;
    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::SetPolicy(g_mockToken, policy, 0, result));
    EXPECT_EQ(0, result.size());
}

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppSetPolicyWithSetInfo001, TestSize.Level0)
{
    auto policy = MakeSinglePolicy();
    std::vector<uint32_t> result;
    SetInfo setInfo;
    setInfo.bundleName = "test.bundle";
    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::SetPolicy(g_mockToken, policy, 0, result, setInfo));
    EXPECT_EQ(0, result.size());
}

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppSetPolicyWithTimestamp001, TestSize.Level0)
{
    auto policy = MakeSinglePolicy();
    std::vector<uint32_t> result;
    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::SetPolicy(g_mockToken, policy, 0, result, uint64_t(1)));
    EXPECT_EQ(0, result.size());
}

// ======== UnSetPolicy ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppUnSetPolicy001, TestSize.Level0)
{
    PolicyInfo info = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::UnSetPolicy(g_mockToken, info));
}

// ======== SetPolicyAsync ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppSetPolicyAsync001, TestSize.Level0)
{
    auto policy = MakeSinglePolicy();
    // oneway IPC, no synchronous permission check
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicyAsync(g_mockToken, policy, 0));
}

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppSetPolicyAsyncWithTimestamp001, TestSize.Level0)
{
    auto policy = MakeSinglePolicy();
    // oneway IPC, no synchronous permission check
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicyAsync(g_mockToken, policy, 0, uint64_t(1)));
}

// ======== UnSetPolicyAsync ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppUnSetPolicyAsync001, TestSize.Level0)
{
    PolicyInfo info = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    // oneway IPC, no synchronous permission check
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicyAsync(g_mockToken, info));
}

// ======== PersistPolicy ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppPersistPolicy001, TestSize.Level0)
{
    auto policy = MakeSinglePolicy();
    std::vector<uint32_t> result;
    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::PersistPolicy(policy, result));
    EXPECT_EQ(0, result.size());
}

// ======== PersistPolicy(tokenId) ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppPersistPolicyByToken001, TestSize.Level0)
{
    auto policy = MakeSinglePolicy();
    std::vector<uint32_t> result;
    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::PersistPolicy(g_mockToken, policy, result));
    EXPECT_EQ(0, result.size());
}

// ======== UnPersistPolicy ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppUnPersistPolicy001, TestSize.Level0)
{
    auto policy = MakeSinglePolicy();
    std::vector<uint32_t> result;
    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::UnPersistPolicy(policy, result));
    EXPECT_EQ(0, result.size());
}

// ======== UnPersistPolicy(tokenId) ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppUnPersistPolicyByToken001, TestSize.Level0)
{
    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::UnPersistPolicy(g_mockToken));
}

// ======== UnPersistPolicy(tokenId, policy) ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppUnPersistPolicyByTokenId001, TestSize.Level0)
{
    auto policy = MakeSinglePolicy();
    std::vector<uint32_t> result;
    EXPECT_EQ(PERMISSION_DENIED,
        SandboxManagerKit::UnPersistPolicy(g_mockToken, policy, result));
}

// ======== GetPersistPolicy ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppGetPersistPolicy001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::GetPersistPolicy(g_mockToken, policy));
}

// ======== StartAccessingPolicy ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppStartAccessingPolicy001, TestSize.Level0)
{
    auto policy = MakeSinglePolicy();
    std::vector<uint32_t> result;
    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::StartAccessingPolicy(policy, result));
    EXPECT_EQ(0, result.size());
}

// ======== StartAccessingPolicy(useCallerToken, tokenId, timestamp) ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppStartAccessingPolicyWithParams001, TestSize.Level0)
{
    auto policy = MakeSinglePolicy();
    std::vector<uint32_t> result;
    EXPECT_EQ(PERMISSION_DENIED,
        SandboxManagerKit::StartAccessingPolicy(policy, result, true, 0, uint64_t(1)));
    EXPECT_EQ(0, result.size());
}

// ======== StopAccessingPolicy ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppStopAccessingPolicy001, TestSize.Level0)
{
    auto policy = MakeSinglePolicy();
    std::vector<uint32_t> result;
    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::StopAccessingPolicy(policy, result));
    EXPECT_EQ(0, result.size());
}

// ======== CheckPolicy ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppCheckPolicy001, TestSize.Level0)
{
    auto policy = MakeSinglePolicy();
    std::vector<bool> result;
    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::CheckPolicy(g_mockToken + 1, policy, result));
}

// ======== CheckPersistPolicy ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppCheckPersistPolicy001, TestSize.Level0)
{
    auto policy = MakeSinglePolicy();
    std::vector<bool> result;
    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::CheckPersistPolicy(g_mockToken + 1, policy, result));
}

// ======== StartAccessingByTokenId ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppStartAccessingByTokenId001, TestSize.Level0)
{
    // oneway IPC, no synchronous permission check
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingByTokenId(g_mockToken));
}

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppStartAccessingByTokenIdWithTimestamp001, TestSize.Level0)
{
    // oneway IPC, no synchronous permission check
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingByTokenId(g_mockToken, uint64_t(1)));
}

// ======== UnSetAllPolicyByToken ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppUnSetAllPolicyByToken001, TestSize.Level0)
{
    // oneway IPC, no synchronous permission check
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetAllPolicyByToken(g_mockToken));
}

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppUnSetAllPolicyByTokenWithTimestamp001, TestSize.Level0)
{
    // oneway IPC, no synchronous permission check
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetAllPolicyByToken(g_mockToken, uint64_t(1)));
}

// ======== SetPolicyByBundleName ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppSetPolicyByBundleName001, TestSize.Level0)
{
    auto policy = MakeSinglePolicy();
    std::vector<uint32_t> result;
    EXPECT_EQ(PERMISSION_DENIED,
        SandboxManagerKit::SetPolicyByBundleName("test.bundle", 0, policy, 0, result));
    EXPECT_EQ(0, result.size());
}

// ======== CleanPersistPolicyByPath ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppCleanPersistPolicyByPath001, TestSize.Level0)
{
    std::vector<std::string> paths = {"/A/B/C"};
    // oneway IPC, no synchronous permission check
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPersistPolicyByPath(paths));
}

// ======== CleanPolicyByUserId ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppCleanPolicyByUserId001, TestSize.Level0)
{
    std::vector<std::string> paths = {"/A/B/C"};
    // oneway IPC, no synchronous permission check
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPolicyByUserId(100, paths));
}

// ======== SetDenyPolicy ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppSetDenyPolicy001, TestSize.Level0)
{
    auto policy = MakeSinglePolicy();
    std::vector<uint32_t> result;
    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::SetDenyPolicy(g_mockToken, policy, result));
    EXPECT_EQ(0, result.size());
}

// ======== UnSetDenyPolicy ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppUnSetDenyPolicy001, TestSize.Level0)
{
    PolicyInfo info = {
        .path = "/A/B/C",
        .mode = OperateMode::DENY_READ_MODE
    };
    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::UnSetDenyPolicy(g_mockToken, info));
}

// ======== SetShareFileInfo ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppSetShareFileInfo001, TestSize.Level0)
{
    EXPECT_EQ(PERMISSION_DENIED,
        SandboxManagerKit::SetShareFileInfo("{}", "test.bundle", 100, g_mockToken));
}

// ======== UpdateShareFileInfo ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppUpdateShareFileInfo001, TestSize.Level0)
{
    EXPECT_EQ(PERMISSION_DENIED,
        SandboxManagerKit::UpdateShareFileInfo("{}", "test.bundle", 100, g_mockToken));
}

// ======== UnsetShareFileInfo ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppUnsetShareFileInfo001, TestSize.Level0)
{
    EXPECT_EQ(PERMISSION_DENIED,
        SandboxManagerKit::UnsetShareFileInfo(g_mockToken, "test.bundle", 100));
}

// ======== GetSharedDirectoryInfo ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppGetSharedDirectoryInfo001, TestSize.Level0)
{
    std::vector<SharedDirectoryInfo> result;
    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::GetSharedDirectoryInfo(result));
}

// ======== GrantSharedDirectoryPermission ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppGrantSharedDirectoryPermission001, TestSize.Level0)
{
    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::GrantSharedDirectoryPermission());
}

// ======== RevokeSharedDirectoryPermission ========

HWTEST_F(SandboxManagerKitSysNopermTest, SysAppRevokeSharedDirectoryPermission001, TestSize.Level0)
{
    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::RevokeSharedDirectoryPermission());
}
} //SandboxManager
} //AccessControl
} // OHOS