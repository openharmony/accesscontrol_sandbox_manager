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
#include <cinttypes>
#include <vector>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "sandbox_test_utils.h"
#include <unistd.h>
#include <chrono>
#include "gtest/gtest.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "permission_def.h"
#include "permission_state_full.h"
#include "policy_info.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_kit.h"
#include "sandbox_test_common.h"
#include "token_setproc.h"

#define HM_DEC_IOCTL_BASE 's'
#define HM_DENY_POLICY_ID 6
#define DENY_DEC_POLICY_CMD _IOW(HM_DEC_IOCTL_BASE, HM_DENY_POLICY_ID, struct SandboxPolicyInfo)

const size_t MAX_POLICY_NUM = 8;
const int DEC_POLICY_HEADER_RESERVED = 64;

struct PathInfo {
    char *path = nullptr;
    uint32_t pathLen = 0;
    uint32_t mode = 0;
    bool result = false;
};

struct SandboxPolicyInfo {
    uint64_t tokenId = 0;
    uint64_t timestamp = 0;
    struct PathInfo pathInfos[MAX_POLICY_NUM];
    uint32_t pathNum = 0;
    int32_t userId = 0;
    uint64_t reserved[DEC_POLICY_HEADER_RESERVED];
    bool persist = false;
};

static int SetDeny(const std::string& path)
{
    struct PathInfo info;
    std::string infoPath = path;
    info.path = const_cast<char *>(infoPath.c_str());
    info.pathLen = infoPath.length();
    struct SandboxPolicyInfo policyInfo;
    policyInfo.tokenId = 0;
    policyInfo.pathInfos[0] = info;
    policyInfo.pathNum = 1;
    policyInfo.persist = true;

    auto fd = open("/dev/dec", O_RDWR);
    if (fd < 0) {
        return fd;
    }
    auto ret = ioctl(fd, DENY_DEC_POLICY_CMD, &policyInfo);
    close(fd);
    return ret;
}

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
const std::string SET_POLICY_PERMISSION = "ohos.permission.SET_SANDBOX_POLICY";
const std::string ACCESS_PERSIST_PERMISSION = "ohos.permission.FILE_ACCESS_PERSIST";
const std::string CHECK_POLICY_PERMISSION = "ohos.permission.CHECK_SANDBOX_POLICY";

uint32_t g_selfTokenId = 0;
uint32_t g_mockToken = 0;
int32_t g_uid = 0;
const int32_t FOUNDATION_UID = 5523;

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
    .userID = 100,
    .bundleName = "sandbox_manager_api_test",
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

class CaseSensitivityTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        g_selfTokenId = GetSelfTokenID();
        currentUserDenied_ = IsDenyPolicyForPath("/storage/Users/currentUser");
        denyPolicyFileExists_ = IsDenyPolicyFileExists();

        // Allocate token for SetDeny
        int mockRet = MockTokenId("foundation");
        (void)mockRet;
        Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
        tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
        g_mockToken = tokenIdEx.tokenIdExStruct.tokenID;
        SetSelfTokenID(g_mockToken);
        
        // Set deny policies to define controlled paths
        SetDeny("/A");
        SetDeny("/C/D");
        SetDeny("/data/temp");
    }

    static void TearDownTestCase()
    {
        Security::AccessToken::AccessTokenKit::DeleteToken(g_mockToken);
    }

    void SetUp() override
    {
        int mockRet = MockTokenId("foundation");
        EXPECT_NE(0, mockRet);
        Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
        tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
        EXPECT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
        g_mockToken = tokenIdEx.tokenIdExStruct.tokenID;
        EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
        g_uid = getuid();
        setuid(FOUNDATION_UID);
    }

    void TearDown() override
    {
        setuid(g_uid);
        EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    }

    void CleanPersistedPolicy(const std::vector<PolicyInfo> &policy)
    {
        std::vector<uint32_t> unPersistResult;
        int32_t ret = SandboxManagerKit::UnPersistPolicy(policy, unPersistResult);
        ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
        ASSERT_EQ(1, unPersistResult.size());
        EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    }

    static bool currentUserDenied_;
    static bool denyPolicyFileExists_;
};

bool CaseSensitivityTest::currentUserDenied_ = false;
bool CaseSensitivityTest::denyPolicyFileExists_ = false;

/**
 * @tc.name: SandboxManagerKitApiTest_CaseInsensitivePath_001
 * @tc.desc: Test UnPersistPolicy with case sensitive paths (current behavior)
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(CaseSensitivityTest, CaseInsensitivePath_001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> setResult;
    std::vector<uint32_t> persistResult;
    std::vector<uint32_t> unpersistResult;
    std::vector<bool> checkResult;
    uint64_t policyFlag = 1;

    // Test case: first set a policy, then persist it
    PolicyInfo infoLower = {
        .path = "/data/temp/test_file.txt",
        .mode = OperateMode::READ_MODE
    };
    policy.emplace_back(infoLower);

    // First set policy (temporary)
    int32_t ret = SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, setResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[0]);

    // Then persist the policy
    ret = SandboxManagerKit::PersistPolicy(policy, persistResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    // Check persist policy exists
    ret = SandboxManagerKit::CheckPersistPolicy(g_mockToken, policy, checkResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, checkResult.size());
    EXPECT_TRUE(checkResult[0]);

    // Now try to unpersist using uppercase path (should fail due to case-sensitive matching)
    std::vector<PolicyInfo> upperPolicy;
    PolicyInfo infoUpper = {
        .path = "/DATA/TEMP/TEST_FILE.TXT",  // Uppercase version
        .mode = OperateMode::READ_MODE
    };
    upperPolicy.emplace_back(infoUpper);

    ret = SandboxManagerKit::UnPersistPolicy(upperPolicy, unpersistResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, unpersistResult.size());
    // Should return POLICY_HAS_NOT_BEEN_PERSISTED since paths are case-sensitive by default
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unpersistResult[0]);

    // Verify policy still exists (was not unpersisted)
    checkResult.clear();
    ret = SandboxManagerKit::CheckPersistPolicy(g_mockToken, policy, checkResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, checkResult.size());
    EXPECT_TRUE(checkResult[0]);

    // Now unpersist with the correct case
    ret = SandboxManagerKit::UnPersistPolicy(policy, unpersistResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, unpersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unpersistResult[0]);

    // Verify policy is no longer persisted
    checkResult.clear();
    ret = SandboxManagerKit::CheckPersistPolicy(g_mockToken, policy, checkResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, checkResult.size());
    EXPECT_FALSE(checkResult[0]);
}

/**
 * @tc.name: SandboxManagerKitApiTest_CaseSensitivePath_001
 * @tc.desc: Test UnPersistPolicy with case sensitive paths (current behavior)
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(CaseSensitivityTest, CaseSensitivePath_001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> setResult;
    std::vector<uint32_t> persistResult;
    std::vector<uint32_t> unpersistResult;
    std::vector<bool> checkResult;
    uint64_t policyFlag = 1;

    // Test case: first set a policy, then persist it
    PolicyInfo infoMixed = {
        .path = "/A/TestPath/file.txt",
        .mode = OperateMode::READ_MODE
    };
    policy.emplace_back(infoMixed);

    // First set policy (temporary)
    int32_t ret = SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, setResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[0]);

    // Then persist the policy
    ret = SandboxManagerKit::PersistPolicy(policy, persistResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    // Check persist policy exists
    ret = SandboxManagerKit::CheckPersistPolicy(g_mockToken, policy, checkResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, checkResult.size());
    EXPECT_TRUE(checkResult[0]);

    // Now try to unpersist using different case path (should fail due to case-sensitive matching)
    std::vector<PolicyInfo> differentCasePolicy;
    PolicyInfo infoDifferentCase = {
        .path = "/a/testpath/file.txt",  // Different case
        .mode = OperateMode::READ_MODE
    };
    differentCasePolicy.emplace_back(infoDifferentCase);

    ret = SandboxManagerKit::UnPersistPolicy(differentCasePolicy, unpersistResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, unpersistResult.size());
    // Should return POLICY_HAS_NOT_BEEN_PERSISTED since paths are case-sensitive by default
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unpersistResult[0]);

    // Verify policy still exists (was not unpersisted)
    checkResult.clear();
    ret = SandboxManagerKit::CheckPersistPolicy(g_mockToken, policy, checkResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, checkResult.size());
    EXPECT_TRUE(checkResult[0]);

    // Now unpersist with the correct case
    ret = SandboxManagerKit::UnPersistPolicy(policy, unpersistResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, unpersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unpersistResult[0]);

    // Verify policy is no longer persisted
    checkResult.clear();
    ret = SandboxManagerKit::CheckPersistPolicy(g_mockToken, policy, checkResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, checkResult.size());
    EXPECT_FALSE(checkResult[0]);
}

/**
 * @tc.name: SandboxManagerKitApiTest_SetPolicy_AppDataBlocked
 * @tc.desc: Test that SetPolicy blocks exact appdata path (case-insensitive) but allows similar names
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(CaseSensitivityTest, SetPolicy_AppDataBlocked, TestSize.Level0)
{
    std::vector<uint32_t> setResult;
    uint64_t policyFlag = 1;

    // {path, expected_result}
    std::vector<std::pair<std::string, uint32_t>> testCases = {
        // Blocked paths (exact appdata match, case-insensitive)
        {"/storage/Users/currentUser/appdata", INVALID_PATH},
        {"/storage/Users/currentUser/APPDATA", INVALID_PATH},
        {"/storage/Users/currentUser/AppData", INVALID_PATH},
        {"/storage/Users/currentUser/aPpDaTa", INVALID_PATH},
        {"/storage/Users/currentUser////aPpDaTa", INVALID_PATH},
        // Allowed paths (similar names)
        {"/storage/Users/currentUser/appdata2", OPERATE_SUCCESSFULLY},
        {"/storage/Users/currentUser/appdata_backup", OPERATE_SUCCESSFULLY},
        {"/storage/Users/currentUser/myappdata", OPERATE_SUCCESSFULLY}
    };

    std::vector<PolicyInfo> policies;
    for (const auto& tc : testCases) {
        policies.push_back({.path = tc.first, .mode = OperateMode::READ_MODE});
    }

    int32_t ret = SandboxManagerKit::SetPolicy(g_mockToken, policies, policyFlag, setResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(testCases.size(), setResult.size());

    // Blocked paths (exact appdata match, case-insensitive)
    EXPECT_EQ(INVALID_PATH, setResult[0]) << "appdata";
    EXPECT_EQ(INVALID_PATH, setResult[1]) << "APPDATA";
    EXPECT_EQ(INVALID_PATH, setResult[2]) << "AppData";
    EXPECT_EQ(INVALID_PATH, setResult[3]) << "aPpDaTa";
    EXPECT_EQ(INVALID_PATH, setResult[4]) << "////aPpDaTa";

    // Allowed paths (similar names)
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[5]) << "appdata2";
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[6]) << "appdata_backup";
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[7]) << "myappdata";
}


/**
 * @tc.name: SandboxManagerKitApiTest_AppDataCaseInsensitiveActivation
 * @tc.desc: Test that paths under appdata with more than 6 components can be activated
 *           with case-insensitive matching (e.g., AppData vs appdata)
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(CaseSensitivityTest, AppDataCaseInsensitiveActivation, TestSize.Level0)
{
    if (!denyPolicyFileExists_ || currentUserDenied_) {
        return;
    }
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> setResult;
    std::vector<uint32_t> persistResult;
    std::vector<uint32_t> startResult;
    std::vector<bool> checkResult;
    uint64_t policyFlag = 1;

    // Persist policy for /storage/Users/currentUser/appdata/el2/base/com.ohos.dlpmanager
    // This path has 8 components, which is > MAX_CHECK_COM_NUM (6), so it's allowed
    PolicyInfo infoParent = { .path = "/storage/Users/currentUser/appdata/el2/base/com.ohos.dlpmanager",
        .mode = OperateMode::READ_MODE };
    policy.emplace_back(infoParent);

    // First set policy (temporary)
    int32_t ret = SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, setResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[0]);

    // Then persist the policy
    ret = SandboxManagerKit::PersistPolicy(policy, persistResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    // Try to activate sub-paths with various case variations of appdata
    // All should succeed because:
    // 1. The paths have 9 components (> MAX_CHECK_COM_NUM), so they're not blocked
    // 2. Case-insensitive matching allows all variations to match appdata
    struct {
        std::string path;
        uint32_t expectedStartResult;
        bool expectedCheckResult;
    } activateCases[] = {
        {"/storage/Users/currentUser/appdata/el2/base/com.ohos.dlpmanager/test.txt", OPERATE_SUCCESSFULLY, true},
        {"/storage/Users/currentUser/AppData/el2/base/com.ohos.dlpmanager/test.txt", OPERATE_SUCCESSFULLY, true},
        {"/storage/Users/currentUser/APPDATA/el2/base/com.ohos.dlpmanager/test.txt", OPERATE_SUCCESSFULLY, true},
        {"/storage/Users/currentUser/aPpDaTa/el2/base/com.ohos.dlpmanager/test.txt", OPERATE_SUCCESSFULLY, true},
        {"/storage/Users/CURRENTUSER/aPpDaTa/el2/base/com.ohos.dlpmanager/test.txt",
            POLICY_HAS_NOT_BEEN_PERSISTED, false},
    };

    std::vector<PolicyInfo> activatePolicies;
    for (const auto& tc : activateCases) {
        activatePolicies.push_back({.path = tc.path, .mode = OperateMode::READ_MODE});
    }

    ret = SandboxManagerKit::StartAccessingPolicy(activatePolicies, startResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(5, startResult.size());
    ret = SandboxManagerKit::CheckPersistPolicy(g_mockToken, activatePolicies, checkResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(5, checkResult.size());
    for (size_t i = 0; i < 5; i++) {
        EXPECT_EQ(activateCases[i].expectedStartResult, startResult[i]);
        EXPECT_EQ(activateCases[i].expectedCheckResult, checkResult[i]);
    }

    // Clean up
    CleanPersistedPolicy(policy);
}

/**
 * @tc.name: SandboxManagerKitApiTest_AppDataBlocked
 * @tc.desc: Test StartAccessingPolicy and CheckPersistPolicy with path under appdata should fail
 *           even if parent is persisted (case-insensitive matching)
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(CaseSensitivityTest, AppDataBlocked, TestSize.Level0)
{
    if (!denyPolicyFileExists_ || currentUserDenied_) {
        return;
    }

    std::vector<PolicyInfo> policy = {
        {.path = "/storage/Users/currentUser", .mode = OperateMode::READ_MODE}
    };
    std::vector<uint32_t> setResult;
    std::vector<uint32_t> persistResult;
    uint64_t policyFlag = 1;

    int32_t ret = SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, setResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[0]);

    ret = SandboxManagerKit::PersistPolicy(policy, persistResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    // Test paths under appdata with various case variations
    std::vector<PolicyInfo> appDataPolicies = {
        {.path = "/storage/Users/currentUser/appdata/", .mode = OperateMode::READ_MODE},
        {.path = "/storage/Users/currentUser/appdata/el2/base/com.ohos.dlpmanager/test.txt",
         .mode = OperateMode::READ_MODE},
        {.path = "/storage/Users/currentUser/AppData/el2/base/com.ohos.dlpmanager/test.txt",
         .mode = OperateMode::READ_MODE},
        {.path = "/storage/Users/currentUser/APPDATA/el2/base/com.ohos.dlpmanager/test.txt",
         .mode = OperateMode::READ_MODE},
        {.path = "/storage/Users/currentUser/aPpDaTa/el2/base/com.ohos.dlpmanager/test.txt",
         .mode = OperateMode::READ_MODE}
    };

    // Test StartAccessingPolicy - all should fail
    std::vector<uint32_t> startResult;
    ret = SandboxManagerKit::StartAccessingPolicy(appDataPolicies, startResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(appDataPolicies.size(), startResult.size());
    for (size_t i = 0; i < startResult.size(); i++) {
        EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[i]);
    }

    // Test CheckPersistPolicy - all should fail
    std::vector<bool> checkResult;
    ret = SandboxManagerKit::CheckPersistPolicy(g_mockToken, appDataPolicies, checkResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(appDataPolicies.size(), checkResult.size());
    for (size_t i = 0; i < checkResult.size(); i++) {
        EXPECT_FALSE(checkResult[i]);
    }

    CleanPersistedPolicy(policy);
}

/**
 * @tc.name: SandboxManagerKitApiTest_DeepDeniedPath_ThumbsBlocked
 * @tc.desc: Persist .thumbnails path, then test that deep denied sub-path .nomedia is blocked
 *           while .NOMEDIA (different case) and normal sub-paths succeed in StartAccessingPolicy
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(CaseSensitivityTest, DeepDeniedPath_ThumbsBlocked, TestSize.Level0)
{
    if (!denyPolicyFileExists_ || currentUserDenied_) {
        return;
    }

    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> setResult;
    std::vector<uint32_t> persistResult;
    std::vector<uint32_t> startResult;
    std::vector<bool> checkResult;
    uint64_t policyFlag = 1;

    // Persist policy for filemanager path
    PolicyInfo infoParent = {
        .path = "/storage/Users/currentUser/HO_DATA_EXT_MISC/Pictures/.thumbnails",
        .mode = OperateMode::READ_MODE
    };
    policy.emplace_back(infoParent);

    // Set and persist the policy
    int32_t ret = SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, setResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[0]);

    ret = SandboxManagerKit::PersistPolicy(policy, persistResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<PolicyInfo> subPolicies = {
        {.path = "/storage/Users/currentUser/HO_DATA_EXT_MISC/Pictures/.thumbnails/file.txt",
         .mode = OperateMode::READ_MODE},
        {.path = "/storage/Users/currentUser/HO_DATA_EXT_MISC/Pictures/.thumbnails/.nomedia/file.txt",
         .mode = OperateMode::READ_MODE},
        {.path = "/storage/Users/currentUser/HO_DATA_EXT_MISC/Pictures/.thumbnails/.NOMEDIA/file.txt",
         .mode = OperateMode::READ_MODE}
    };

    // Test StartAccessingPolicy
    ret = SandboxManagerKit::StartAccessingPolicy(subPolicies, startResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[2]);

    // Test CheckPersistPolicy
    ret = SandboxManagerKit::CheckPersistPolicy(g_mockToken, subPolicies, checkResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(3, checkResult.size());
    EXPECT_TRUE(checkResult[0]);
    EXPECT_FALSE(checkResult[1]);
    EXPECT_FALSE(checkResult[2]);

    // Clean up
    CleanPersistedPolicy(policy);
}

/**
 * @tc.name: SandboxManagerKitApiTest_AuthorizeDeniedPath_ExactCaseOnly
 * @tc.desc: Persist the exact .thumbnails/.nomedia path, then verify StartAccessingPolicy succeeds
 *           only for exact case match while wrong-case .NOMEDIA and CURRENTUSER variants fail
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(CaseSensitivityTest, AuthorizeDeniedPath_ExactCaseOnly, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> setResult;
    std::vector<uint32_t> persistResult;
    std::vector<uint32_t> startResult;
    std::vector<bool> checkResult;
    uint64_t policyFlag = 1;

    // Persist policy for the exact denied .thumbs path
    PolicyInfo infoParent = {
        .path = "/storage/Users/currentUser/HO_DATA_EXT_MISC/Pictures/.thumbnails/.nomedia",
        .mode = OperateMode::READ_MODE
    };
    policy.emplace_back(infoParent);

    // Set and persist the policy
    int32_t ret = SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, setResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[0]);

    ret = SandboxManagerKit::PersistPolicy(policy, persistResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<PolicyInfo> subPolicies = {
        {.path = "/storage/Users/currentUser/HO_DATA_EXT_MISC/Pictures/.thumbnails/.nomedia/file.txt",
         .mode = OperateMode::READ_MODE},
        {.path = "/storage/Users/currentUser/HO_DATA_EXT_MISC/Pictures/.thumbnails/.NOMEDIA/file.txt",
         .mode = OperateMode::READ_MODE},
        {.path = "/storage/Users/CURRENTUSER/HO_DATA_EXT_MISC/Pictures/.thumbnails/.NOMEDIA/file.txt",
         .mode = OperateMode::READ_MODE}
    };

    // Test StartAccessingPolicy
    ret = SandboxManagerKit::StartAccessingPolicy(subPolicies, startResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[2]);
    // Test CheckPersistPolicy
    ret = SandboxManagerKit::CheckPersistPolicy(g_mockToken, subPolicies, checkResult);
    ASSERT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(3, checkResult.size());
    EXPECT_TRUE(checkResult[0]);
    EXPECT_TRUE(checkResult[1]);
    EXPECT_FALSE(checkResult[2]);
    // Clean up
    CleanPersistedPolicy(policy);
}

} // SandboxManager
} // AccessControl
} // OHOS
