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

#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "generic_values.h"
#include "hap_token_info.h"
#include "policy_field_const.h"
#include "policy_info.h"
#define private public
#include "policy_info_manager.h"
#include "share_files.h"
#undef private
#include "sandbox_manager_const.h"
#include "sandbox_manager_rdb.h"
#include "sandbox_manager_log.h"
#include "sandbox_manager_err_code.h"
#include <sys/mount.h>
#include "dec_test.h"
#include "token_setproc.h"
#include "sandbox_test_common.h"
#include "sandbox_manager_service.h"
#include "media_path_support.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
const std::string DOWNLOAD_PERMISSION = "ohos.permission.READ_WRITE_DOWNLOAD_DIRECTORY";
const std::string DESKTOP_PERMISSION = "ohos.permission.READ_WRITE_DESKTOP_DIRECTORY";
const std::string DOCUMENTS_PERMISSION = "ohos.permission.READ_WRITE_DOCUMENTS_DIRECTORY";
uint32_t g_mockToken;

Security::AccessToken::PermissionStateFull g_testState1 = {
    .permissionName = DOWNLOAD_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_testState2 = {
    .permissionName = DESKTOP_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_testState3 = {
    .permissionName = DOCUMENTS_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::HapInfoParams g_testInfoParms = {
    .userID = 100,
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

class NewPolicyTests : public testing::Test  {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    uint32_t selfTokenId_;
};

#ifdef DEC_ENABLED
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

static int SetConstraint(const std::string& path)
{
    struct PathInfo info;
    string infoPath = path;
    info.path = const_cast<char *>(infoPath.c_str());
    info.pathLen = infoPath.length();
    struct SandboxPolicyInfo policyInfo;
    policyInfo.tokenId = g_mockToken;
    policyInfo.pathInfos[0] = info;
    policyInfo.pathNum = 1;
    policyInfo.persist = true;

    auto fd = open("/dev/dec", O_RDWR);
    if (fd < 0) {
        std::cout << "fd open err" << std::endl;
        return fd;
    }
    auto ret = ioctl(fd, CONSTRAINT_DEC_RULE_CMD, &policyInfo);
    close(fd);
    return ret;
}
#endif

void NewPolicyTests::SetUpTestCase(void)
{
    // remove all in db
    GenericValues conditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, conditions);
}

void NewPolicyTests::TearDownTestCase(void)
{
    // remove all in db
    GenericValues conditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, conditions);
}

void NewPolicyTests::SetUp(void)
{
    selfTokenId_ = 0;
    PolicyInfoManager::GetInstance().Init();
    EXPECT_TRUE(MockTokenId("foundation"));
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
    EXPECT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    g_mockToken = tokenIdEx.tokenIdExStruct.tokenID;
}

void NewPolicyTests::TearDown(void)
{
    if (PolicyInfoManager::GetInstance().macAdapter_.fd_ > 0) {
        close(PolicyInfoManager::GetInstance().macAdapter_.fd_);
        PolicyInfoManager::GetInstance().macAdapter_.fd_ = -1;
        PolicyInfoManager::GetInstance().macAdapter_.isMacSupport_ = false;
    }
    Security::AccessToken::AccessTokenKit::DeleteToken(g_mockToken);
}

#ifdef DEC_ENABLED

/**
 * @tc.name: RemovePolicyCaseSensitiveTest
 * @tc.desc: Test RemovePolicy with case-sensitive path matching
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NewPolicyTests, RemovePolicyCaseSensitiveTest, TestSize.Level0)
{
    // Setup: Configure /storage/Users/currentUser as case-insensitive
    PolicyInfoManager::GetInstance().caseInsensitivePaths_.push_back("/storage/Users/currentUser");
    PolicyInfoManager::GetInstance().caseSensitivePaths_.push_back("/storage/Users/currentUser/appdata");

    SetConstraint("/storage/Users");

    // Step 1: Set temporary policy with original case
    std::vector<PolicyInfo> setPolicies = {
        {"/storage/Users/currentUser/appdata/el2/base/com.example/files/data.txt", OperateMode::READ_MODE}
    };
    std::vector<uint32_t> setResult;

    int32_t ret = PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, setPolicies, 1, setResult, 0);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);

    // Step 2: Add policy to persist it
    std::vector<uint32_t> addResult;
    ret = PolicyInfoManager::GetInstance().AddPolicy(g_mockToken, setPolicies, addResult, 0);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, addResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, addResult[0]);

    // Step 5: Try to remove with different case (should fail)
    PolicyInfo removePolicyWrongCase;
    removePolicyWrongCase.path = "/storage/users/currentuser/appdata/el2/base/com.example/files/DATA.txt";
    removePolicyWrongCase.mode = OperateMode::READ_MODE;

    std::vector<PolicyInfo> removePoliciesWrongCase = {removePolicyWrongCase};
    std::vector<uint32_t> removeResultWrongCase;

    ret = PolicyInfoManager::GetInstance().RemovePolicy(
        g_mockToken, removePoliciesWrongCase, removeResultWrongCase);

    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, removeResultWrongCase.size());
    EXPECT_EQ(SandboxRetType::POLICY_HAS_NOT_BEEN_PERSISTED, removeResultWrongCase[0]);

    // Step 6: Remove with exact case (should succeed)
    std::vector<PolicyInfo> removePoliciesExactCase = {
        {"/storage/Users/currentUser/appdata/el2/base/com.example/files/data.txt", OperateMode::READ_MODE}
    };
    std::vector<uint32_t> removeResultExactCase;

    ret = PolicyInfoManager::GetInstance().RemovePolicy(
        g_mockToken, removePoliciesExactCase, removeResultExactCase);

    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, removeResultExactCase.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, removeResultExactCase[0]);

    // Step 7: Verify policy has been removed
    std::vector<uint32_t> checkResultAfterSuccessRemove;
    ret = PolicyInfoManager::GetInstance().MatchPolicy(g_mockToken, removePoliciesExactCase,
        checkResultAfterSuccessRemove);
    ASSERT_EQ(1, checkResultAfterSuccessRemove.size());
    EXPECT_EQ(SandboxRetType::POLICY_HAS_NOT_BEEN_PERSISTED, checkResultAfterSuccessRemove[0]);

    // Cleanup: Clear case-insensitive paths configuration
    PolicyInfoManager::GetInstance().caseInsensitivePaths_.clear();
}

/**
 * @tc.name: RemovePolicyCaseInsensitiveTest
 * @tc.desc: Test RemovePolicy with case-insensitive path matching
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NewPolicyTests, RemovePolicyCaseInsensitiveTest, TestSize.Level0)
{
    // Ensure /storage/Users/currentUser is configured as case-insensitive
    PolicyInfoManager::GetInstance().caseInsensitivePaths_.push_back("/storage/Users/currentUser");

    SetConstraint("/storage/Users");

    // Step 1: Set a temporary policy first
    PolicyInfo setPolicy;
    setPolicy.path = "/storage/Users/currentUser/Download/TEST.TXT";  // Mixed case
    setPolicy.mode = OperateMode::READ_MODE;

    std::vector<PolicyInfo> setPolicies = {setPolicy};
    std::vector<uint32_t> setResult;

    int32_t ret = PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, setPolicies, 1, setResult, 0);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);

    // Step 2: Add the policy to persist it
    std::vector<uint32_t> addResult;
    ret = PolicyInfoManager::GetInstance().AddPolicy(g_mockToken, setPolicies, addResult, 0);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, addResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, addResult[0]);

    // Step 3: Verify the policy exists before removing it using lowercase path
    std::vector<PolicyInfo> matchPolicies = {
        {"/storage/Users/currentUser/Download/test.TXT", OperateMode::READ_MODE}  // Lowercase
    };
    std::vector<uint32_t> matchResultBeforeRemove;
    ret = PolicyInfoManager::GetInstance().MatchPolicy(g_mockToken, matchPolicies, matchResultBeforeRemove);
    ASSERT_EQ(1, matchResultBeforeRemove.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, matchResultBeforeRemove[0]); // Should find the policy

    // Step 4: Remove the policy with lowercase path (should work due to case-insensitive matching)
    std::vector<PolicyInfo> removePolicies = {
        {"/storage/Users/currentUser/Download/TEST.TXT", OperateMode::READ_MODE}
    };
    std::vector<uint32_t> removeResult;

    ret = PolicyInfoManager::GetInstance().RemovePolicy(
        g_mockToken, removePolicies, removeResult);

    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, removeResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, removeResult[0]);

    // Verify the policy has been removed by checking if it still persists
    std::vector<uint32_t> checkResult;
    ret = PolicyInfoManager::GetInstance().MatchPolicy(g_mockToken, removePolicies, checkResult);
    ASSERT_EQ(1, checkResult.size());
    EXPECT_EQ(SandboxRetType::POLICY_HAS_NOT_BEEN_PERSISTED, checkResult[0]);

    // Cleanup
    PolicyInfoManager::GetInstance().caseInsensitivePaths_.clear();
}

/**
 * @tc.name: AddPolicyCaseInsensitiveTest
 * @tc.desc: Test AddPolicy with two paths of different cases
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NewPolicyTests, AddPolicyCaseInsensitiveTest, TestSize.Level0)
{
    // Ensure /storage/Users/currentUser is configured as case-insensitive
    PolicyInfoManager::GetInstance().caseInsensitivePaths_.push_back("/storage/Users/currentUser/Insensitive");

    SetConstraint("/storage/Users");

    // Step 1: Set a temporary policy first with mixed case
    PolicyInfo setPolicy;
    setPolicy.path = "/storage/Users/currentUser/Insensitive";
    setPolicy.mode = OperateMode::READ_MODE;

    std::vector<PolicyInfo> setPolicies = {setPolicy};
    std::vector<uint32_t> setResult;

    int32_t ret = PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, setPolicies, 1, setResult, 0);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);

    // Step 2: Add two policies with different cases (mixed case and lowercase)
    std::vector<PolicyInfo> addPolicies = {
        {"/storage/Users/currentUser/Insensitive/Download/Test.TXT", OperateMode::READ_MODE},  // Mixed case
        {"/storage/Users/currentUser/Insensitive/Download/test.txt", OperateMode::READ_MODE}   // Lowercase
    };
    std::vector<uint32_t> addResult;

    ret = PolicyInfoManager::GetInstance().AddPolicy(g_mockToken, addPolicies, addResult, 0);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(2, addResult.size());
    // Both policies should be added successfully (case-insensitive matching)
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, addResult[0]);
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, addResult[1]);

    // Step 3: Verify both policies exist using different case variations
    std::vector<PolicyInfo> matchPolicies = {
        {"/storage/Users/currentUser/Insensitive/DOWNLOAD/Test.TXT", OperateMode::READ_MODE},   // Mixed case
        {"/storage/Users/currentUser/Insensitive/download/test.txt", OperateMode::READ_MODE}    // Lowercase
    };  // Combined into single vector
    std::vector<uint32_t> matchResult;
    ret = PolicyInfoManager::GetInstance().MatchPolicy(g_mockToken, matchPolicies, matchResult);
    ASSERT_EQ(2, matchResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, matchResult[0]);
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, matchResult[1]);

    // Step 4: Remove policies with lowercase path
    std::vector<PolicyInfo> removePolicies = {
        {"/storage/Users/currentUser/Insensitive/DOWNload/Test.TXT", OperateMode::READ_MODE},   // Mixed case
        {"/storage/Users/currentUser/Insensitive/downLOAD/test.txt", OperateMode::READ_MODE}    // Lowercase
    };
    std::vector<uint32_t> removeResult;

    ret = PolicyInfoManager::GetInstance().RemovePolicy(
        g_mockToken, removePolicies, removeResult);

    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(2, removeResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, removeResult[0]);

    // Verify the policies have been removed
    std::vector<uint32_t> checkResult;
    ret = PolicyInfoManager::GetInstance().MatchPolicy(g_mockToken, matchPolicies, checkResult);
    ASSERT_EQ(2, checkResult.size());
    EXPECT_EQ(SandboxRetType::POLICY_HAS_NOT_BEEN_PERSISTED, checkResult[0]);
    EXPECT_EQ(SandboxRetType::POLICY_HAS_NOT_BEEN_PERSISTED, checkResult[1]);

    // Cleanup
    PolicyInfoManager::GetInstance().caseInsensitivePaths_.clear();
}

#endif

/**
 * @tc.name: GetMediaPoliciesTest
 * @tc.desc: Test PolicyInfoManager::GetMediaPolicies function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NewPolicyTests, GetMediaPoliciesTest, TestSize.Level0)
{
    uint32_t testTokenId = 1001;
    std::vector<PolicyInfo> policies;

    // Initialize media functionality
    int32_t initResult = SandboxManagerMedia::GetInstance().InitMedia();
    EXPECT_EQ(SANDBOX_MANAGER_OK, initResult);

    // Step 1: Use MediaPermissionHelper to add some media permissions
    Media::MediaPermissionHelper* helper = Media::MediaPermissionHelper::GetMediaPermissionHelper();
    EXPECT_NE(nullptr, helper);

    std::vector<std::string> uris = {"/data/storage/el2/media/test1.jpg", "/data/storage/el2/media/test2.jpg"};
    std::vector<Media::PhotoPermissionType> photoPermissionTypes = {
        Media::PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        Media::PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO
    };

    // Grant permissions to the test token ID
    int32_t grantResult = helper->GrantPhotoUriPermission(1000, testTokenId, uris, photoPermissionTypes,
        Media::HideSensitiveType::ALL_DESENSITIZE);
    EXPECT_EQ(0, grantResult);

    // Step 2: Call GetMediaPolicies to retrieve media policies
    int32_t getResult = PolicyInfoManager::GetInstance().GetMediaPolicies(testTokenId, policies);
    EXPECT_EQ(0, getResult);

    // Step 3: Verify that media policies were added to the policies vector
    // There should be one policy added for media permissions
    EXPECT_EQ(1, policies.size());

    if (!policies.empty()) {
        // Check that the path is set correctly for media policies
        EXPECT_EQ("/data/storage/el2/media", policies[0].path);
        
        // The mode should be a combination of READ_MODE and WRITE_MODE based on the input permissions
        int32_t expectedMode = 0;
        for (const auto& perm : photoPermissionTypes) {
            if (perm == Media::PhotoPermissionType::PERSIST_READ_IMAGEVIDEO) {
                expectedMode |= OperateMode::READ_MODE;
            } else if (perm == Media::PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO) {
                expectedMode |= OperateMode::WRITE_MODE;
            } else if (perm == Media::PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO) {
                expectedMode |= (OperateMode::WRITE_MODE | OperateMode::READ_MODE);
            }
        }
        EXPECT_EQ(expectedMode, policies[0].mode);
    }
}

/**
 * @tc.name: GetPersistPolicyTest
 * @tc.desc: Test PolicyInfoManager::GetPersistPolicy function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NewPolicyTests, GetPersistPolicyTest, TestSize.Level0)
{
    uint32_t testTokenId = g_mockToken; // Use the mock token from test setup
    PolicyVecRawData policyRawData;

    // Step 1: First set a temporary policy
    PolicyInfo policy;
    policy.path = "/data/storage/el2/test/persist_policy";
    policy.mode = OperateMode::READ_MODE;
    std::vector<PolicyInfo> policiesToSet = {policy};
    std::vector<uint32_t> setResults;

    int32_t setRet = PolicyInfoManager::GetInstance().SetPolicy(testTokenId, policiesToSet, 1, setResults, 0);
    EXPECT_EQ(SANDBOX_MANAGER_OK, setRet);
    ASSERT_EQ(1, setResults.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResults[0]);

    // Step 2: Then add the policy to persist it
    std::vector<uint32_t> addResults;
    int32_t addRet = PolicyInfoManager::GetInstance().AddPolicy(testTokenId, policiesToSet, addResults);
    EXPECT_EQ(SANDBOX_MANAGER_OK, addRet);
    ASSERT_EQ(1, addResults.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, addResults[0]);

    // Step 3: Call GetPersistPolicy to retrieve all persisted policies for the token
    int32_t getResult = PolicyInfoManager::GetInstance().GetPersistPolicy(testTokenId, policyRawData);
    EXPECT_EQ(SANDBOX_MANAGER_OK, getResult);

    // Step 4: Verify the retrieved policy
    std::vector<PolicyInfo> retrievedPolicies;
    policyRawData.Unmarshalling(retrievedPolicies);
    
    EXPECT_GT(retrievedPolicies.size(), 0); // At least one policy should be retrieved
    
    // Find the specific policy we added
    bool foundTestPolicy = false;
    for (const auto& retrievedPolicy : retrievedPolicies) {
        if (retrievedPolicy.path == policy.path && retrievedPolicy.mode == policy.mode) {
            foundTestPolicy = true;
            break;
        }
    }
    EXPECT_TRUE(foundTestPolicy);

    // Step 5: Test with an invalid token ID to verify error handling
    PolicyVecRawData emptyPolicyRawData;
    int32_t invalidResult = PolicyInfoManager::GetInstance().GetPersistPolicy(0, emptyPolicyRawData);
    EXPECT_EQ(INVALID_PARAMTER, invalidResult);
}

/**
 * @tc.name: GetMediaPoliciesFailedTest
 * @tc.desc: Test PolicyInfoManager::GetMediaPolicies function when GetPhotoUriPersistPermission fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NewPolicyTests, GetMediaPoliciesFailedTest, TestSize.Level0)
{
    uint32_t testTokenId = 0;
    std::vector<PolicyInfo> policies;

    // Initialize media functionality
    int32_t initResult = SandboxManagerMedia::GetInstance().InitMedia();
    EXPECT_EQ(SANDBOX_MANAGER_OK, initResult);

    // Note: We are not granting any permissions to this token ID, so when GetPhotoUriPersistPermission
    // is called, it should return an error or empty list
    
    // Step 1: Call GetMediaPolicies to retrieve media policies for a token that has no permissions
    int32_t getResult = PolicyInfoManager::GetInstance().GetMediaPolicies(testTokenId, policies);
    // The function should return OK but the policies vector should remain empty
    EXPECT_NE(SANDBOX_MANAGER_OK, getResult);

    // Step 2: Verify that no policies were added to the policies vector
    EXPECT_EQ(0, policies.size());
}

/**
 * @tc.name: GetPersistPolicyTest_EmptyResults
 * @tc.desc: Test PolicyInfoManager::GetPersistPolicy function when no policies exist for token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NewPolicyTests, GetPersistPolicyTest_EmptyResults, TestSize.Level0)
{
    // Use a token ID that has no persisted policies
    uint32_t testTokenId = 9999; // Arbitrary token ID that shouldn't have policies
    PolicyVecRawData policyRawData;

    // Call GetPersistPolicy to retrieve policies for the token that has none
    int32_t getResult = PolicyInfoManager::GetInstance().GetPersistPolicy(testTokenId, policyRawData);
    EXPECT_EQ(SANDBOX_MANAGER_OK, getResult);

    // Verify that no policies were retrieved (empty results branch)
    std::vector<PolicyInfo> retrievedPolicies;
    policyRawData.Unmarshalling(retrievedPolicies);

    // Should have no policies since none were added for this token
    EXPECT_EQ(0, retrievedPolicies.size());
}

} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS