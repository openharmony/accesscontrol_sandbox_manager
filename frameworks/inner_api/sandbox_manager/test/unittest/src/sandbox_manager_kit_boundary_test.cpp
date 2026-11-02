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

#include "sandbox_manager_kit_boundary_test.h"

#include <climits>
#include <cstdint>
#include <fcntl.h>
#include <string>
#include <sys/ioctl.h>
#include <unistd.h>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "permission_def.h"
#include "permission_state_full.h"
#include "policy_info.h"
#include "sandbox_manager_client.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"
#include "sandbox_manager_kit.h"
#include "sandbox_test_common.h"
#include "token_setproc.h"

#define HM_DEC_IOCTL_BASE 's'
#define HM_DENY_POLICY_ID 6
#define DENY_DEC_POLICY_CMD _IOW(HM_DEC_IOCTL_BASE, HM_DENY_POLICY_ID, struct SandboxPolicyInfo)

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
const std::string SET_POLICY_PERMISSION = "ohos.permission.SET_SANDBOX_POLICY";
const std::string CHECK_POLICY_PERMISSION = "ohos.permission.CHECK_SANDBOX_POLICY";
const std::string ACCESS_PERSIST_PERMISSION = "ohos.permission.FILE_ACCESS_PERSIST";
const std::string FILE_ACCESS_PERMISSION = "ohos.permission.FILE_ACCESS_MANAGER";
const std::string DOWNLOAD_PERMISSION = "ohos.permission.READ_WRITE_DOWNLOAD_DIRECTORY";
const std::string REVOKE_PERSIST_PERMISSION_NAME = "ohos.permission.REVOKE_FILE_ACCESS_PERSIST";
const std::string GET_PERSIST_PERMISSION_NAME = "ohos.permission.GET_FILE_ACCESS_PERSIST";
const std::string ACCESS_SHARED_FILE = "ohos.permission.ACCESS_SHARED_FILE";

const size_t MAX_PATH_LENGTH = 4095;
const size_t PATH_COMPONENT_LIMIT = 250;
const uint64_t VALID_POLICY_FLAG_TEMP = 0;
const uint64_t VALID_POLICY_FLAG_PERSIST = 1;
const uint64_t INVALID_POLICY_FLAG = 2;
const int32_t FOUNDATION_UID = 5523;
const size_t MAX_POLICY_NUM = 8;
const int DEC_POLICY_HEADER_RESERVED = 64;
const std::string VALID_PATH = "/A/B";
const std::string NOT_PERSISTED_PATH = "/A/B/boundary_not_persisted";

uint32_t g_selfTokenId;
uint64_t g_mockToken;
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
    .permissionName = DOWNLOAD_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_testState6 = {
    .permissionName = GET_PERSIST_PERMISSION_NAME,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_testState7 = {
    .permissionName = REVOKE_PERSIST_PERMISSION_NAME,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_testState8 = {
    .permissionName = ACCESS_SHARED_FILE,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::HapInfoParams g_testInfoParms = {
    .userID = 100,
    .bundleName = "sandbox_manager_test",
    .instIndex = 0,
    .appIDDesc = "test",
    .isSystemApp = true
};

Security::AccessToken::HapPolicyParams g_testPolicyPrams = {
    .apl = Security::AccessToken::APL_NORMAL,
    .domain = "test.domain",
    .permList = {},
    .permStateList = {g_testState1, g_testState2, g_testState3, g_testState4,
        g_testState5, g_testState6, g_testState7, g_testState8}
};

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

// Build an absolute path with exact length, each component no longer than PATH_COMPONENT_LIMIT
std::string MakeBoundaryPath(size_t len)
{
    std::string path;
    if (len == 0) {
        return path;
    }
    path.reserve(len);
    while (path.size() < len) {
        path += '/';
        size_t remain = len - path.size();
        path.append(remain < PATH_COMPONENT_LIMIT ? remain : PATH_COMPONENT_LIMIT, 'a');
    }
    return path;
}

std::vector<PolicyInfo> MakeSinglePolicy(const std::string &path, uint64_t mode = OperateMode::READ_MODE)
{
    std::vector<PolicyInfo> policy;
    policy.push_back({.path = path, .mode = mode});
    return policy;
}

int SetDeny(const std::string &path)
{
    struct PathInfo info;
    std::string infoPath = path;
    info.path = const_cast<char *>(infoPath.c_str());
    info.pathLen = infoPath.length();
    struct SandboxPolicyInfo policyInfo;
    policyInfo.tokenId = g_mockToken;
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

int32_t g_uid;
};

bool SandboxManagerKitBoundaryTest::fileManagerPresent_ = false;

void SandboxManagerKitBoundaryTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    fileManagerPresent_ = (GetTokenIdFromProcess("file_manager_service") != 0);
    SetDeny("/A");
    SetDeny("/C/D");
    SetDeny("/data/temp");
}

void SandboxManagerKitBoundaryTest::TearDownTestCase()
{
    Security::AccessToken::AccessTokenKit::DeleteToken(g_mockToken);
}

void SandboxManagerKitBoundaryTest::SetUp()
{
    EXPECT_TRUE(MockTokenId("foundation"));
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
    EXPECT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    g_mockToken = tokenIdEx.tokenIDEx;
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
    g_uid = getuid();
    setuid(FOUNDATION_UID);
}

void SandboxManagerKitBoundaryTest::TearDown()
{
    setuid(g_uid);
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
}

/**
 * @tc.name: CleanPersistPolicyByPathBoundary001
 * @tc.desc: CleanPersistPolicyByPath with empty filePathList boundary.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, CleanPersistPolicyByPathBoundary001, TestSize.Level0)
{
    std::vector<std::string> emptyList;
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::CleanPersistPolicyByPath(emptyList));
}

/**
 * @tc.name: CleanPersistPolicyByPathBoundary002
 * @tc.desc: CleanPersistPolicyByPath with single valid path passes client boundary check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, CleanPersistPolicyByPathBoundary002, TestSize.Level0)
{
    std::vector<std::string> filePathList;
    filePathList.emplace_back(VALID_PATH);
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::CleanPersistPolicyByPath(filePathList));
}

/**
 * @tc.name: CleanPersistPolicyByPathBoundary003
 * @tc.desc: CleanPersistPolicyByPath with path length boundaries: empty string / 4095 / 4096.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, CleanPersistPolicyByPathBoundary003, TestSize.Level0)
{
    std::vector<std::string> filePathList;
    filePathList.emplace_back("");
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::CleanPersistPolicyByPath(filePathList));

    filePathList.clear();
    filePathList.emplace_back(MakeBoundaryPath(MAX_PATH_LENGTH));
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::CleanPersistPolicyByPath(filePathList));

    filePathList.clear();
    filePathList.emplace_back(MakeBoundaryPath(MAX_PATH_LENGTH + 1));
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::CleanPersistPolicyByPath(filePathList));
}

/**
 * @tc.name: PersistPolicyBoundary001
 * @tc.desc: PersistPolicy with empty policy vector boundary, both overloads.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, PersistPolicyBoundary001, TestSize.Level0)
{
    std::vector<PolicyInfo> emptyPolicy;
    std::vector<uint32_t> result;
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::PersistPolicy(emptyPolicy, result));
    EXPECT_TRUE(result.empty());
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::PersistPolicy(g_mockToken, emptyPolicy, result));
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: PersistPolicyBoundary002
 * @tc.desc: PersistPolicy with path length and mode boundaries carried in PolicyInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, PersistPolicyBoundary002, TestSize.Level0)
{
    std::vector<uint32_t> result;

    // empty path
    std::vector<PolicyInfo> emptyPathPolicy = MakeSinglePolicy("", OperateMode::WRITE_MODE);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(emptyPathPolicy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_EQ(INVALID_PATH, result[0]);

    // invalid mode 0
    result.clear();
    std::vector<PolicyInfo> invalidModePolicy = MakeSinglePolicy(VALID_PATH, 0);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(invalidModePolicy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_EQ(INVALID_MODE, result[0]);

    // all valid operate mode bits combined, mode itself is legal
    result.clear();
    uint64_t allMode = OperateMode::READ_MODE | OperateMode::WRITE_MODE |
        OperateMode::CREATE_MODE | OperateMode::DELETE_MODE | OperateMode::RENAME_MODE;
    std::vector<PolicyInfo> allModePolicy = MakeSinglePolicy(VALID_PATH, allMode);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(allModePolicy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_NE(INVALID_MODE, result[0]);

    // path length exactly MAX_PATH_LENGTH, client and service should accept the length
    result.clear();
    std::vector<PolicyInfo> maxLenPolicy = MakeSinglePolicy(MakeBoundaryPath(MAX_PATH_LENGTH));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(maxLenPolicy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_NE(INVALID_PATH, result[0]);

    // path length MAX_PATH_LENGTH + 1, service reports per-policy INVALID_PATH
    result.clear();
    std::vector<PolicyInfo> overLenPolicy = MakeSinglePolicy(MakeBoundaryPath(MAX_PATH_LENGTH + 1));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(overLenPolicy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_EQ(INVALID_PATH, result[0]);
}

/**
 * @tc.name: UnPersistPolicyBoundary001
 * @tc.desc: UnPersistPolicy with empty vector and single not-persisted policy boundary.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, UnPersistPolicyBoundary001, TestSize.Level0)
{
    std::vector<PolicyInfo> emptyPolicy;
    std::vector<uint32_t> result;
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnPersistPolicy(emptyPolicy, result));
    EXPECT_TRUE(result.empty());

    std::vector<PolicyInfo> policy = MakeSinglePolicy(NOT_PERSISTED_PATH, OperateMode::WRITE_MODE);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, result[0]);
}

/**
 * @tc.name: UnPersistPolicyByTokenIdBoundary001
 * @tc.desc: UnPersistPolicy(tokenId) with tokenId boundaries 0 / 1 / valid / UINT32_MAX.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, UnPersistPolicyByTokenIdBoundary001, TestSize.Level0)
{
    // client boundary: tokenId 0
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnPersistPolicy(0));
    // service boundary: nonexistent tokenIds are rejected with INVALID_PARAMTER
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnPersistPolicy(1));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnPersistPolicy(UINT32_MAX));
    // allocated mock token passes tokenId validation
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::UnPersistPolicy(g_mockToken));
}

/**
 * @tc.name: PersistPolicyByTokenIdBoundary001
 * @tc.desc: PersistPolicy(tokenId, ...) tokenId and policy size boundary matrix.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, PersistPolicyByTokenIdBoundary001, TestSize.Level0)
{
    std::vector<PolicyInfo> emptyPolicy;
    std::vector<PolicyInfo> policy = MakeSinglePolicy(VALID_PATH);
    std::vector<uint32_t> result;

    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::PersistPolicy(0, emptyPolicy, result));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::PersistPolicy(0, policy, result));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::PersistPolicy(1, emptyPolicy, result));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::PersistPolicy(UINT32_MAX, emptyPolicy, result));
    EXPECT_TRUE(result.empty());

    // tokenId beyond client boundary check, service accepts any nonzero tokenId here
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::PersistPolicy(1, policy, result));
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::PersistPolicy(UINT32_MAX, policy, result));
}

/**
 * @tc.name: UnPersistPolicyByTokenIdBoundary002
 * @tc.desc: UnPersistPolicy(tokenId, ...) tokenId and policy size boundary matrix.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, UnPersistPolicyByTokenIdBoundary002, TestSize.Level0)
{
    std::vector<PolicyInfo> emptyPolicy;
    std::vector<PolicyInfo> policy = MakeSinglePolicy(VALID_PATH);
    std::vector<uint32_t> result;

    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnPersistPolicy(0, emptyPolicy, result));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnPersistPolicy(0, policy, result));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnPersistPolicy(1, emptyPolicy, result));
    EXPECT_TRUE(result.empty());

    // service rejects nonexistent target tokenIds with INVALID_PARAMTER
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnPersistPolicy(1, policy, result));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnPersistPolicy(UINT32_MAX, policy, result));
    // allocated mock token passes tokenId validation
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::UnPersistPolicy(g_mockToken, policy, result));
}

/**
 * @tc.name: GetPersistPolicyBoundary001
 * @tc.desc: GetPersistPolicy with tokenId boundaries 0 / valid / UINT32_MAX.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, GetPersistPolicyBoundary001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::GetPersistPolicy(0, policy));
    EXPECT_TRUE(policy.empty());

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::GetPersistPolicy(g_mockToken, policy));

    // service rejects nonexistent tokenId with INVALID_PARAMTER
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::GetPersistPolicy(UINT32_MAX, policy));
}

/**
 * @tc.name: SetPolicyBoundary001
 * @tc.desc: SetPolicy with empty policy vector boundary, all three overloads.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, SetPolicyBoundary001, TestSize.Level0)
{
    std::vector<PolicyInfo> emptyPolicy;
    std::vector<uint32_t> result;
    SetInfo setInfo;
    uint64_t timestamp = 0;

    EXPECT_EQ(INVALID_PARAMTER,
        SandboxManagerKit::SetPolicy(g_mockToken, emptyPolicy, VALID_POLICY_FLAG_PERSIST, result));
    EXPECT_EQ(INVALID_PARAMTER,
        SandboxManagerKit::SetPolicy(g_mockToken, emptyPolicy, VALID_POLICY_FLAG_PERSIST, result, setInfo));
    EXPECT_EQ(INVALID_PARAMTER,
        SandboxManagerKit::SetPolicy(g_mockToken, emptyPolicy, VALID_POLICY_FLAG_PERSIST, result, timestamp));
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: SetPolicyBoundary002
 * @tc.desc: SetPolicy with tokenId boundary 0, all three overloads.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, SetPolicyBoundary002, TestSize.Level0)
{
    std::vector<PolicyInfo> policy = MakeSinglePolicy(VALID_PATH);
    std::vector<uint32_t> result;
    SetInfo setInfo;
    uint64_t timestamp = 0;

    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicy(0, policy, VALID_POLICY_FLAG_PERSIST, result));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicy(0, policy, VALID_POLICY_FLAG_PERSIST,
        result, setInfo));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicy(0, policy, VALID_POLICY_FLAG_PERSIST,
        result, timestamp));
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: SetPolicyBoundary003
 * @tc.desc: SetPolicy with policyFlag boundaries 0 / 1 / 2 / UINT64_MAX.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, SetPolicyBoundary003, TestSize.Level0)
{
    std::vector<PolicyInfo> policy = MakeSinglePolicy(VALID_PATH);
    std::vector<uint32_t> result;

    // invalid flags rejected by client
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicy(g_mockToken, policy, INVALID_POLICY_FLAG, result));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicy(g_mockToken, policy, UINT64_MAX, result));
    EXPECT_TRUE(result.empty());

    // flag lower boundary 0 (temporary)
    ASSERT_EQ(SANDBOX_MANAGER_OK,
        SandboxManagerKit::SetPolicy(g_mockToken, policy, VALID_POLICY_FLAG_TEMP, result));
    ASSERT_EQ(1, result.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, result[0]);

    // flag upper boundary 1 (persistent)
    result.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK,
        SandboxManagerKit::SetPolicy(g_mockToken, policy, VALID_POLICY_FLAG_PERSIST, result));
    ASSERT_EQ(1, result.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, result[0]);
}

/**
 * @tc.name: SetPolicyBoundary004
 * @tc.desc: SetPolicy with policy path length boundaries 4095 / 4096 carried in PolicyInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, SetPolicyBoundary004, TestSize.Level0)
{
    std::vector<uint32_t> result;

    std::vector<PolicyInfo> maxLenPolicy = MakeSinglePolicy(MakeBoundaryPath(MAX_PATH_LENGTH));
    ASSERT_EQ(SANDBOX_MANAGER_OK,
        SandboxManagerKit::SetPolicy(g_mockToken, maxLenPolicy, VALID_POLICY_FLAG_TEMP, result));
    ASSERT_EQ(1, result.size());
    EXPECT_NE(INVALID_PATH, result[0]);

    result.clear();
    std::vector<PolicyInfo> overLenPolicy = MakeSinglePolicy(MakeBoundaryPath(MAX_PATH_LENGTH + 1));
    ASSERT_EQ(SANDBOX_MANAGER_OK,
        SandboxManagerKit::SetPolicy(g_mockToken, overLenPolicy, VALID_POLICY_FLAG_TEMP, result));
    ASSERT_EQ(1, result.size());
    EXPECT_EQ(INVALID_PATH, result[0]);
}

/**
 * @tc.name: SetPolicySetInfoBoundary001
 * @tc.desc: SetPolicy setInfo/timestamp overload boundaries: userId INT32 range, timestamp UINT64_MAX.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, SetPolicySetInfoBoundary001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy = MakeSinglePolicy(VALID_PATH);
    std::vector<uint32_t> result;

    SetInfo defaultInfo;
    ASSERT_EQ(SANDBOX_MANAGER_OK,
        SandboxManagerKit::SetPolicy(g_mockToken, policy, VALID_POLICY_FLAG_TEMP, result, defaultInfo));

    SetInfo minUserInfo;
    minUserInfo.userId = INT32_MIN;
    result.clear();
    EXPECT_NE(INVALID_PARAMTER,
        SandboxManagerKit::SetPolicy(g_mockToken, policy, VALID_POLICY_FLAG_TEMP, result, minUserInfo));

    SetInfo maxUserInfo;
    maxUserInfo.userId = INT32_MAX;
    result.clear();
    EXPECT_NE(INVALID_PARAMTER,
        SandboxManagerKit::SetPolicy(g_mockToken, policy, VALID_POLICY_FLAG_TEMP, result, maxUserInfo));

    result.clear();
    EXPECT_NE(INVALID_PARAMTER,
        SandboxManagerKit::SetPolicy(g_mockToken, policy, VALID_POLICY_FLAG_TEMP, result, UINT64_MAX));
}

/**
 * @tc.name: SetPolicyByBundleNameBoundary001
 * @tc.desc: SetPolicyByBundleName with empty policy / invalid flag client boundaries.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, SetPolicyByBundleNameBoundary001, TestSize.Level0)
{
    std::vector<PolicyInfo> emptyPolicy;
    std::vector<PolicyInfo> policy = MakeSinglePolicy(VALID_PATH);
    std::vector<uint32_t> result;

    // empty policy rejected by client
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicyByBundleName("sandbox_manager_test", 0,
        emptyPolicy, VALID_POLICY_FLAG_PERSIST, result));

    // invalid policyFlag rejected by client
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicyByBundleName("sandbox_manager_test", 0,
        policy, INVALID_POLICY_FLAG, result));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicyByBundleName("sandbox_manager_test", 0,
        policy, UINT64_MAX, result));
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: SetPolicyByBundleNameBoundary002
 * @tc.desc: SetPolicyByBundleName with bundleName and appCloneIndex boundaries, service resolves token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, SetPolicyByBundleNameBoundary002, TestSize.Level0)
{
    std::vector<PolicyInfo> policy = MakeSinglePolicy(VALID_PATH);
    std::vector<uint32_t> result;

    // empty bundleName and extreme appCloneIndex pass the client and cannot be resolved
    // to an installed application token by the service
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicyByBundleName("", 0,
        policy, VALID_POLICY_FLAG_TEMP, result));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicyByBundleName("sandbox_manager_test", INT32_MAX,
        policy, VALID_POLICY_FLAG_TEMP, result));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicyByBundleName("sandbox_manager_test", INT32_MIN,
        policy, VALID_POLICY_FLAG_TEMP, result));
}

/**
 * @tc.name: UnSetPolicyBoundary001
 * @tc.desc: UnSetPolicy with tokenId 0 / path length boundaries 0 / 4095 / 4096.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, UnSetPolicyBoundary001, TestSize.Level0)
{
    PolicyInfo info = {.path = VALID_PATH, .mode = OperateMode::READ_MODE};

    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetPolicy(0, info));

    PolicyInfo emptyPathInfo = {.path = "", .mode = OperateMode::READ_MODE};
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetPolicy(g_mockToken, emptyPathInfo));

    PolicyInfo overLenInfo = {.path = MakeBoundaryPath(MAX_PATH_LENGTH + 1), .mode = OperateMode::READ_MODE};
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetPolicy(g_mockToken, overLenInfo));

    PolicyInfo maxLenInfo = {.path = MakeBoundaryPath(MAX_PATH_LENGTH), .mode = OperateMode::READ_MODE};
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::UnSetPolicy(g_mockToken, maxLenInfo));

    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::UnSetPolicy(g_mockToken, info));
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::UnSetPolicy(UINT32_MAX, info));
}

/**
 * @tc.name: SetDenyPolicyBoundary001
 * @tc.desc: SetDenyPolicy with empty policy vector boundary and single policy with mode 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, SetDenyPolicyBoundary001, TestSize.Level0)
{
    std::vector<PolicyInfo> emptyPolicy;
    std::vector<uint32_t> result;
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetDenyPolicy(g_mockToken, emptyPolicy, result));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetDenyPolicy(0, emptyPolicy, result));
    EXPECT_TRUE(result.empty());

    // mode boundary 0 carried in a single policy, forwarded beyond client boundary check
    std::vector<PolicyInfo> policy = MakeSinglePolicy(VALID_PATH, 0);
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::SetDenyPolicy(g_mockToken, policy, result));
}

/**
 * @tc.name: UnSetDenyPolicyBoundary001
 * @tc.desc: UnSetDenyPolicy with path length boundaries 0 / 4095 / 4096.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, UnSetDenyPolicyBoundary001, TestSize.Level0)
{
    PolicyInfo emptyPathInfo = {.path = "", .mode = OperateMode::DENY_READ_MODE};
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetDenyPolicy(g_mockToken, emptyPathInfo));

    PolicyInfo overLenInfo = {.path = MakeBoundaryPath(MAX_PATH_LENGTH + 1), .mode = OperateMode::DENY_READ_MODE};
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetDenyPolicy(g_mockToken, overLenInfo));

    PolicyInfo maxLenInfo = {.path = MakeBoundaryPath(MAX_PATH_LENGTH), .mode = OperateMode::DENY_READ_MODE};
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::UnSetDenyPolicy(g_mockToken, maxLenInfo));

    PolicyInfo info = {.path = VALID_PATH, .mode = OperateMode::DENY_READ_MODE};
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::UnSetDenyPolicy(g_mockToken, info));
}

/**
 * @tc.name: SetPolicyAsyncBoundary001
 * @tc.desc: SetPolicyAsync with empty policy / tokenId 0 / policyFlag boundaries, both overloads.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, SetPolicyAsyncBoundary001, TestSize.Level0)
{
    std::vector<PolicyInfo> emptyPolicy;
    std::vector<PolicyInfo> policy = MakeSinglePolicy(VALID_PATH);

    EXPECT_EQ(INVALID_PARAMTER,
        SandboxManagerKit::SetPolicyAsync(g_mockToken, emptyPolicy, VALID_POLICY_FLAG_PERSIST));
    EXPECT_EQ(INVALID_PARAMTER,
        SandboxManagerKit::SetPolicyAsync(g_mockToken, emptyPolicy, VALID_POLICY_FLAG_PERSIST, UINT64_MAX));

    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicyAsync(0, policy, VALID_POLICY_FLAG_PERSIST));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicyAsync(0, policy, VALID_POLICY_FLAG_PERSIST, 0));

    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicyAsync(g_mockToken, policy, INVALID_POLICY_FLAG));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicyAsync(g_mockToken, policy, UINT64_MAX));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicyAsync(g_mockToken, policy, UINT64_MAX, 0));

    // valid flag boundaries 0 / 1 and timestamp UINT64_MAX pass client check
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::SetPolicyAsync(g_mockToken, policy, VALID_POLICY_FLAG_TEMP));
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::SetPolicyAsync(g_mockToken, policy, VALID_POLICY_FLAG_PERSIST));
    EXPECT_NE(INVALID_PARAMTER,
        SandboxManagerKit::SetPolicyAsync(g_mockToken, policy, VALID_POLICY_FLAG_PERSIST, UINT64_MAX));
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::SetPolicyAsync(UINT32_MAX, policy, VALID_POLICY_FLAG_TEMP));
}

/**
 * @tc.name: UnSetPolicyAsyncBoundary001
 * @tc.desc: UnSetPolicyAsync with tokenId boundary 0 and valid tokenId boundary.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, UnSetPolicyAsyncBoundary001, TestSize.Level0)
{
    PolicyInfo info = {.path = VALID_PATH, .mode = OperateMode::READ_MODE};
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetPolicyAsync(0, info));
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::UnSetPolicyAsync(g_mockToken, info));
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::UnSetPolicyAsync(UINT32_MAX, info));
}

/**
 * @tc.name: CheckPolicyBoundary001
 * @tc.desc: CheckPolicy with empty policy / tokenId 0 / path length 4095 boundaries.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, CheckPolicyBoundary001, TestSize.Level0)
{
    std::vector<PolicyInfo> emptyPolicy;
    std::vector<PolicyInfo> policy = MakeSinglePolicy(VALID_PATH);
    std::vector<bool> result;

    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::CheckPolicy(g_mockToken, emptyPolicy, result));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::CheckPolicy(0, policy, result));
    EXPECT_TRUE(result.empty());

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());

    // path length boundary MAX_PATH_LENGTH accepted by client and service
    result.clear();
    std::vector<PolicyInfo> maxLenPolicy = MakeSinglePolicy(MakeBoundaryPath(MAX_PATH_LENGTH));
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, maxLenPolicy, result));
    EXPECT_EQ(1, result.size());
}

/**
 * @tc.name: StartAccessingPolicyBoundary001
 * @tc.desc: StartAccessingPolicy with empty vector boundary and not-persisted policy, both overloads.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, StartAccessingPolicyBoundary001, TestSize.Level0)
{
    std::vector<PolicyInfo> emptyPolicy;
    std::vector<uint32_t> result;
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::StartAccessingPolicy(emptyPolicy, result));
    EXPECT_EQ(INVALID_PARAMTER,
        SandboxManagerKit::StartAccessingPolicy(emptyPolicy, result, true, g_mockToken, 0));
    EXPECT_TRUE(result.empty());

    std::vector<PolicyInfo> policy = MakeSinglePolicy(NOT_PERSISTED_PATH, OperateMode::WRITE_MODE);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, result[0]);

    // useCallerToken=false with tokenId and timestamp UINT64_MAX boundaries
    result.clear();
    EXPECT_NE(INVALID_PARAMTER,
        SandboxManagerKit::StartAccessingPolicy(policy, result, false, g_mockToken, UINT64_MAX));
}

/**
 * @tc.name: StopAccessingPolicyBoundary001
 * @tc.desc: StopAccessingPolicy with empty vector boundary and not-persisted policy.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, StopAccessingPolicyBoundary001, TestSize.Level0)
{
    std::vector<PolicyInfo> emptyPolicy;
    std::vector<uint32_t> result;
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::StopAccessingPolicy(emptyPolicy, result));
    EXPECT_TRUE(result.empty());

    std::vector<PolicyInfo> policy = MakeSinglePolicy(NOT_PERSISTED_PATH, OperateMode::WRITE_MODE);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, result[0]);
}

/**
 * @tc.name: CheckPersistPolicyBoundary001
 * @tc.desc: CheckPersistPolicy with empty policy / tokenId 0 / not-persisted policy boundaries.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, CheckPersistPolicyBoundary001, TestSize.Level0)
{
    std::vector<PolicyInfo> emptyPolicy;
    std::vector<PolicyInfo> policy = MakeSinglePolicy(NOT_PERSISTED_PATH);
    std::vector<bool> result;

    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::CheckPersistPolicy(g_mockToken, emptyPolicy, result));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::CheckPersistPolicy(0, policy, result));
    EXPECT_TRUE(result.empty());

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);
}

/**
 * @tc.name: StartAccessingByTokenIdBoundary001
 * @tc.desc: StartAccessingByTokenId with tokenId boundaries 0 / valid / UINT32_MAX, both overloads.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, StartAccessingByTokenIdBoundary001, TestSize.Level0)
{
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::StartAccessingByTokenId(0));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::StartAccessingByTokenId(0, UINT64_MAX));

    // allocated mock token passes tokenId validation
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::StartAccessingByTokenId(g_mockToken));
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::StartAccessingByTokenId(g_mockToken, UINT64_MAX));
}

/**
 * @tc.name: UnSetAllPolicyByTokenBoundary001
 * @tc.desc: UnSetAllPolicyByToken with tokenId boundaries 0 / valid / UINT32_MAX, both overloads.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, UnSetAllPolicyByTokenBoundary001, TestSize.Level0)
{
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetAllPolicyByToken(0));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetAllPolicyByToken(0, UINT64_MAX));
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::UnSetAllPolicyByToken(g_mockToken));
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::UnSetAllPolicyByToken(UINT32_MAX, UINT64_MAX));
}

/**
 * @tc.name: UnSetAllPolicyByTokenAsyncBoundary001
 * @tc.desc: UnSetAllPolicyByTokenAsync with tokenId boundaries 0 / valid / UINT32_MAX, both overloads.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, UnSetAllPolicyByTokenAsyncBoundary001, TestSize.Level0)
{
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetAllPolicyByTokenAsync(0));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetAllPolicyByTokenAsync(0, UINT64_MAX));
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::UnSetAllPolicyByTokenAsync(g_mockToken));
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::UnSetAllPolicyByTokenAsync(UINT32_MAX, UINT64_MAX));
}

/**
 * @tc.name: CleanPolicyByUserIdBoundary001
 * @tc.desc: CleanPolicyByUserId with empty list / userId boundaries / over-limit path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, CleanPolicyByUserIdBoundary001, TestSize.Level0)
{
    std::vector<std::string> emptyList;
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::CleanPolicyByUserId(0, emptyList));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::CleanPolicyByUserId(100, emptyList));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::CleanPolicyByUserId(UINT32_MAX, emptyList));

    // non-empty list passes client boundary check, userId is not client-checked
    std::vector<std::string> filePathList;
    filePathList.emplace_back(VALID_PATH);
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::CleanPolicyByUserId(UINT32_MAX, filePathList));

    filePathList.clear();
    filePathList.emplace_back(MakeBoundaryPath(MAX_PATH_LENGTH));
    filePathList.emplace_back(MakeBoundaryPath(MAX_PATH_LENGTH + 1));
    filePathList.emplace_back("");
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::CleanPolicyByUserId(100, filePathList));
}

/**
 * @tc.name: DeactivePolicyByPathBoundary001
 * @tc.desc: DeactivePolicyByPath with path length boundaries 0 / 4095 / 4096.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, DeactivePolicyByPathBoundary001, TestSize.Level0)
{
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::DeactivePolicyByPath(""));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::DeactivePolicyByPath(MakeBoundaryPath(MAX_PATH_LENGTH + 1)));
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::DeactivePolicyByPath(MakeBoundaryPath(MAX_PATH_LENGTH)));
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::DeactivePolicyByPath("/data/temp"));
}

/**
 * @tc.name: ActivePolicyByPathBoundary001
 * @tc.desc: ActivePolicyByPath with path length boundaries 0 / 4095 / 4096.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, ActivePolicyByPathBoundary001, TestSize.Level0)
{
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::ActivePolicyByPath(""));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::ActivePolicyByPath(MakeBoundaryPath(MAX_PATH_LENGTH + 1)));
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::ActivePolicyByPath(MakeBoundaryPath(MAX_PATH_LENGTH)));
    EXPECT_NE(INVALID_PARAMTER, SandboxManagerKit::ActivePolicyByPath("/data/temp"));
}

/**
 * @tc.name: UgcPermissionBoundary001
 * @tc.desc: GrantPermissionByUser/RevokePermissionByUser with tokenId 0 / empty and invalid-mode policy.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, UgcPermissionBoundary001, TestSize.Level0)
{
    std::vector<PolicyInfo> emptyPolicy;
    // mode 0 is filtered by the service, no persisted side effect
    std::vector<PolicyInfo> invalidModePolicy = MakeSinglePolicy(VALID_PATH, 0);

    // no client-side validation, boundary inputs must be handled without crash
    int32_t ret = SandboxManagerKit::GrantPermissionByUser(0, emptyPolicy);
    EXPECT_GE(ret, SANDBOX_MANAGER_OK);
    EXPECT_LE(ret, SANDBOX_MANAGER_NOT_SYS_APP);
    ret = SandboxManagerKit::GrantPermissionByUser(UINT32_MAX, invalidModePolicy);
    EXPECT_GE(ret, SANDBOX_MANAGER_OK);
    EXPECT_LE(ret, SANDBOX_MANAGER_NOT_SYS_APP);

    ret = SandboxManagerKit::RevokePermissionByUser(0, emptyPolicy);
    EXPECT_GE(ret, SANDBOX_MANAGER_OK);
    EXPECT_LE(ret, SANDBOX_MANAGER_NOT_SYS_APP);
    ret = SandboxManagerKit::RevokePermissionByUser(UINT32_MAX, invalidModePolicy);
    EXPECT_GE(ret, SANDBOX_MANAGER_OK);
    EXPECT_LE(ret, SANDBOX_MANAGER_NOT_SYS_APP);
}

/**
 * @tc.name: GetStatusByPermissionBoundary001
 * @tc.desc: GetStatusByPermission with empty tokenIdList / tokenId 0 / UINT32_MAX boundaries.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitBoundaryTest, GetStatusByPermissionBoundary001, TestSize.Level0)
{
    std::vector<PermissionStatusInfo> result;
    result.push_back({});

    std::vector<uint32_t> emptyList;
    int32_t ret = SandboxManagerKit::GetStatusByPermission(emptyList, result);
    EXPECT_GE(ret, SANDBOX_MANAGER_OK);
    EXPECT_LE(ret, SANDBOX_MANAGER_NOT_SYS_APP);
    EXPECT_TRUE(result.empty());

    std::vector<uint32_t> tokenIdList = {0, UINT32_MAX};
    ret = SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
    EXPECT_GE(ret, SANDBOX_MANAGER_OK);
    EXPECT_LE(ret, SANDBOX_MANAGER_NOT_SYS_APP);
    EXPECT_TRUE(result.empty());
}
} //SandboxManager
} //AccessControl
} // OHOS
