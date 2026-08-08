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

#include "sandbox_manager_kit_async_test.h"

#include <chrono>
#include <cstdint>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "permission_def.h"
#include "permission_state_full.h"
#include "policy_info.h"
#include "securec.h"
#include "sandbox_manager_err_code.h"
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

const int32_t FOUNDATION_UID = 5523;
const size_t MAX_POLICY_NUM = 8;
const int DEC_POLICY_HEADER_RESERVED = 64;

uint32_t g_selfTokenId;
uint32_t g_mockToken;
int32_t g_uid;

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
    .bundleName = "sandbox_manager_async_test",
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
} // namespace

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
    auto ret = ioctl(fd, DENY_DEC_POLICY_CMD, &policyInfo);
    std::cout << "set deny ret: " << ret << std::endl;
    close(fd);
    return ret;
}

static bool AllPoliciesRemoved(const std::vector<bool>& result, size_t expected)
{
    if (result.size() != expected) {
        return false;
    }
    for (bool r : result) {
        if (r) {
            return false;
        }
    }
    return true;
}

static bool WaitForPolicyRemoved(uint32_t tokenId, const std::vector<PolicyInfo>& policies)
{
    const int totalWaitMs = 5000;
    const int intervalMs = 200;
    for (int elapsed = 0; elapsed < totalWaitMs; elapsed += intervalMs) {
        std::vector<bool> result;
        int32_t ret = SandboxManagerKit::CheckPolicy(tokenId, policies, result);
        if (ret == SANDBOX_MANAGER_OK && AllPoliciesRemoved(result, policies.size())) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
    }
    return false;
}

void SandboxManagerKitAsyncTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    SetDeny("/A");
    SetDeny("/C/D");
    SetDeny("/data/temp");
}

void SandboxManagerKitAsyncTest::TearDownTestCase()
{
    Security::AccessToken::AccessTokenKit::DeleteToken(g_mockToken);
}

void SandboxManagerKitAsyncTest::SetUp()
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

void SandboxManagerKitAsyncTest::TearDown()
{
    setuid(g_uid);
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
}

/**
 * @tc.name: UnSetAllPolicyByTokenAsyncTest001
 * @tc.desc: destroy all mac policy in kernel with given tokenid async
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitAsyncTest, UnSetAllPolicyByTokenAsyncTest001, TestSize.Level0)
{
    std::vector<PolicyInfo> policyA;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParentA = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policyA.emplace_back(infoParentA);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyA, policyFlag, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyA, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetAllPolicyByTokenAsync(g_mockToken));
    ASSERT_TRUE(WaitForPolicyRemoved(g_mockToken, policyA));

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyA, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);
}

/**
 * @tc.name: UnSetAllPolicyByTokenAsyncTest002
 * @tc.desc: destroy all mac policy in kernel with given tokenid async, multiple policies
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitAsyncTest, UnSetAllPolicyByTokenAsyncTest002, TestSize.Level0)
{
    std::vector<PolicyInfo> policys;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> setResult;
    PolicyInfo infoDirA = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoDirB = {
        .path = "/A/C",
        .mode = OperateMode::WRITE_MODE
    };
    policys.emplace_back(std::move(infoDirA));
    policys.emplace_back(std::move(infoDirB));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policys, policyFlag, setResult));
    ASSERT_EQ(2, setResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[1]);

    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policys, checkResult));
    ASSERT_EQ(2, checkResult.size());
    EXPECT_TRUE(checkResult[0]);
    EXPECT_TRUE(checkResult[1]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetAllPolicyByTokenAsync(g_mockToken));
    ASSERT_TRUE(WaitForPolicyRemoved(g_mockToken, policys));

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policys, checkResult));
    ASSERT_EQ(2, checkResult.size());
    EXPECT_FALSE(checkResult[0]);
    EXPECT_FALSE(checkResult[1]);
}

/**
 * @tc.name: UnSetAllPolicyByTokenAsyncTest003
 * @tc.desc: UnSetAllPolicyByTokenAsync with invalid tokenId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitAsyncTest, UnSetAllPolicyByTokenAsyncTest003, TestSize.Level0)
{
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetAllPolicyByTokenAsync(0));
}

/**
 * @tc.name: UnSetAllPolicyByTokenAsyncTest004
 * @tc.desc: destroy all mac policy in kernel with given tokenid and timestamp async
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitAsyncTest, UnSetAllPolicyByTokenAsyncTest004, TestSize.Level0)
{
    std::vector<PolicyInfo> policyA;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParentA = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policyA.emplace_back(infoParentA);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyA, policyFlag, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyA, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetAllPolicyByTokenAsync(g_mockToken, uint64_t(1)));
    ASSERT_TRUE(WaitForPolicyRemoved(g_mockToken, policyA));

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyA, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);
}

/**
 * @tc.name: UnSetAllPolicyByTokenAsyncTest005
 * @tc.desc: UnSetAllPolicyByTokenAsync only affects the specified tokenId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitAsyncTest, UnSetAllPolicyByTokenAsyncTest005, TestSize.Level0)
{
    uint64_t policyFlag = 1;
    uint32_t tokenA = g_mockToken;
    uint32_t tokenB = g_mockToken + 1;

    std::vector<PolicyInfo> policyA;
    policyA.emplace_back(PolicyInfo{.path = "/A/B", .mode = OperateMode::READ_MODE});
    std::vector<uint32_t> setResultA;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(tokenA, policyA, policyFlag, setResultA));
    ASSERT_EQ(1, setResultA.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResultA[0]);

    std::vector<PolicyInfo> policyB;
    policyB.emplace_back(PolicyInfo{.path = "/X/Y", .mode = OperateMode::WRITE_MODE});
    std::vector<uint32_t> setResultB;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(tokenB, policyB, policyFlag, setResultB));
    ASSERT_EQ(1, setResultB.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResultB[0]);

    std::vector<bool> checkResultA;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(tokenA, policyA, checkResultA));
    ASSERT_EQ(1, checkResultA.size());
    EXPECT_TRUE(checkResultA[0]);

    std::vector<bool> checkResultB;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(tokenB, policyB, checkResultB));
    ASSERT_EQ(1, checkResultB.size());
    EXPECT_TRUE(checkResultB[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetAllPolicyByTokenAsync(tokenA));
    ASSERT_TRUE(WaitForPolicyRemoved(tokenA, policyA));

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(tokenA, policyA, checkResultA));
    ASSERT_EQ(1, checkResultA.size());
    EXPECT_FALSE(checkResultA[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(tokenB, policyB, checkResultB));
    ASSERT_EQ(1, checkResultB.size());
    EXPECT_TRUE(checkResultB[0]);
}

/**
 * @tc.name: UnSetAllPolicyByTokenAsyncTest006
 * @tc.desc: multi-thread concurrent UnSetAllPolicyByTokenAsync, verify all policies removed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitAsyncTest, UnSetAllPolicyByTokenAsyncTest006, TestSize.Level0)
{
    const int pathCount = 5;
    const int threadCount = 5;
    uint64_t policyFlag = 1;
    std::vector<std::string> paths = {"/A/B", "/A/C", "/A/D", "/A/E", "/A/F"};

    for (int i = 0; i < pathCount; i++) {
        std::vector<PolicyInfo> policy;
        policy.emplace_back(PolicyInfo{.path = paths[i], .mode = OperateMode::READ_MODE});
        std::vector<uint32_t> setResult;
        ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, setResult));
        ASSERT_EQ(1, setResult.size());
        EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[0]);
    }

    std::vector<PolicyInfo> allPolicies;
    for (int i = 0; i < pathCount; i++) {
        allPolicies.emplace_back(PolicyInfo{.path = paths[i], .mode = OperateMode::READ_MODE});
    }
    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, allPolicies, checkResult));
    ASSERT_EQ(pathCount, checkResult.size());
    for (int i = 0; i < pathCount; i++) {
        EXPECT_TRUE(checkResult[i]);
    }

    std::vector<std::thread> threads;
    for (int i = 0; i < threadCount; i++) {
        threads.emplace_back([&]() {
            SandboxManagerKit::UnSetAllPolicyByTokenAsync(g_mockToken);
        });
    }
    for (auto& t : threads) {
        t.join();
    }
    ASSERT_TRUE(WaitForPolicyRemoved(g_mockToken, allPolicies));

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, allPolicies, checkResult));
    ASSERT_EQ(pathCount, checkResult.size());
    for (int i = 0; i < pathCount; i++) {
        EXPECT_FALSE(checkResult[i]);
    }
}
} // SandboxManager
} // AccessControl
} // OHOS
