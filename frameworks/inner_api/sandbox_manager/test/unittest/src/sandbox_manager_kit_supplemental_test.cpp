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

#include "sandbox_manager_kit_supplemental_test.h"
#include "sandbox_test_utils.h"

#include <cstdint>
#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "permission_def.h"
#include "permission_state_full.h"
#include "policy_info.h"
#include "securec.h"
#include "sandbox_manager_client.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"
#include "sandbox_manager_kit.h"
#include "sandbox_test_common.h"
#include "token_setproc.h"
#include "os_account_manager.h"

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
const uint32_t INVALID_OPERATE_MODE = 0;
#ifdef PERFORMANCE_TEST
const double SET_POLICY_MAX_TIME_SEC = 15.0;
const double CHECK_PERSIST_MAX_TIME_SEC = 200.0 / 1000.0;
#endif
#define TEST_TIMESTAMP 5
const int32_t FOUNDATION_UID = 5523;
const size_t MAX_POLICY_NUM = 8;
const int DEC_POLICY_HEADER_RESERVED = 64;
uint32_t g_selfTokenId;
uint32_t g_mockToken;
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
    .permStateList = {g_testState1, g_testState2, g_testState3, g_testState4}
};
};

static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerKitTest"
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

#ifdef DEC_SUPPORT_DENY_DELETE_RENAME
static bool WaitForTokenNum(uint32_t tokenId, int32_t expectNum, int32_t expectDenyNum)
{
    constexpr int32_t maxWaitTimeMs = 5000;
    constexpr int32_t pollIntervalMs = 200;
    constexpr int32_t msToUs = 1000;
    int32_t elapsedMs = 0;
    int32_t num = 0;
    int32_t denyNum = 0;
    while (elapsedMs < maxWaitTimeMs) {
        if (GetTokenNum(tokenId, num, denyNum) == 0 && num == expectNum && denyNum == expectDenyNum) {
            return true;
        }
        usleep(pollIntervalMs * msToUs);
        elapsedMs += pollIntervalMs;
    }
    return false;
}

static std::vector<PolicyInfo> MakePolicies(int32_t count, const std::string &pathA, const std::string &pathB,
    OperateMode mode)
{
    std::vector<PolicyInfo> policies;
    for (int32_t i = 0; i < count; ++i) {
        std::string path = (i % 2 == 0) ? pathA + std::to_string(i) : pathB + std::to_string(i);
        policies.push_back({.path = path, .mode = mode});
    }
    return policies;
}
#endif

void SandboxManagerKitSupplementalTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    fileManagerPresent_ = (GetTokenIdFromProcess("file_manager_service") != 0);
    SetDeny("/A");
    SetDeny("/C/D");
    SetDeny("/data/temp");
}

void SandboxManagerKitSupplementalTest::TearDownTestCase()
{
    Security::AccessToken::AccessTokenKit::DeleteToken(g_mockToken);
}

static int32_t g_uid;
bool SandboxManagerKitSupplementalTest::fileManagerPresent_ = false;
void SandboxManagerKitSupplementalTest::SetUp()
{
    EXPECT_TRUE(MockTokenId("foundation"));
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
    EXPECT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    g_mockToken = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
    g_uid = getuid();
    setuid(FOUNDATION_UID);
}

void SandboxManagerKitSupplementalTest::TearDown()
{
    setuid(g_uid);
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
}

/**
 * @tc.name: StartAccessingPolicy001
 * @tc.desc: Test INVALID_PATH/INVALID_MODE.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, StartAccessingPolicy001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policySub;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent1 = {
        .path = "", // invalid path
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo infoParent2 = {
        .path = "/A/B",
        .mode = INVALID_OPERATE_MODE  // invalid mode
    };
    PolicyInfo infoSub = {
        .path = "/A/B/C",
        .mode = OperateMode::WRITE_MODE
    };
    policySub.emplace_back(infoSub);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub);
    policy.emplace_back(infoParent1);
    policy.emplace_back(infoParent2);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(INVALID_PATH, startResult[1]);
    EXPECT_EQ(INVALID_MODE, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(INVALID_PATH, unPersistResult[1]);
    EXPECT_EQ(INVALID_MODE, unPersistResult[2]);
}

const int32_t SPACE_MGR_SERVICE_UID = 7013;
#ifdef DEC_SUPPORT_DENY_RW
/**
 * @tc.name: PhysicalPathDenyTest001
 * @tc.desc: test deny physical path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, PhysicalPathDenyTest001, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> policyResult;
    PolicyInfo info1 = {
        .path = "/data/service/el1/100/",
        .mode = OperateMode::DENY_READ_MODE
    };
    const uint32_t tokenId = g_mockToken;
    policy.emplace_back(info1);

    int32_t uid = getuid();
    setuid(SPACE_MGR_SERVICE_UID);

    const char *DISTRIBUTE_PATH = "/data/service/el1/100/distributeddata";
    DIR *dir = opendir(DISTRIBUTE_PATH);
    ASSERT_NE(dir, nullptr);
    closedir(dir);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetDenyPolicy(tokenId, policy, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    dir = opendir(DISTRIBUTE_PATH);
    ASSERT_EQ(dir, nullptr);

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetDenyPolicy(tokenId, info1));
    dir = opendir(DISTRIBUTE_PATH);
    ASSERT_NE(dir, nullptr);
    closedir(dir);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetDenyPolicy(tokenId, policy, policyResult));
    dir = opendir(DISTRIBUTE_PATH);
    ASSERT_EQ(dir, nullptr);
    setuid(uid);
}

static void UnSetDenyPolicyBatch(uint32_t tokenId, const std::vector<PolicyInfo> &policies)
{
    for (const auto &policy : policies) {
        EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetDenyPolicy(tokenId, policy));
    }
}

/**
 * @tc.name: UnSetDenyPolicyBatchPartialUnset001
 * @tc.desc: test UnSetDenyPolicy batch — partial unset, remaining deny still active
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, UnSetDenyPolicyBatchPartialUnset001, TestSize.Level1)
{
    struct TestEntry { PolicyInfo policy; const char *testPath; };
    TestEntry entries[] = {
        { { .path = "/data/service/el1/100/", .mode = OperateMode::DENY_READ_MODE },
            "/data/service/el1/100/distributeddata" },
        { { .path = "/data/service/el1/public/", .mode = OperateMode::DENY_READ_MODE },
            "/data/service/el1/public/sandbox_manager" },
        { { .path = "/data/service/el1/0/", .mode = OperateMode::DENY_READ_MODE },
            "/data/service/el1/0/distributeddata" },
    };
    constexpr size_t ENTRY_COUNT = sizeof(entries) / sizeof(entries[0]);
    const uint32_t tokenId = g_mockToken;
    auto verifyAccess = [](const char *path, bool expectBlocked) {
        DIR *dir = opendir(path);
        if (expectBlocked) { ASSERT_EQ(dir, nullptr); } else { ASSERT_NE(dir, nullptr); closedir(dir); }
    };
    for (size_t i = 0; i < ENTRY_COUNT; ++i) {
        verifyAccess(entries[i].testPath, false);
    }
    int32_t uid = getuid();
    setuid(SPACE_MGR_SERVICE_UID);
    std::vector<PolicyInfo> allPolicies;
    std::vector<uint32_t> policyResult;
    for (size_t i = 0; i < ENTRY_COUNT; ++i) {
        allPolicies.emplace_back(entries[i].policy);
    }
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetDenyPolicy(tokenId, allPolicies, policyResult));
    ASSERT_EQ(ENTRY_COUNT, policyResult.size());
    for (size_t i = 0; i < ENTRY_COUNT; ++i) {
        EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[i]);
    }
    for (size_t i = 0; i < ENTRY_COUNT; ++i) {
        verifyAccess(entries[i].testPath, true);
    }
    std::vector<PolicyInfo> partialUnset = {entries[0].policy, entries[1].policy};
    UnSetDenyPolicyBatch(tokenId, partialUnset);
    verifyAccess(entries[0].testPath, false);
    verifyAccess(entries[1].testPath, false);
    verifyAccess(entries[2].testPath, true);
    std::vector<PolicyInfo> lastUnset = {entries[2].policy};
    UnSetDenyPolicyBatch(tokenId, lastUnset);
    verifyAccess(entries[2].testPath, false);
    setuid(uid);
}
#endif

/**
 * @tc.name: PhysicalPathDenyTest002
 * @tc.desc: test deny physical path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, PhysicalPathDenyTest002, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> policyResult;
    PolicyInfo info1 = {
        .path = "/data/service/el1/100/",
        .mode = OperateMode::DENY_READ_MODE
    };
    const uint32_t tokenId = g_mockToken;
    policy.emplace_back(info1);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(tokenId, policy, 1, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(INVALID_MODE, policyResult[0]);

    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetPolicy(tokenId, info1));
}

/**
 * @tc.name: PhysicalPathDenyTest003
 * @tc.desc: test deny physical path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, PhysicalPathDenyTest003, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> policyResult;
    PolicyInfo info1 = {
        .path = "/data/service/el1/100/",
        .mode = OperateMode::READ_MODE
    };
    const uint32_t tokenId = g_mockToken;
    policy.emplace_back(info1);

    int32_t uid = getuid();
    setuid(SPACE_MGR_SERVICE_UID);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetDenyPolicy(tokenId, policy, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(INVALID_MODE, policyResult[0]);

    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetDenyPolicy(tokenId, info1));
    setuid(uid);
}

/**
 * @tc.name: PhysicalPathDenyTest004
 * @tc.desc: test deny physical path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, PhysicalPathDenyTest004, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> policyResult;
    PolicyInfo info1 = {
        .path = "/data/service/el1/100/",
        .mode = OperateMode::DENY_READ_MODE
    };
    const uint32_t tokenId = g_mockToken;
    policy.emplace_back(info1);

    ASSERT_EQ(PERMISSION_DENIED, SandboxManagerKit::SetDenyPolicy(tokenId, policy, policyResult));
    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::UnSetDenyPolicy(tokenId, info1));
}

#ifdef DEC_SUPPORT_DENY_RW
/**
 * @tc.name: PhysicalPathDenyTest005
 * @tc.desc: test deny physical path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, PhysicalPathDenyTest005, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> policyResult;
    PolicyInfo info1 = {
        .path = "/data/service/el1/100/",
        .mode = OperateMode::DENY_READ_MODE
    };
    const uint32_t tokenId = g_mockToken;
    policy.emplace_back(info1);

    setuid(g_uid);
    int32_t uid = getuid();
    setuid(SPACE_MGR_SERVICE_UID);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetDenyPolicy(tokenId, policy, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    setuid(FOUNDATION_UID);
    std::vector<uint32_t> retType;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(tokenId, policy, retType));
    EXPECT_EQ(INVALID_MODE, retType[0]);

    setuid(SPACE_MGR_SERVICE_UID);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetDenyPolicy(tokenId, info1));
    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(INVALID_MODE, unPersistResult[0]);

    setuid(uid);
}
#endif


/**
 * @tc.name: SetPolicy001
 * @tc.desc: Test setting READ_MODE and WRITE_MODE separately.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, SetPolicy001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policyCheck;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParent1 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoParent2 = {
        .path = "/A/B",
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo infoParent3 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policy.emplace_back(infoParent1);
    policy.emplace_back(infoParent2);
    policyCheck.emplace_back(infoParent3);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, policyResult));
    ASSERT_EQ(2, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[1]);

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyCheck, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);
}

/**
 * @tc.name: SetPolicy002
 * @tc.desc: Test setting READ_MODE and READ_MODE | WRITE_MODE separately.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, SetPolicy002, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policyCheck;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParent1 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoParent2 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    PolicyInfo infoParent3 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policy.emplace_back(infoParent1);
    policy.emplace_back(infoParent2);
    policyCheck.emplace_back(infoParent3);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, policyResult));
    ASSERT_EQ(2, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[1]);

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyCheck, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);
}

/**
 * @tc.name: SetPolicy003
 * @tc.desc: Test setting WRITE_MODE and READ_MODE | WRITE_MODE separately.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, SetPolicy003, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policyCheck;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParent1 = {
        .path = "/A/B",
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo infoParent2 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    PolicyInfo infoParent3 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policy.emplace_back(infoParent1);
    policy.emplace_back(infoParent2);
    policyCheck.emplace_back(infoParent3);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, policyResult));
    ASSERT_EQ(2, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[1]);

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyCheck, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);
}

/**
 * @tc.name: PersistPolicyCoverage001
 * @tc.desc: CheckPersistPolicyInput with invalid input.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, PersistPolicyCoverage001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    PolicyInfo info1 = {
        .path = "/a/b",
        .mode = 0,
    };

    PolicyInfo info2 = {
        .path = "",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE,
    };
    policy.emplace_back(info1);
    policy.emplace_back(info2);
    std::vector<uint32_t> result;

    std::vector<bool> checkResult1;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policy, checkResult1));
    ASSERT_EQ(2, checkResult1.size());
    EXPECT_FALSE(checkResult1[0]);
    EXPECT_FALSE(checkResult1[1]);
}

/**
 * @tc.name: PersistPolicyCoverage002
 * @tc.desc: PersistPolicy with diffrent mode.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, PersistPolicyCoverage002, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policy.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<PolicyInfo> policyChildren;
    PolicyInfo infoChildren = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policyChildren.emplace_back(infoChildren);

    std::vector<uint32_t> retType;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(g_mockToken, policyChildren, retType));
    ASSERT_EQ(1, retType.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policyChildren, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);
}

/**
 * @tc.name: PersistPolicyCoverage003
 * @tc.desc: PersistPolicy with diffrent mode.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, PersistPolicyCoverage003, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policy.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<PolicyInfo> policyChildren;
    PolicyInfo infoChildren = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE
    };
    policyChildren.emplace_back(infoChildren);

    std::vector<uint32_t> retType;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(g_mockToken, policyChildren, retType));
    ASSERT_EQ(1, retType.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policyChildren, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);\
}

/**
 * @tc.name: PersistPolicyCoverage004
 * @tc.desc: PersistPolicy with diffrent mode.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, PersistPolicyCoverage004, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    policy.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<PolicyInfo> policyChildren;
    PolicyInfo infoChildren = {
        .path = "/A/B/C",
        .mode = OperateMode::WRITE_MODE
    };
    policyChildren.emplace_back(infoChildren);

    std::vector<uint32_t> retType;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(g_mockToken, policyChildren, retType));
    ASSERT_EQ(1, retType.size());
    EXPECT_EQ(FORBIDDEN_TO_BE_PERSISTED, retType[0]);

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policyChildren, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);
}

/**
 * @tc.name: UnPersistPolicyCoverage001
 * @tc.desc: UnPersistPolicy Input with invalid input.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, UnPersistPolicyCoverage001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = 0
    };
    policy.emplace_back(infoParent);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(INVALID_MODE, unPersistResult[0]);
}

/**
 * @tc.name: CleanPolicyByUserId
 * @tc.desc: UnPersistPolicy Input with invalid input.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, CleanPolicyByUserIdCoverage001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    int32_t userId = 0;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "CleanPolicyByUserIdTest, get user id failed error=%{public}d", ret);
        userId = 0; // set default userId
    }
    std::vector<std::string> filePaths;
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::CleanPolicyByUserId(userId, filePaths));

    filePaths.emplace_back(infoParent.path);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPolicyByUserId(-1, filePaths));
}

#ifdef PERFORMANCE_TEST
/**
 * @tc.name: MassiveIPCTest001
 * @tc.desc: SetPolicy test time.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, MassiveIPCTest001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    uint64_t policySize = 200000;
    uint64_t policyFlag = 1;

    for (uint64_t i = 0; i < policySize; i++) {
        PolicyInfo info;
        info.mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
        char path[1024];
        sprintf_s(path, sizeof(path), "/data/temp/a/b/c/d/e/f/g/h/i/j/persist/%d", i);
        info.path.assign(path);
        policy.emplace_back(info);
    }

    std::vector<uint32_t> ret;
    auto start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, ret));
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    std::cout << "SetPolicy cost " << duration.count() << "s" << std::endl;
    EXPECT_LT(duration.count(), SET_POLICY_MAX_TIME_SEC)
        << "SetPolicy takes more than 15 seconds!";
    ASSERT_EQ(policySize, ret.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_EQ(OPERATE_SUCCESSFULLY, ret[i]);
    }
}

/**
 * @tc.name: MassiveIPCTest002
 * @tc.desc: CheckPersistPolicy test time.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, MassiveIPCTest002, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    uint64_t policySize = 10000;
    uint64_t policyFlag = 1;

    for (uint64_t i = 0; i < policySize; i++) {
        PolicyInfo info;
        info.mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
        char path[1024];
        sprintf_s(path, sizeof(path), "/data/temp/a/b/c/d/e/f/g/h/i/j/persist/%d", i);
        info.path.assign(path);
        policy.emplace_back(info);
    }

    std::vector<uint32_t> ret;
    auto start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, ret));
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    std::cout << "SetPolicy cost " << duration.count() << "s" << std::endl;
    ASSERT_EQ(policySize, ret.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_EQ(OPERATE_SUCCESSFULLY, ret[i]);
    }

    std::vector<uint32_t> policyResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, policyResult));
    ASSERT_EQ(policySize, policyResult.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[i]);
    }

    std::vector<PolicyInfo> policySubset;
    uint64_t querySize = 500;
    policySubset = std::vector<PolicyInfo>(policy.begin(), policy.begin() + querySize);
    std::vector<bool> checkResult1;
    start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policySubset, checkResult1));
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "CheckPersistPolicy cost " << duration.count() << "s" << std::endl;
    EXPECT_LT(duration.count(), CHECK_PERSIST_MAX_TIME_SEC)
        << "CheckPersistPolicy takes more than 200ms!";
    ASSERT_EQ(querySize, checkResult1.size());
    for (uint64_t i = 0; i < querySize; i++) {
        EXPECT_TRUE(checkResult1[i]);
    }

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    ASSERT_EQ(policySize, unPersistResult.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[i]);
    }
}
#endif
/**
 * @tc.name: StartAccessingPolicyCoverage001
 * @tc.desc: StartAccessingPolicy with invalid input.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, StartAccessingPolicyCoverage001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo info1 = {
        .path = "/a/b",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    policy.emplace_back(info1);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, policyResult));
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<uint32_t> retType;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(g_mockToken, policy, retType));
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);

    std::vector<PolicyInfo> policyError;
    PolicyInfo info2 = {
        .path = "",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    PolicyInfo info3 = {
        .path = "/a/b",
        .mode = 0
    };

    policyError.emplace_back(info2);
    policyError.emplace_back(info3);

    std::vector<uint32_t> retType1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policyError, retType1));
    EXPECT_EQ(INVALID_PATH, retType1[0]);
    EXPECT_EQ(INVALID_MODE, retType1[1]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetAllPolicyByToken(g_mockToken));
}

/**
 * @tc.name: StartAccessingPolicyCoverage002
 * @tc.desc: StartAccessingPolicy with time.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, StartAccessingPolicyCoverage002, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo info1 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    policy.emplace_back(info1);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, policyResult));
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<uint32_t> retType;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(g_mockToken, policy, retType));
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);

    std::vector<uint32_t> retType1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, retType1, true, 0, TEST_TIMESTAMP));
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType1[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetAllPolicyByToken(g_mockToken, TEST_TIMESTAMP - 1));
    sleep(1);

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetAllPolicyByToken(g_mockToken, TEST_TIMESTAMP + 1));
    sleep(1);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);
}

/**
 * @tc.name: StopAccessingPolicyCoverage001
 * @tc.desc: StopAccessingPolicyCoverage001 invalid input.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, StopAccessingPolicyCoverage001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo info1 = {
        .path = "/a/b",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    policy.emplace_back(info1);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, policyResult));
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<uint32_t> retType;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(g_mockToken, policy, retType));
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);

    std::vector<PolicyInfo> policyError;
    PolicyInfo info2 = {
        .path = "",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    PolicyInfo info3 = {
        .path = "/a/b",
        .mode = 0
    };

    policyError.emplace_back(info2);
    policyError.emplace_back(info3);

    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policyError, startResult));
    EXPECT_EQ(2, startResult.size());
    EXPECT_EQ(INVALID_PATH, startResult[0]);
    EXPECT_EQ(INVALID_MODE, startResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
}

/**
 * @tc.name: PolicyModeCoverage001
 * @tc.desc: diffent mode test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, PolicyModeCoverage001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy1;
    std::vector<PolicyInfo> policy2;
    std::vector<PolicyInfo> policy3;
    std::vector<uint32_t> persistResult;
    PolicyInfo info1 = {
        .path = "/A/B",
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo info2 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo info3 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    policy1.emplace_back(info1);
    policy1.emplace_back(info2);
    policy1.emplace_back(info3);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy1, policyFlag, persistResult));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy1, persistResult));
    ASSERT_EQ(3, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[2]);

    policy2.emplace_back(info1);
    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy2, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);

    std::vector<bool> checkPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policy1, checkPersistResult));
    ASSERT_EQ(3, checkPersistResult.size());
    EXPECT_TRUE(checkPersistResult[0]);
    EXPECT_TRUE(checkPersistResult[1]);
    EXPECT_TRUE(checkPersistResult[2]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy1, unPersistResult));
    ASSERT_EQ(3, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[2]);
}

/**
 * @tc.name: PolicyModeCoverage002
 * @tc.desc: diffent mode test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, PolicyModeCoverage002, TestSize.Level0)
{
    std::vector<PolicyInfo> policy1;
    std::vector<PolicyInfo> policy2;
    std::vector<PolicyInfo> policy3;
    std::vector<uint32_t> persistResult;
    PolicyInfo info1 = {
        .path = "/A/B",
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo info2 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo info3 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    policy1.emplace_back(info1);
    policy1.emplace_back(info2);
    policy1.emplace_back(info3);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy1, policyFlag, persistResult));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy1, persistResult));
    ASSERT_EQ(3, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[2]);

    policy2.emplace_back(info1);
    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy2, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);

    policy3.emplace_back(info3);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy3, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);

    std::vector<bool> checkPersistResult1;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policy1, checkPersistResult1));
    ASSERT_EQ(3, checkPersistResult1.size());
    EXPECT_FALSE(checkPersistResult1[0]);
    EXPECT_TRUE(checkPersistResult1[1]);
    EXPECT_FALSE(checkPersistResult1[2]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy1, unPersistResult));
    ASSERT_EQ(3, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[2]);
}

/**
 * @tc.name: PolicyModeCoverage003
 * @tc.desc: diffent mode test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, PolicyModeCoverage003, TestSize.Level0)
{
    std::vector<PolicyInfo> policy1;
    std::vector<PolicyInfo> policyR;
    std::vector<PolicyInfo> policyW;
    std::vector<uint32_t> persistResult;
    PolicyInfo info1 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo info2 = {
        .path = "/A/B",
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo info3 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    policy1.emplace_back(info3);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy1, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy1, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policyR.emplace_back(info1);
    policyW.emplace_back(info2);
    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyR, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);

    std::vector<bool> checkPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policyW, checkPersistResult));
    ASSERT_EQ(1, checkPersistResult.size());
    EXPECT_TRUE(checkPersistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy1, unPersistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
}

/**
 * @tc.name: PolicyModeCoverage004
 * @tc.desc: diffent mode test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, PolicyModeCoverage004, TestSize.Level0)
{
    std::vector<PolicyInfo> policy1;
    std::vector<PolicyInfo> policyR;
    std::vector<PolicyInfo> policyW;
    std::vector<uint32_t> persistResult;
    PolicyInfo info1 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo info2 = {
        .path = "/A/B",
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo info3 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    policy1.emplace_back(info3);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy1, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy1, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policyR.emplace_back(info1);
    policyW.emplace_back(info2);
    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyW, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);

    std::vector<bool> checkPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policyR, checkPersistResult));
    ASSERT_EQ(1, checkPersistResult.size());
    EXPECT_TRUE(checkPersistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy1, unPersistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
}

/**
 * @tc.name: PolicyModeCoverage005
 * @tc.desc: diffent mode test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, PolicyModeCoverage005, TestSize.Level0)
{
    std::vector<PolicyInfo> policy1;
    std::vector<PolicyInfo> policy2;
    std::vector<PolicyInfo> policy3;
    std::vector<uint32_t> persistResult;
    PolicyInfo info1 = {
        .path = "/A/B",
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo info2 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo info3 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    policy1.emplace_back(info1);
    policy1.emplace_back(info2);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy1, policyFlag, persistResult));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy1, persistResult));
    ASSERT_EQ(2, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);

    policy2.emplace_back(info3);

    std::vector<bool> checkPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policy2, checkPersistResult));
    ASSERT_EQ(1, checkPersistResult.size());
    EXPECT_TRUE(checkPersistResult[0]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy1, unPersistResult));
    ASSERT_EQ(2, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
}

/**
 * @tc.name: PolicyAsyncCoverage001
 * @tc.desc: SetPolicyAsync with invalid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, PolicyAsyncCoverage001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy1;
    std::vector<PolicyInfo> policy2;
    std::vector<PolicyInfo> policy3;
    uint64_t policyFlag = 1;
    PolicyInfo info1 = {
        .path = "/A/B",
        .mode = 0
    };
    PolicyInfo info2 = {
        .path = "",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    PolicyInfo info3 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policy1.emplace_back(info1);
    policy2.emplace_back(info2);
    policy3.emplace_back(info3);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicyAsync(g_mockToken, policy1, policyFlag));
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicyAsync(g_mockToken, policy2, policyFlag));
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicyAsync(g_mockToken + 1, policy2, policyFlag));
    ASSERT_EQ(SandboxManagerErrCode::INVALID_PARAMTER,
        SandboxManagerKit::SetPolicyAsync(0, policy3, policyFlag));
}

/**
 * @tc.name: PolicyAsyncCoverage002
 * @tc.desc: SetPolicyAsync with time
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, PolicyAsyncCoverage002, TestSize.Level0)
{
    std::vector<PolicyInfo> policy1;
    std::vector<PolicyInfo> policy2;
    std::vector<PolicyInfo> policy3;
    uint64_t policyFlag = 1;
    PolicyInfo info1 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    policy1.emplace_back(info1);

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicyAsync(g_mockToken, policy1, policyFlag, TEST_TIMESTAMP));
    sleep(1);
    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy1, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, info1));
}

/**
 * @tc.name: SetPolicyWithUIDCoverage001
 * @tc.desc: setpolicy with default userId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, SetPolicyWithUIDCoverage001, TestSize.Level0)
{
    if (!fileManagerPresent_) {
        return;
    }
    setuid(g_uid);
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> policyResult;
    PolicyInfo info1 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    policy.emplace_back(info1);
    uint64_t policyFlag = 1;
    std::vector<uint32_t> persistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    int32_t userId = 0;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        userId = 100; // set default userId
    }

    Security::AccessToken::AccessTokenID tokenID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_NE(0, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));

    std::vector<std::string> filePaths;
    filePaths.emplace_back(info1.path);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPolicyByUserId(userId, filePaths));
    sleep(1);

    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);
}

/**
 * @tc.name: SetPolicyWithUIDCoverage002
 * @tc.desc: setpolicy without permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, SetPolicyWithUIDCoverage002, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> policyResult;
    PolicyInfo info1 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    policy.emplace_back(info1);
    uint64_t policyFlag = 1;
    std::vector<uint32_t> persistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    int32_t userId = 0;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        userId = 100; // set default userId
    }

    std::vector<std::string> filePaths;
    filePaths.emplace_back(info1.path);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPolicyByUserId(userId, filePaths));
    sleep(1);

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, info1));
}

/**
 * @tc.name: UnSetPolicyCoverage001
 * @tc.desc: UnSetPolicy with invalid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, UnSetPolicyCoverage001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy1;
    uint64_t policyFlag = 1;
    PolicyInfo info1 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    policy1.emplace_back(info1);
    std::vector<uint32_t> persistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy1, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    PolicyInfo info2 = {
        .path = "",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetPolicy(0, info1));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetPolicy(g_mockToken, info2));
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, info1));
}

/**
 * @tc.name: UnSetPolicyAsyncCoverage001
 * @tc.desc: UnSetPolicyAsync with invalid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, UnSetPolicyAsyncCoverage001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy1;
    uint64_t policyFlag = 1;
    PolicyInfo info1 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    policy1.emplace_back(info1);
    std::vector<uint32_t> persistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy1, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetPolicyAsync(0, info1));

    PolicyInfo info2 = {
        .path = "",
        .mode = 0
    };
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicyAsync(g_mockToken, info2));
    sleep(1);
    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy1, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicyAsync(g_mockToken, info1));
    sleep(2);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy1, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);
}

/**
 * @tc.name: UnSetAllPolicyByTokenCoverage001
 * @tc.desc: UnSetAllPolicyByToken with invalid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, UnSetAllPolicyByTokenCoverage001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo info1 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    policy.emplace_back(info1);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, policyResult));
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<uint32_t> retType;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(g_mockToken, policy, retType));
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);

    ASSERT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetAllPolicyByToken(0));
    sleep(1);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetAllPolicyByToken(g_mockToken));
    sleep(1);
}

/**
 * @tc.name: PolicyModeUnsetCoverage001
 * @tc.desc: set r + w, unset r, clean all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, PolicyModeUnsetCoverage001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy1;
    std::vector<PolicyInfo> policy3;
    std::vector<uint32_t> persistResult;
    PolicyInfo info1 = {
        .path = "/A/B",
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo info2 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo info3 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    policy1.emplace_back(info3);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy1, policyFlag, persistResult));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy1, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy3.emplace_back(info1);
    policy3.emplace_back(info2);
    policy3.emplace_back(info3);
    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy3, checkResult));
    ASSERT_EQ(3, checkResult.size());
    EXPECT_TRUE(checkResult[0]);
    EXPECT_TRUE(checkResult[1]);
    EXPECT_TRUE(checkResult[2]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, info1));
    sleep(1);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy3, checkResult));
    ASSERT_EQ(3, checkResult.size());
    EXPECT_FALSE(checkResult[0]);
    EXPECT_FALSE(checkResult[1]);
    EXPECT_FALSE(checkResult[2]);
}

/**
 * @tc.name: StartAccessingPolicyCoverage003
 * @tc.desc: StartAccessingByTokenId with time.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, StartAccessingPolicyCoverage003, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo info1 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    policy.emplace_back(info1);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, policyResult,
        TEST_TIMESTAMP));
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);
    std::vector<uint32_t> retType;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(g_mockToken, policy, retType));
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingByTokenId(g_mockToken, TEST_TIMESTAMP));
    setuid(uid);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetAllPolicyByToken(g_mockToken, TEST_TIMESTAMP - 1));
    sleep(1);
    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetAllPolicyByToken(g_mockToken, TEST_TIMESTAMP + 1));
    sleep(1);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);
}

#ifdef DEC_SUPPORT_DENY_RW
/**
 * @tc.name: StartAccessingPolicyNullByte001
 * @tc.desc: StartAccessingPolicy with path containing embedded null byte (\\0 truncation).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, StartAccessingPolicyNullByte001, TestSize.Level0)
{
    // Construct a path with an embedded null byte: "/storage/Users/currentUser/appdata\0abc"
    // std::string::length() will count past \0, but strlen() stops at \0,
    // so the service should detect the mismatch and return INVALID_PATH.
    const char rawPath[] = "/storage/Users/currentUser/appdata\0abc";
    PolicyInfo infoNullByte = {
        .path = std::string(rawPath, sizeof(rawPath) - 1),
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    // Verify the embedded null byte is present in the std::string
    ASSERT_EQ(sizeof(rawPath) - 1, infoNullByte.path.length());
    ASSERT_NE(infoNullByte.path.length(), strlen(infoNullByte.path.c_str()));

    // SetPolicy with normal path should succeed
    PolicyInfo infoNormal = {
        .path = "/storage/Users/currentUser",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    std::vector<PolicyInfo> normalPolicy;
    normalPolicy.emplace_back(infoNormal);
    std::vector<uint32_t> setResult;
    uint64_t policyFlag = 1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, normalPolicy, policyFlag, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[0]);

    // PersistPolicy with normal path should succeed
    std::vector<uint32_t> persistResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(normalPolicy, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    // StartAccessingPolicy with null-byte path should be rejected
    std::vector<PolicyInfo> nullBytePolicy;
    nullBytePolicy.emplace_back(infoNullByte);
    std::vector<uint32_t> startResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(nullBytePolicy, startResult));
    ASSERT_EQ(1, startResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[0]);
}
#endif

#ifdef DEC_SUPPORT_DENY_DELETE_RENAME
/**
 * @tc.name: TokenNumAfterSetDenyPolicy001
 * @tc.desc: SetDenyPolicy increases both num and deny_num by 1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, DenyPolicyNumInc, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(SPACE_MGR_SERVICE_UID);
    int32_t numBefore = 0;
    int32_t denyNumBefore = 0;
    int32_t ret = GetTokenNum(g_mockToken, numBefore, denyNumBefore);
    if (ret != 0) {
        setuid(uid);
        GTEST_SKIP() << "GetTokenNum failed, skip test";
        return;
    }

    std::vector<PolicyInfo> policy = {{.path = "/data/test/token_num_deny", .mode = OperateMode::DENY_READ_MODE}};
    std::vector<uint32_t> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetDenyPolicy(g_mockToken, policy, result));

    int32_t numAfter = 0;
    int32_t denyNumAfter = 0;
    ASSERT_EQ(0, GetTokenNum(g_mockToken, numAfter, denyNumAfter));
    EXPECT_EQ(numBefore + 1, numAfter);
    EXPECT_EQ(denyNumBefore + 1, denyNumAfter);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetDenyPolicy(g_mockToken, policy[0]));
    setuid(uid);
}

/**
 * @tc.name: TokenNumAfterUnSetDenyPolicy001
 * @tc.desc: UnSetDenyPolicy decreases both num and deny_num by 1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, UnSetDenyPolicyNumDec, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(SPACE_MGR_SERVICE_UID);
    std::vector<PolicyInfo> policy = {{.path = "/data/test/token_num_unset_deny",
        .mode = OperateMode::DENY_READ_MODE}};
    std::vector<uint32_t> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetDenyPolicy(g_mockToken, policy, result));

    int32_t numBefore = 0;
    int32_t denyNumBefore = 0;
    ASSERT_EQ(0, GetTokenNum(g_mockToken, numBefore, denyNumBefore));

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetDenyPolicy(g_mockToken, policy[0]));

    int32_t numAfter = 0;
    int32_t denyNumAfter = 0;
    ASSERT_EQ(0, GetTokenNum(g_mockToken, numAfter, denyNumAfter));
    EXPECT_EQ(numBefore - 1, numAfter);
    EXPECT_EQ(denyNumBefore - 1, denyNumAfter);
    setuid(uid);
}

/**
 * @tc.name: TokenNumAfterSetPolicy001
 * @tc.desc: SetPolicy increases num by 1, deny_num unchanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, SetPolicyNumOnly, TestSize.Level0)
{
    int32_t numBefore = 0;
    int32_t denyNumBefore = 0;
    int32_t ret = GetTokenNum(g_mockToken, numBefore, denyNumBefore);
    if (ret != 0) {
        GTEST_SKIP() << "GetTokenNum failed, skip test";
        return;
    }

    std::vector<PolicyInfo> policy = {{.path = "/data/test/token_num_set", .mode = OperateMode::READ_MODE}};
    std::vector<uint32_t> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, 0, result));

    int32_t numAfter = 0;
    int32_t denyNumAfter = 0;
    ASSERT_EQ(0, GetTokenNum(g_mockToken, numAfter, denyNumAfter));
    EXPECT_EQ(numBefore + 1, numAfter);
    EXPECT_EQ(denyNumBefore, denyNumAfter);

    // Cleanup
    PolicyInfo info = policy[0];
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, info));
}

/**
 * @tc.name: UnSetPolicyNumDec
 * @tc.desc: UnSetPolicy decreases num by 1, deny_num unchanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, UnSetPolicyNumDec, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(SPACE_MGR_SERVICE_UID);
    std::vector<PolicyInfo> policy = {{.path = "/data/test/token_num_unset", .mode = OperateMode::READ_MODE}};
    std::vector<uint32_t> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, 0, result));

    int32_t numBefore = 0;
    int32_t denyNumBefore = 0;
    ASSERT_EQ(0, GetTokenNum(g_mockToken, numBefore, denyNumBefore));

    PolicyInfo info = policy[0];
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, info));

    int32_t numAfter = 0;
    int32_t denyNumAfter = 0;
    ASSERT_EQ(0, GetTokenNum(g_mockToken, numAfter, denyNumAfter));
    EXPECT_EQ(numBefore - 1, numAfter);
    EXPECT_EQ(denyNumBefore, denyNumAfter);
    setuid(uid);
}

/**
 * @tc.name: MixedPolicyDenyNum
 * @tc.desc: Interleaved SetPolicy and SetDenyPolicy — SetPolicy only bumps num,
 *           SetDenyPolicy bumps both num and deny_num
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, MixedPolicyDenyNum, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(SPACE_MGR_SERVICE_UID);

    int32_t numBase = 0;
    int32_t denyNumBase = 0;
    int32_t ret = GetTokenNum(g_mockToken, numBase, denyNumBase);
    if (ret != 0) {
        setuid(uid);
        GTEST_SKIP() << "GetTokenNum failed, skip test";
        return;
    }

    // SetPolicy: num+1, deny_num unchanged
    std::vector<PolicyInfo> normalPolicy = {{.path = "/data/test/mixed_normal", .mode = OperateMode::READ_MODE}};
    std::vector<uint32_t> normalResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, normalPolicy, 0, normalResult));

    int32_t num = 0;
    int32_t denyNum = 0;
    ASSERT_EQ(0, GetTokenNum(g_mockToken, num, denyNum));
    EXPECT_EQ(numBase + 1, num);
    EXPECT_EQ(denyNumBase, denyNum);

    // SetDenyPolicy: num+1, deny_num+1
    std::vector<PolicyInfo> denyPolicy = {{.path = "/data/test/mixed_deny", .mode = OperateMode::DENY_READ_MODE}};
    std::vector<uint32_t> denyResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetDenyPolicy(g_mockToken, denyPolicy, denyResult));

    ASSERT_EQ(0, GetTokenNum(g_mockToken, num, denyNum));
    EXPECT_EQ(numBase + 2, num);
    EXPECT_EQ(denyNumBase + 1, denyNum);

    // UnSetDenyPolicy: num-1, deny_num-1
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetDenyPolicy(g_mockToken, denyPolicy[0]));
    ASSERT_EQ(0, GetTokenNum(g_mockToken, num, denyNum));
    EXPECT_EQ(numBase + 1, num);
    EXPECT_EQ(denyNumBase, denyNum);

    // UnSetPolicy: num-1, deny_num unchanged
    PolicyInfo info = normalPolicy[0];
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, info));
    ASSERT_EQ(0, GetTokenNum(g_mockToken, num, denyNum));
    EXPECT_EQ(numBase, num);
    EXPECT_EQ(denyNumBase, denyNum);

    setuid(uid);
}


/**
 * @tc.name: UnSetAllPolicyByTokenNum
 * @tc.desc: UnSetAllPolicyByToken clears both normal and deny policies,
 *           resetting num and deny_num to baseline
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, UnSetAllPolicyByTokenNum, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(SPACE_MGR_SERVICE_UID);

    int32_t numBase = 0;
    int32_t denyNumBase = 0;
    int32_t ret = GetTokenNum(g_mockToken, numBase, denyNumBase);
    if (ret != 0) {
        setuid(uid);
        GTEST_SKIP() << "GetTokenNum failed, skip test";
        return;
    }

    std::vector<PolicyInfo> normalPolicy = {{.path = "/data/test/unset_all_normal", .mode = OperateMode::READ_MODE}};
    std::vector<uint32_t> normalResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, normalPolicy, 0, normalResult));

    std::vector<PolicyInfo> denyPolicy = {{.path = "/data/test/unset_all_deny", .mode = OperateMode::DENY_READ_MODE}};
    std::vector<uint32_t> denyResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetDenyPolicy(g_mockToken, denyPolicy, denyResult));

    int32_t num = 0;
    int32_t denyNum = 0;
    ASSERT_EQ(0, GetTokenNum(g_mockToken, num, denyNum));
    EXPECT_EQ(numBase + 2, num);
    EXPECT_EQ(denyNumBase + 1, denyNum);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetAllPolicyByToken(g_mockToken));

    ASSERT_TRUE(WaitForTokenNum(g_mockToken, numBase, denyNumBase));

    setuid(uid);
}

/**
 * @tc.name: CleanPersistPolicyByPathNum
 * @tc.desc: CleanPersistPolicyByPath clears the authorized persist policy,
 *           resetting num to baseline
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, CleanPersistPolicyByPathNum, TestSize.Level0)
{
    if (!fileManagerPresent_) {
        return;
    }
    int32_t uid = getuid();
    setuid(SPACE_MGR_SERVICE_UID);

    int32_t numBase = 0;
    int32_t denyNumBase = 0;
    int32_t ret = GetTokenNum(g_mockToken, numBase, denyNumBase);
    if (ret != 0) {
        setuid(uid);
        GTEST_SKIP() << "GetTokenNum failed, skip test";
        return;
    }

    std::vector<PolicyInfo> policy = {{.path = "/data/test/clean_persist_path", .mode = OperateMode::READ_MODE}};
    std::vector<uint32_t> policyResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, 1, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<PolicyInfo> denyPolicy = {{.path = "/data/test/clean_persist_deny",
        .mode = OperateMode::DENY_READ_MODE}};
    std::vector<uint32_t> denyResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetDenyPolicy(g_mockToken, denyPolicy, denyResult));

    int32_t num = 0;
    int32_t denyNum = 0;
    ASSERT_EQ(0, GetTokenNum(g_mockToken, num, denyNum));
    EXPECT_EQ(numBase + 2, num);
    EXPECT_EQ(denyNumBase + 1, denyNum);

    std::vector<std::string> filePaths;
    filePaths.emplace_back("/data/test");
    ASSERT_EQ(0, CleanPolicyByPathByUser(0, filePaths));

    setuid(g_uid);
    Security::AccessToken::AccessTokenID tokenID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_NE(0, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPersistPolicyByPath(filePaths));
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));

    setuid(SPACE_MGR_SERVICE_UID);
    ASSERT_TRUE(WaitForTokenNum(g_mockToken, numBase, denyNumBase));

    setuid(uid);
}

/**
 * @tc.name: CleanPersistPolicyByPathParentDir
 * @tc.desc: CleanPersistPolicyByPath with parent dir /data/test cleans
 *           all child policies (normal + deny) under that path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, CleanPersistPolicyByPathParentDir, TestSize.Level0)
{
    if (!fileManagerPresent_) {
        return;
    }
    int32_t uid = getuid();
    setuid(SPACE_MGR_SERVICE_UID);

    int32_t numBase = 0;
    int32_t denyNumBase = 0;
    int32_t ret = GetTokenNum(g_mockToken, numBase, denyNumBase);
    if (ret != 0) {
        setuid(uid);
        GTEST_SKIP() << "GetTokenNum failed, skip test";
        return;
    }

    std::vector<PolicyInfo> policyA = {{.path = "/data/tmp/clean_sub", .mode = OperateMode::READ_MODE}};
    std::vector<uint32_t> resultA;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyA, 1, resultA));

    std::vector<PolicyInfo> policyB = {{.path = "/data/test/clean_sub_e", .mode = OperateMode::WRITE_MODE}};
    std::vector<uint32_t> resultB;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyB, 1, resultB));

    std::vector<PolicyInfo> denyPolicy = {{.path = "/data/test/clean_sub_deny", .mode = OperateMode::DENY_READ_MODE}};
    std::vector<uint32_t> denyResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetDenyPolicy(g_mockToken, denyPolicy, denyResult));

    int32_t num = 0;
    int32_t denyNum = 0;
    ASSERT_EQ(0, GetTokenNum(g_mockToken, num, denyNum));
    EXPECT_EQ(numBase + 3, num);
    EXPECT_EQ(denyNumBase + 1, denyNum);

    std::vector<std::string> filePaths;
    filePaths.emplace_back("/data/test");
    ASSERT_EQ(0, CleanPolicyByPathByUser(0, filePaths));

    setuid(g_uid);
    Security::AccessToken::AccessTokenID tokenID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_NE(0, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPersistPolicyByPath(filePaths));
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));

    setuid(SPACE_MGR_SERVICE_UID);
    ASSERT_TRUE(WaitForTokenNum(g_mockToken, numBase + 1, denyNumBase));

    setuid(uid);
}

/**
 * @tc.name: CleanPersistPolicyByPathMassive
 * @tc.desc: CleanPersistPolicyByPath with parent dir /data/test cleans only
 *           child policies under /data/test, policies under other parent
 *           dirs (/data/storage) remain
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, CleanPersistPolicyByPathMassive, TestSize.Level0)
{
    if (!fileManagerPresent_) {
        return;
    }
    int32_t uid = getuid();
    setuid(SPACE_MGR_SERVICE_UID);

    constexpr int32_t NORMAL_COUNT = 30;
    constexpr int32_t DENY_COUNT = 10;
    int32_t numBase = 0;
    int32_t denyNumBase = 0;
    if (GetTokenNum(g_mockToken, numBase, denyNumBase) != 0) {
        setuid(uid);
        GTEST_SKIP() << "GetTokenNum failed, skip test";
        return;
    }

    std::vector<PolicyInfo> normalPolicies = MakePolicies(NORMAL_COUNT, "/data/test/massive_normal_",
        "/data/storage/massive_normal_", OperateMode::READ_MODE);
    std::vector<uint32_t> normalResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, normalPolicies, 1, normalResult));
    ASSERT_EQ(NORMAL_COUNT, static_cast<int32_t>(normalResult.size()));

    std::vector<PolicyInfo> denyPolicies = MakePolicies(DENY_COUNT, "/data/test/massive_deny_",
        "/data/storage/massive_deny_", OperateMode::DENY_READ_MODE);
    std::vector<uint32_t> denyResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetDenyPolicy(g_mockToken, denyPolicies, denyResult));
    ASSERT_EQ(DENY_COUNT, static_cast<int32_t>(denyResult.size()));

    int32_t num = 0;
    int32_t denyNum = 0;
    ASSERT_EQ(0, GetTokenNum(g_mockToken, num, denyNum));
    EXPECT_EQ(numBase + NORMAL_COUNT + DENY_COUNT, num);
    EXPECT_EQ(denyNumBase + DENY_COUNT, denyNum);

    std::vector<std::string> filePaths = {"/data/test"};
    ASSERT_EQ(0, CleanPolicyByPathByUser(0, filePaths));
    setuid(g_uid);
    Security::AccessToken::AccessTokenID tokenID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_NE(0, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPersistPolicyByPath(filePaths));
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
    setuid(SPACE_MGR_SERVICE_UID);
    ASSERT_TRUE(WaitForTokenNum(g_mockToken, numBase + NORMAL_COUNT / 2 + DENY_COUNT / 2,
        denyNumBase + DENY_COUNT / 2));

    setuid(uid);
}

/**
 * @tc.name: CleanPersistPolicyByPathMultiTokenMultiPath
 * @tc.desc: CleanPersistPolicyByPath with multiple parent dirs cleans child
 *           policies across multiple tokens, resetting counts to baseline
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, CleanPersistPolicyByPathMultiTokenMultiPath, TestSize.Level0)
{
    if (!fileManagerPresent_) {
        return;
    }
    int32_t uid = getuid();
    setuid(SPACE_MGR_SERVICE_UID);
    uint32_t mockToken2 = g_mockToken + 1;
    int32_t numBase = 0;
    int32_t denyNumBase = 0;
    int32_t numBase2 = 0;
    int32_t denyNumBase2 = 0;
    if (GetTokenNum(g_mockToken, numBase, denyNumBase) != 0 ||
        GetTokenNum(mockToken2, numBase2, denyNumBase2) != 0) {
        setuid(uid);
        GTEST_SKIP() << "GetTokenNum failed, skip test";
        return;
    }
    std::vector<uint32_t> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken,
        {{.path = "/data/test/multi_normal", .mode = OperateMode::READ_MODE}}, 1, result));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(mockToken2,
        {{.path = "/data/storage/multi_normal_b", .mode = OperateMode::WRITE_MODE}}, 1, result));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetDenyPolicy(g_mockToken,
        {{.path = "/data/tmp/multi_deny", .mode = OperateMode::DENY_READ_MODE}}, result));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetDenyPolicy(mockToken2,
        {{.path = "/data/app/multi_deny_b", .mode = OperateMode::DENY_WRITE_MODE}}, result));
    int32_t num = 0;
    int32_t denyNum = 0;
    ASSERT_EQ(0, GetTokenNum(g_mockToken, num, denyNum));
    EXPECT_EQ(numBase + 2, num);
    EXPECT_EQ(denyNumBase + 1, denyNum);
    ASSERT_EQ(0, GetTokenNum(mockToken2, num, denyNum));
    EXPECT_EQ(numBase2 + 2, num);
    EXPECT_EQ(denyNumBase2 + 1, denyNum);
    std::vector<std::string> filePaths = {"/data/test", "/data/storage", "/data/tmp", "/data/app"};
    ASSERT_EQ(0, CleanPolicyByPathByUser(0, filePaths));
    setuid(g_uid);
    Security::AccessToken::AccessTokenID tokenID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_NE(0, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPersistPolicyByPath(filePaths));
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
    setuid(SPACE_MGR_SERVICE_UID);
    ASSERT_TRUE(WaitForTokenNum(g_mockToken, numBase, denyNumBase));
    ASSERT_TRUE(WaitForTokenNum(mockToken2, numBase2, denyNumBase2));
    setuid(uid);
}
#endif
} // SandboxManager
} // AccessControl
} // OHOS
