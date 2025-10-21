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
#ifdef DEC_ENABLED
const uint32_t INVALID_OPERATE_MODE = 0;
#endif
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
void SandboxManagerKitSupplementalTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    SetDeny("/A");
    SetDeny("/C/D");
    SetDeny("/data/temp");
}

void SandboxManagerKitSupplementalTest::TearDownTestCase()
{
    Security::AccessToken::AccessTokenKit::DeleteToken(g_mockToken);
}

void SandboxManagerKitSupplementalTest::SetUp()
{
    EXPECT_TRUE(MockTokenId("foundation"));
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
    EXPECT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    g_mockToken = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
}

void SandboxManagerKitSupplementalTest::TearDown()
{
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
}

#ifdef DEC_ENABLED
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
#endif

#ifdef DEC_ENABLED
#ifdef DEC_EXT
/**
 * @tc.name: PhysicalPathDenyTest001
 * @tc.desc: test deny physical path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSupplementalTest, PhysicalPathDenyTest001, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo info1 = {
        .path = "/data/service/el1/100/",
        .mode = OperateMode::DENY_READ_MODE
    };
    const uint32_t tokenId = g_mockToken;
    policy.emplace_back(info1);

    const char *DISTRIBUTE_PATH = "/data/service/el1/100/distributeddata";
    DIR *dir = opendir(DISTRIBUTE_PATH);
    ASSERT_NE(dir, nullptr);
    closedir(dir);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(tokenId, policy, policyFlag, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    dir = opendir(DISTRIBUTE_PATH);
    ASSERT_EQ(dir, nullptr);

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(tokenId, info1));
    dir = opendir(DISTRIBUTE_PATH);
    ASSERT_NE(dir, nullptr);
    closedir(dir);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(tokenId, policy, policyFlag, policyResult));
    dir = opendir(DISTRIBUTE_PATH);
    ASSERT_EQ(dir, nullptr);
}
#endif // DEC_EXT
#endif // DEC_ENABLED

#ifdef DEC_ENABLED
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
#endif

#ifdef DEC_ENABLED
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
#endif

#ifdef DEC_ENABLED
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
#endif
} // SandboxManager
} // AccessControl
} // OHOS
