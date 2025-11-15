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

#include "sandbox_manager_kit_permission_test.h"

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
void SandboxManagerKitPermissionTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    SetDeny("/A");
    SetDeny("/C/D");
    SetDeny("/data/temp");
}

void SandboxManagerKitPermissionTest::TearDownTestCase()
{
    Security::AccessToken::AccessTokenKit::DeleteToken(g_mockToken);
}

void SandboxManagerKitPermissionTest::SetUp()
{
    EXPECT_TRUE(MockTokenId("foundation"));
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
    EXPECT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    g_mockToken = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
}

void SandboxManagerKitPermissionTest::TearDown()
{
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
}

#ifdef DEC_ENABLED
/**
 * @tc.name: StartAndStopAccessingPolicyTest001
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, StartAndStopAccessingPolicyTest001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    policyParent.emplace_back(infoParent);
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/E",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoSub3 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE
    };
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyParent, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policyParent, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoSub3);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(4, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[2]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[3]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(4, unPersistResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[3]);
}

/**
 * @tc.name: StartAndStopAccessingPolicyTest002
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, StartAndStopAccessingPolicyTest002, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::CREATE_MODE
    };
    policyParent.emplace_back(infoParent);
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/E",
        .mode = OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub3 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::CREATE_MODE
    };
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyParent, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policyParent, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoSub3);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(4, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[2]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[3]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(4, unPersistResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[3]);
}

/**
 * @tc.name: StartAndStopAccessingPolicyTest003
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, StartAndStopAccessingPolicyTest003, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::DELETE_MODE
    };
    policyParent.emplace_back(infoParent);
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/E",
        .mode = OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub3 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::DELETE_MODE
    };
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyParent, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policyParent, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoSub3);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(4, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[2]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[3]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(4, unPersistResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[3]);
}

/**
 * @tc.name: StartAndStopAccessingPolicyTest004
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, StartAndStopAccessingPolicyTest004, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::RENAME_MODE
    };
    policyParent.emplace_back(infoParent);
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/E",
        .mode = OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub3 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::RENAME_MODE
    };
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyParent, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policyParent, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoSub3);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(4, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[2]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[3]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(4, unPersistResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[3]);
}

/**
 * @tc.name: StartAndStopAccessingPolicyTest005
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, StartAndStopAccessingPolicyTest005, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policyParent.emplace_back(infoParent);
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/E",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    PolicyInfo infoSub3 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyParent, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policyParent, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoSub3);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(4, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[2]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[3]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(4, unPersistResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[3]);
}

/**
 * @tc.name: StartAndStopAccessingPolicyTest006
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, StartAndStopAccessingPolicyTest006, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    policyParent.emplace_back(infoParent);
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/E",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub3 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyParent, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policyParent, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoSub3);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(4, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[2]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[3]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(4, unPersistResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[3]);
}

/**
 * @tc.name: StartAndStopAccessingPolicyTest007
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, StartAndStopAccessingPolicyTest007, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    policyParent.emplace_back(infoParent);
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/E",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub3 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyParent, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policyParent, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoSub3);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(4, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[2]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[3]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(4, unPersistResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[3]);
}

/**
 * @tc.name: StartAndStopAccessingPolicyTest008
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, StartAndStopAccessingPolicyTest008, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    policyParent.emplace_back(infoParent);
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/E",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub3 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyParent, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policyParent, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoSub3);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(4, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[2]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[3]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(4, unPersistResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[3]);
}

/**
 * @tc.name: StartAccessingPolicyTestMode001
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, StartAccessingPolicyTestMode001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policySub;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/D",
        .mode = OperateMode::READ_MODE
    };
    policySub.emplace_back(infoSub1);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
}

/**
 * @tc.name: StartAccessingPolicyTestMode002
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, StartAccessingPolicyTestMode002, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policySub;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/D",
        .mode = OperateMode::CREATE_MODE
    };
    policySub.emplace_back(infoSub1);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
}

/**
 * @tc.name: StartAccessingPolicyTestMode003
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, StartAccessingPolicyTestMode003, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policySub;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/D",
        .mode = OperateMode::DELETE_MODE
    };
    policySub.emplace_back(infoSub1);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
}

/**
 * @tc.name: StartAccessingPolicyTestMode004
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, StartAccessingPolicyTestMode004, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policySub;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/D",
        .mode = OperateMode::RENAME_MODE
    };
    policySub.emplace_back(infoSub1);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
}

/**
 * @tc.name: StartAccessingPolicyTestMode005
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, StartAccessingPolicyTestMode005, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policySub;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policySub.emplace_back(infoSub1);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
}

/**
 * @tc.name: StartAccessingPolicyTestMode006
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, StartAccessingPolicyTestMode006, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policySub;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    policySub.emplace_back(infoSub1);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
}

/**
 * @tc.name: StartAccessingPolicyTestMode007
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, StartAccessingPolicyTestMode007, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policySub;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    policySub.emplace_back(infoSub1);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
}

/**
 * @tc.name: StartAccessingPolicyTestMode008
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, StartAccessingPolicyTestMode008, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policySub;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    policySub.emplace_back(infoSub1);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
}

/**
 * @tc.name: ParentDirAndChildDirSuccTest001
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, ParentDirAndChildDirSuccTest001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE
    };

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, persistResult));
    ASSERT_EQ(3, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[2]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, persistResult));
    EXPECT_EQ(3, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[2]);

    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[2]);
}

/**
 * @tc.name: ParentDirAndChildDirSuccTest002
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, ParentDirAndChildDirSuccTest002, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::CREATE_MODE
    };

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, persistResult));
    ASSERT_EQ(3, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[2]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, persistResult));
    EXPECT_EQ(3, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[2]);

    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[2]);
}

/**
 * @tc.name: ParentDirAndChildDirSuccTest003
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, ParentDirAndChildDirSuccTest003, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::DELETE_MODE
    };

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, persistResult));
    ASSERT_EQ(3, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[2]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, persistResult));
    EXPECT_EQ(3, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[2]);

    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[2]);
}

/**
 * @tc.name: ParentDirAndChildDirSuccTest004
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, ParentDirAndChildDirSuccTest004, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::RENAME_MODE
    };

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, persistResult));
    ASSERT_EQ(3, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[2]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, persistResult));
    EXPECT_EQ(3, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[2]);

    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[2]);
}

/**
 * @tc.name: ParentDirAndChildDirSuccTest005
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, ParentDirAndChildDirSuccTest005, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, persistResult));
    ASSERT_EQ(3, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[2]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, persistResult));
    EXPECT_EQ(3, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[2]);

    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[2]);
}

/**
 * @tc.name: ParentDirAndChildDirSuccTest006
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, ParentDirAndChildDirSuccTest006, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, persistResult));
    ASSERT_EQ(3, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[2]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, persistResult));
    EXPECT_EQ(3, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[2]);

    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[2]);
}

/**
 * @tc.name: ParentDirAndChildDirSuccTest007
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, ParentDirAndChildDirSuccTest007, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, persistResult));
    ASSERT_EQ(3, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[2]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, persistResult));
    EXPECT_EQ(3, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[2]);

    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[2]);
}

/**
 * @tc.name: ParentDirAndChildDirSuccTest008
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, ParentDirAndChildDirSuccTest008, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, persistResult));
    ASSERT_EQ(3, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[2]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, persistResult));
    EXPECT_EQ(3, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[2]);

    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[2]);
}

/**
 * @tc.name: ParentAndChildDirStopAccessingPolicyTest001
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, ParentAndChildDirStopAccessingPolicyTest001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/E",
        .mode = OperateMode::READ_MODE
    };
    policyParent.emplace_back(infoParent);
    policySub.emplace_back(infoSub1);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
}

/**
 * @tc.name: ParentAndChildDirStopAccessingPolicyTest002
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, ParentAndChildDirStopAccessingPolicyTest002, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/E",
        .mode = OperateMode::CREATE_MODE
    };
    policyParent.emplace_back(infoParent);
    policySub.emplace_back(infoSub1);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
}

/**
 * @tc.name: ParentAndChildDirStopAccessingPolicyTest003
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, ParentAndChildDirStopAccessingPolicyTest003, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/E",
        .mode = OperateMode::DELETE_MODE
    };
    policyParent.emplace_back(infoParent);
    policySub.emplace_back(infoSub1);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
}

/**
 * @tc.name: ParentAndChildDirStopAccessingPolicyTest004
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, ParentAndChildDirStopAccessingPolicyTest004, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/E",
        .mode = OperateMode::RENAME_MODE
    };
    policyParent.emplace_back(infoParent);
    policySub.emplace_back(infoSub1);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
}

/**
 * @tc.name: ParentAndChildDirStopAccessingPolicyTest005
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, ParentAndChildDirStopAccessingPolicyTest005, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/E",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policyParent.emplace_back(infoParent);
    policySub.emplace_back(infoSub1);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
}

/**
 * @tc.name: ParentAndChildDirStopAccessingPolicyTest006
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, ParentAndChildDirStopAccessingPolicyTest006, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/E",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    policyParent.emplace_back(infoParent);
    policySub.emplace_back(infoSub1);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
}

/**
 * @tc.name: ParentAndChildDirStopAccessingPolicyTest007
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, ParentAndChildDirStopAccessingPolicyTest007, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/E",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    policyParent.emplace_back(infoParent);
    policySub.emplace_back(infoSub1);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
}

/**
 * @tc.name: ParentAndChildDirStopAccessingPolicyTest008
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, ParentAndChildDirStopAccessingPolicyTest008, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/E",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    policyParent.emplace_back(infoParent);
    policySub.emplace_back(infoSub1);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, startResult));
    EXPECT_EQ(3, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[2]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(3, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[2]);
}
#endif
} // SandboxManager
} // AccessControl
} // OHOS
