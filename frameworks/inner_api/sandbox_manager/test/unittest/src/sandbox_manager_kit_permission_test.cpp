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
#include "shared_directory_info_vec_raw_data.h"

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
const std::string GRANT_SENSITIVE_PERMISSION = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS";
const std::string REVOKE_SENSITIVE_PERMISSION = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS";
const std::string GET_SENSITIVE_PERMISSION = "ohos.permission.GET_SENSITIVE_PERMISSIONS";
const size_t MAX_POLICY_NUM = 8;
const int DEC_POLICY_HEADER_RESERVED = 64;
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
    .permissionName = GRANT_SENSITIVE_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_testState6 = {
    .permissionName = REVOKE_SENSITIVE_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_testState7 = {
    .permissionName = GET_SENSITIVE_PERMISSION,
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
        g_testState5, g_testState6, g_testState7}
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

    std::vector<PolicyInfo> cleanupPolicies = {
        {"/storage/Users/currentUser/Music", OperateMode::READ_MODE},
        {"/storage/Users/currentUser/Images", OperateMode::READ_MODE | OperateMode::WRITE_MODE},
        {"/storage/Users/currentUser/Images", OperateMode::WRITE_MODE},
    };
    const uint32_t UGC_TEST_TOKENID_START = 60001;
    const uint32_t UGC_TEST_TOKENID_END = 60011;
    for (uint32_t tokenId = UGC_TEST_TOKENID_START; tokenId <= UGC_TEST_TOKENID_END; ++tokenId) {
        SandboxManagerKit::RevokePermissionByUser(tokenId, cleanupPolicies);
    }
}

void SandboxManagerKitPermissionTest::SetUp()
{
    EXPECT_TRUE(MockTokenId("foundation"));
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
    EXPECT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    g_mockToken = tokenIdEx.tokenIDEx;
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
}

void SandboxManagerKitPermissionTest::TearDown()
{
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
}

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

/**
 * @tc.name: GetSharedDirectoryInfoTest001
 * @tc.desc: GetSharedDirectoryInfo with normal input.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, GetSharedDirectoryInfoTest001, TestSize.Level0)
{
    std::vector<SharedDirectoryInfo> result;

    int32_t ret = SandboxManagerKit::GetSharedDirectoryInfo(result);
    EXPECT_EQ(PERMISSION_DENIED, ret);
}
/**
 * @tc.name: GrantPermissionByUserTest001
 * @tc.desc: GrantPermissionByUser with valid policies via kit IPC.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, GrantPermissionByUserTest001, TestSize.Level0)
{
    uint32_t tokenId = 60001;
    std::vector<PolicyInfo> policies = {
        {"/storage/Users/currentUser/Music", OperateMode::READ_MODE},
        {"/storage/Users/currentUser/Images", OperateMode::READ_MODE | OperateMode::WRITE_MODE},
        {"/storage/External", OperateMode::READ_MODE},
    };

    std::vector<PolicyInfo> cleanupPolicies = {
        {"/storage/Users/currentUser/Music", OperateMode::READ_MODE},
        {"/storage/Users/currentUser/Images", OperateMode::READ_MODE | OperateMode::WRITE_MODE},
        {"/storage/External", OperateMode::READ_MODE},
    };
    SandboxManagerKit::RevokePermissionByUser(tokenId, cleanupPolicies);

    int32_t ret = SandboxManagerKit::GrantPermissionByUser(tokenId, policies);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    std::vector<uint32_t> tokenIdList = {tokenId};
    std::vector<PermissionStatusInfo> result;
    ret = SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(3u, result.size());
    for (size_t i = 0; i < result.size(); ++i) {
        EXPECT_EQ(static_cast<int32_t>(UGC_PERMISSION_GRANTED), result[i].grantStatus);
    }
}

/**
 * @tc.name: GrantPermissionByUserTest002
 * @tc.desc: GrantPermissionByUser with empty policies.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, GrantPermissionByUserTest002, TestSize.Level0)
{
    uint32_t tokenId = 60002;
    std::vector<PolicyInfo> policies;
    int32_t ret = SandboxManagerKit::GrantPermissionByUser(tokenId, policies);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: GrantPermissionByUserTest003
 * @tc.desc: GrantPermissionByUser with all invalid policies (empty path + bad mode).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, GrantPermissionByUserTest003, TestSize.Level0)
{
    uint32_t tokenId = 60003;
    std::vector<PolicyInfo> policies = {
        {"", OperateMode::READ_MODE},
        {"/storage/Users/currentUser/Music", 0},
    };
    int32_t ret = SandboxManagerKit::GrantPermissionByUser(tokenId, policies);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    std::vector<uint32_t> tokenIdList = {tokenId};
    std::vector<PermissionStatusInfo> result;
    ret = SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    EXPECT_EQ(0u, result.size());
}

/**
 * @tc.name: GrantPermissionByUserTest004
 * @tc.desc: GrantPermissionByUser with mixed valid/invalid policies; only valid persisted.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, GrantPermissionByUserTest004, TestSize.Level0)
{
    uint32_t tokenId = 60004;
    std::vector<PolicyInfo> policies = {
        {"/storage/Users/currentUser/Music", OperateMode::READ_MODE},
        {"", OperateMode::READ_MODE},
        {"/storage/Users/currentUser/Images", 0},
    };
    int32_t ret = SandboxManagerKit::GrantPermissionByUser(tokenId, policies);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    std::vector<uint32_t> tokenIdList = {tokenId};
    std::vector<PermissionStatusInfo> result;
    ret = SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1u, result.size());
    EXPECT_EQ("/storage/Users/currentUser/Music", result[0].policyInfo.path);
    EXPECT_EQ(static_cast<int32_t>(UGC_PERMISSION_GRANTED), result[0].grantStatus);
}

/**
 * @tc.name: RevokePermissionByUserTest001
 * @tc.desc: RevokePermissionByUser after grant; verify status becomes DENIED.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, RevokePermissionByUserTest001, TestSize.Level0)
{
    uint32_t tokenId = 60005;
    std::vector<PolicyInfo> policies = {
        {"/storage/Users/currentUser/Music", OperateMode::READ_MODE},
    };

    int32_t ret = SandboxManagerKit::GrantPermissionByUser(tokenId, policies);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    ret = SandboxManagerKit::RevokePermissionByUser(tokenId, policies);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    std::vector<uint32_t> tokenIdList = {tokenId};
    std::vector<PermissionStatusInfo> result;
    ret = SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1u, result.size());
    EXPECT_EQ(static_cast<int32_t>(UGC_PERMISSION_DENIED), result[0].grantStatus);
}

/**
 * @tc.name: RevokePermissionByUserTest002
 * @tc.desc: RevokePermissionByUser with empty policies.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, RevokePermissionByUserTest002, TestSize.Level0)
{
    uint32_t tokenId = 60006;
    std::vector<PolicyInfo> policies;
    int32_t ret = SandboxManagerKit::RevokePermissionByUser(tokenId, policies);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: RevokePermissionByUserTest003
 * @tc.desc: RevokePermissionByUser with all invalid policies (nothing to revoke).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, RevokePermissionByUserTest003, TestSize.Level0)
{
    uint32_t tokenId = 60007;
    std::vector<PolicyInfo> policies = {
        {"", OperateMode::READ_MODE},
        {"/storage/Users/currentUser/Music", 0},
    };
    int32_t ret = SandboxManagerKit::RevokePermissionByUser(tokenId, policies);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    std::vector<uint32_t> tokenIdList = {tokenId};
    std::vector<PermissionStatusInfo> result;
    ret = SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    EXPECT_EQ(0u, result.size());
}

/**
 * @tc.name: RevokePermissionByUserTest004
 * @tc.desc: RevokePermissionByUser with mixed valid/invalid policies.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, RevokePermissionByUserTest004, TestSize.Level0)
{
    uint32_t tokenId = 60008;
    std::vector<PolicyInfo> grantPolicies = {
        {"/storage/Users/currentUser/Music", OperateMode::READ_MODE},
        {"/storage/Users/currentUser/Images", OperateMode::WRITE_MODE},
    };
    int32_t ret = SandboxManagerKit::GrantPermissionByUser(tokenId, grantPolicies);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    std::vector<PolicyInfo> revokePolicies = {
        {"/storage/Users/currentUser/Music", OperateMode::READ_MODE},
        {"", OperateMode::READ_MODE},
        {"/storage/Users/currentUser/Images", OperateMode::WRITE_MODE},
    };
    ret = SandboxManagerKit::RevokePermissionByUser(tokenId, revokePolicies);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    std::vector<uint32_t> tokenIdList = {tokenId};
    std::vector<PermissionStatusInfo> result;
    ret = SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(2u, result.size());
    for (size_t i = 0; i < result.size(); ++i) {
        EXPECT_EQ(static_cast<int32_t>(UGC_PERMISSION_DENIED), result[i].grantStatus);
    }
}

/**
 * @tc.name: GetStatusByPermissionTest001
 * @tc.desc: GetStatusByPermission with multiple tokenIds, some with records and some without.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, GetStatusByPermissionTest001, TestSize.Level0)
{
    uint32_t tokenId1 = 60009;
    uint32_t tokenId2 = 60010;
    std::vector<PolicyInfo> policies1 = {
        {"/storage/Users/currentUser/Music", OperateMode::READ_MODE},
    };
    int32_t ret = SandboxManagerKit::GrantPermissionByUser(tokenId1, policies1);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    std::vector<uint32_t> tokenIdList = {tokenId1, tokenId2};
    std::vector<PermissionStatusInfo> result;
    ret = SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1u, result.size());
    EXPECT_EQ(tokenId1, result[0].tokenId);
    EXPECT_EQ(static_cast<int32_t>(UGC_PERMISSION_GRANTED), result[0].grantStatus);
}

/**
 * @tc.name: GetStatusByPermissionTest002
 * @tc.desc: GetStatusByPermission with empty tokenIdList.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, GetStatusByPermissionTest002, TestSize.Level0)
{
    std::vector<uint32_t> tokenIdList;
    std::vector<PermissionStatusInfo> result;
    int32_t ret = SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: GrantRevokeGrantSamePathTest001
 * @tc.desc: Grant -> Revoke -> Grant same path, verify status after each step.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, GrantRevokeGrantSamePathTest001, TestSize.Level0)
{
    uint32_t tokenId = 60011;
    std::vector<PolicyInfo> policies = {
        {"/storage/Users/currentUser/Music", OperateMode::READ_MODE},
    };

    std::vector<PolicyInfo> cleanupPolicies = {
        {"/storage/Users/currentUser/Music", OperateMode::READ_MODE},
    };
    SandboxManagerKit::RevokePermissionByUser(tokenId, cleanupPolicies);

    std::vector<uint32_t> tokenIdList = {tokenId};

    // Step 1: Grant
    int32_t ret = SandboxManagerKit::GrantPermissionByUser(tokenId, policies);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    std::vector<PermissionStatusInfo> result;
    ret = SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1u, result.size());
    EXPECT_EQ(static_cast<int32_t>(UGC_PERMISSION_GRANTED), result[0].grantStatus);

    // Step 2: Revoke
    ret = SandboxManagerKit::RevokePermissionByUser(tokenId, policies);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    result.clear();
    ret = SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1u, result.size());
    EXPECT_EQ(static_cast<int32_t>(UGC_PERMISSION_DENIED), result[0].grantStatus);

    // Step 3: Grant again
    ret = SandboxManagerKit::GrantPermissionByUser(tokenId, policies);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    result.clear();
    ret = SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1u, result.size());
    EXPECT_EQ(static_cast<int32_t>(UGC_PERMISSION_GRANTED), result[0].grantStatus);
}

/**
 * @tc.name: GrantPermissionByUserTest005
 * @tc.desc: GrantPermissionByUser with tokenId=0, should return INVALID_PARAMTER.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, GrantPermissionByUserTest005, TestSize.Level0)
{
    uint32_t tokenId = 0;
    std::vector<PolicyInfo> policies = {
        {"/storage/Users/currentUser/Music", OperateMode::READ_MODE},
    };
    int32_t ret = SandboxManagerKit::GrantPermissionByUser(tokenId, policies);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: GrantPermissionByUserTest006
 * @tc.desc: GrantPermissionByUser with disallowed path, should return OK but no records persisted.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, GrantPermissionByUserTest006, TestSize.Level0)
{
    uint32_t tokenId = 60012;
    std::vector<PolicyInfo> policies = {
        {"/data/app", OperateMode::READ_MODE},
        {"/storage/Users/currentUser/Documents", OperateMode::READ_MODE},
    };
    int32_t ret = SandboxManagerKit::GrantPermissionByUser(tokenId, policies);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    std::vector<uint32_t> tokenIdList = {tokenId};
    std::vector<PermissionStatusInfo> result;
    ret = SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    EXPECT_EQ(0u, result.size());
}

/**
 * @tc.name: GrantPermissionByUserTest007
 * @tc.desc: GrantPermissionByUser with false-prefix paths (e.g. /storage/ExternalBar).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, GrantPermissionByUserTest007, TestSize.Level0)
{
    uint32_t tokenId = 60013;
    std::vector<PolicyInfo> policies = {
        {"/storage/Users/currentUser/MusicFoo", OperateMode::READ_MODE},
        {"/storage/ExternalBar", OperateMode::READ_MODE},
        {"/storage/userExternalBaz", OperateMode::READ_MODE},
    };
    int32_t ret = SandboxManagerKit::GrantPermissionByUser(tokenId, policies);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    std::vector<uint32_t> tokenIdList = {tokenId};
    std::vector<PermissionStatusInfo> result;
    ret = SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    EXPECT_EQ(0u, result.size());
}

/**
 * @tc.name: GrantPermissionByUserTest008
 * @tc.desc: GrantPermissionByUser with allowed sub-paths, verify records persisted.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, GrantPermissionByUserTest008, TestSize.Level0)
{
    uint32_t tokenId = 60014;
    std::vector<PolicyInfo> policies = {
        {"/storage/Users/currentUser/Music/sub", OperateMode::READ_MODE},
        {"/storage/Users/currentUser/Videos/a/b/c", OperateMode::READ_MODE | OperateMode::WRITE_MODE},
        {"/storage/External/sdcard", OperateMode::READ_MODE},
    };
    int32_t ret = SandboxManagerKit::GrantPermissionByUser(tokenId, policies);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    std::vector<uint32_t> tokenIdList = {tokenId};
    std::vector<PermissionStatusInfo> result;
    ret = SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(3u, result.size());
    for (size_t i = 0; i < result.size(); ++i) {
        EXPECT_EQ(static_cast<int32_t>(UGC_PERMISSION_GRANTED), result[i].grantStatus);
    }
}

/**
 * @tc.name: GrantPermissionByUserTest009
 * @tc.desc: GrantPermissionByUser with all 5 allowed path prefixes in one call.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, GrantPermissionByUserTest009, TestSize.Level0)
{
    uint32_t tokenId = 60015;
    std::vector<PolicyInfo> policies = {
        {"/storage/Users/currentUser/Music", OperateMode::READ_MODE},
        {"/storage/Users/currentUser/Images", OperateMode::WRITE_MODE},
        {"/storage/Users/currentUser/Videos", OperateMode::READ_MODE | OperateMode::WRITE_MODE},
        {"/storage/External", OperateMode::READ_MODE},
        {"/storage/userExternal", OperateMode::READ_MODE},
    };
    int32_t ret = SandboxManagerKit::GrantPermissionByUser(tokenId, policies);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    std::vector<uint32_t> tokenIdList = {tokenId};
    std::vector<PermissionStatusInfo> result;
    ret = SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(5u, result.size());
    for (size_t i = 0; i < result.size(); ++i) {
        EXPECT_EQ(static_cast<int32_t>(UGC_PERMISSION_GRANTED), result[i].grantStatus);
    }
}

/**
 * @tc.name: GrantPermissionByUserTest010
 * @tc.desc: GrantPermissionByUser re-grant existing path (REPLACE semantics), verify no duplicate.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, GrantPermissionByUserTest010, TestSize.Level0)
{
    uint32_t tokenId = 60016;
    std::vector<PolicyInfo> policies = {
        {"/storage/Users/currentUser/Music", OperateMode::READ_MODE},
    };
    std::vector<PolicyInfo> cleanupPolicies = {
        {"/storage/Users/currentUser/Music", OperateMode::READ_MODE},
    };
    SandboxManagerKit::RevokePermissionByUser(tokenId, cleanupPolicies);

    int32_t ret = SandboxManagerKit::GrantPermissionByUser(tokenId, policies);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    ret = SandboxManagerKit::GrantPermissionByUser(tokenId, policies);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    std::vector<uint32_t> tokenIdList = {tokenId};
    std::vector<PermissionStatusInfo> result;
    ret = SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1u, result.size());
    EXPECT_EQ(static_cast<int32_t>(UGC_PERMISSION_GRANTED), result[0].grantStatus);
}

/**
 * @tc.name: RevokePermissionByUserTest005
 * @tc.desc: RevokePermissionByUser with tokenId=0, should return INVALID_PARAMTER.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, RevokePermissionByUserTest005, TestSize.Level0)
{
    uint32_t tokenId = 0;
    std::vector<PolicyInfo> policies = {
        {"/storage/Users/currentUser/Music", OperateMode::READ_MODE},
    };
    int32_t ret = SandboxManagerKit::RevokePermissionByUser(tokenId, policies);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: RevokePermissionByUserTest006
 * @tc.desc: RevokePermissionByUser on non-existent record, should return OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, RevokePermissionByUserTest006, TestSize.Level0)
{
    uint32_t tokenId = 60017;
    std::vector<PolicyInfo> policies = {
        {"/storage/Users/currentUser/Music", OperateMode::READ_MODE},
    };
    std::vector<PolicyInfo> cleanupPolicies = {
        {"/storage/Users/currentUser/Music", OperateMode::READ_MODE},
    };
    SandboxManagerKit::RevokePermissionByUser(tokenId, cleanupPolicies);

    int32_t ret = SandboxManagerKit::RevokePermissionByUser(tokenId, policies);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: GetStatusByPermissionTest003
 * @tc.desc: GetStatusByPermission with tokenIdList containing 0, should return INVALID_PARAMTER.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, GetStatusByPermissionTest003, TestSize.Level0)
{
    std::vector<uint32_t> tokenIdList = {60018, 0};
    std::vector<PermissionStatusInfo> result;
    int32_t ret = SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: GetStatusByPermissionTest004
 * @tc.desc: GetStatusByPermission with multiple tokenIds all having records.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, GetStatusByPermissionTest004, TestSize.Level0)
{
    uint32_t tokenId1 = 60019;
    uint32_t tokenId2 = 60020;
    std::vector<PolicyInfo> policies1 = {
        {"/storage/Users/currentUser/Music", OperateMode::READ_MODE},
    };
    std::vector<PolicyInfo> policies2 = {
        {"/storage/Users/currentUser/Images", OperateMode::WRITE_MODE},
        {"/storage/External", OperateMode::READ_MODE},
    };
    SandboxManagerKit::GrantPermissionByUser(tokenId1, policies1);
    SandboxManagerKit::GrantPermissionByUser(tokenId2, policies2);

    std::vector<uint32_t> tokenIdList = {tokenId1, tokenId2};
    std::vector<PermissionStatusInfo> result;
    int32_t ret = SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(3u, result.size());
    for (size_t i = 0; i < result.size(); ++i) {
        EXPECT_EQ(static_cast<int32_t>(UGC_PERMISSION_GRANTED), result[i].grantStatus);
    }
}

/**
 * @tc.name: GetStatusByPermissionTest005
 * @tc.desc: GetStatusByPermission with tokenIdList with no records at all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitPermissionTest, GetStatusByPermissionTest005, TestSize.Level0)
{
    std::vector<uint32_t> tokenIdList = {69999, 69998};
    std::vector<PermissionStatusInfo> result;
    int32_t ret = SandboxManagerKit::GetStatusByPermission(tokenIdList, result);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    EXPECT_EQ(0u, result.size());
}
} // SandboxManager
} // AccessControl
} // OHOS
