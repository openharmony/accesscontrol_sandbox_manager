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

#include "sandbox_manager_kit_mode_test.h"

#include <cstdint>
#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <vector>
#include "accesstoken_kit.h"
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
void SandboxManagerKitModeTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    SetDeny("/A");
    SetDeny("/C/D");
    SetDeny("/data/temp");
}

void SandboxManagerKitModeTest::TearDownTestCase()
{
    Security::AccessToken::AccessTokenKit::DeleteToken(g_mockToken);
}

void SandboxManagerKitModeTest::SetUp()
{
    EXPECT_TRUE(MockTokenId("foundation"));
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
    EXPECT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    g_mockToken = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
}

void SandboxManagerKitModeTest::TearDown()
{
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
}

#ifdef DEC_ENABLED
/**
 * @tc.name: PersistPolicyParentAndChildDirTest001
 * @tc.desc: Test persistent authorization for both subdirectories and parent directories simultaneously.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyParentAndChildDirTest001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    uint64_t policyFlag = 1;
    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);

    std::vector<uint32_t> persistResult;
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

    std::vector<uint32_t> unPersistResult;
    std::vector<PolicyInfo> policyParent;
    policyParent.emplace_back(infoParent);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);

    std::vector<PolicyInfo> policySub;
    policySub.emplace_back(infoSub1);
    policySub.emplace_back(infoSub2);
    unPersistResult.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policySub, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
}

/**
 * @tc.name: PersistPolicyParentAndChildDirTest002
 * @tc.desc: Test persistent authorization for both subdirectories and parent directories simultaneously.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyParentAndChildDirTest002, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::CREATE_MODE
    };
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::CREATE_MODE
    };
    uint64_t policyFlag = 1;
    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);

    std::vector<uint32_t> persistResult;
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

    std::vector<uint32_t> unPersistResult;
    std::vector<PolicyInfo> policyParent;
    policyParent.emplace_back(infoParent);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);

    std::vector<PolicyInfo> policySub;
    policySub.emplace_back(infoSub1);
    policySub.emplace_back(infoSub2);
    unPersistResult.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policySub, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
}

/**
 * @tc.name: PersistPolicyParentAndChildDirTest003
 * @tc.desc: Test persistent authorization for both subdirectories and parent directories simultaneously.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyParentAndChildDirTest003, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::DELETE_MODE
    };
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::DELETE_MODE
    };
    uint64_t policyFlag = 1;
    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);

    std::vector<uint32_t> persistResult;
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

    std::vector<uint32_t> unPersistResult;
    std::vector<PolicyInfo> policyParent;
    policyParent.emplace_back(infoParent);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);

    std::vector<PolicyInfo> policySub;
    policySub.emplace_back(infoSub1);
    policySub.emplace_back(infoSub2);
    unPersistResult.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policySub, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
}

/**
 * @tc.name: PersistPolicyParentAndChildDirTest004
 * @tc.desc: Test persistent authorization for both subdirectories and parent directories simultaneously.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyParentAndChildDirTest004, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::RENAME_MODE
    };
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::RENAME_MODE
    };
    uint64_t policyFlag = 1;
    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);

    std::vector<uint32_t> persistResult;
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

    std::vector<uint32_t> unPersistResult;
    std::vector<PolicyInfo> policyParent;
    policyParent.emplace_back(infoParent);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);

    std::vector<PolicyInfo> policySub;
    policySub.emplace_back(infoSub1);
    policySub.emplace_back(infoSub2);
    unPersistResult.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policySub, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
}

/**
 * @tc.name: PersistPolicyParentAndChildDirTest005
 * @tc.desc: Test persistent authorization for both subdirectories and parent directories simultaneously.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyParentAndChildDirTest005, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    uint64_t policyFlag = 1;
    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);

    std::vector<uint32_t> persistResult;
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

    std::vector<uint32_t> unPersistResult;
    std::vector<PolicyInfo> policyParent;
    policyParent.emplace_back(infoParent);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);

    std::vector<PolicyInfo> policySub;
    policySub.emplace_back(infoSub1);
    policySub.emplace_back(infoSub2);
    unPersistResult.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policySub, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
}

/**
 * @tc.name: PersistPolicyParentAndChildDirTest006
 * @tc.desc: Test persistent authorization for both subdirectories and parent directories simultaneously.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyParentAndChildDirTest006, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    uint64_t policyFlag = 1;
    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);

    std::vector<uint32_t> persistResult;
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

    std::vector<uint32_t> unPersistResult;
    std::vector<PolicyInfo> policyParent;
    policyParent.emplace_back(infoParent);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);

    std::vector<PolicyInfo> policySub;
    policySub.emplace_back(infoSub1);
    policySub.emplace_back(infoSub2);
    unPersistResult.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policySub, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
}

/**
 * @tc.name: PersistPolicyParentAndChildDirTest007
 * @tc.desc: Test persistent authorization for both subdirectories and parent directories simultaneously.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyParentAndChildDirTest007, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    uint64_t policyFlag = 1;
    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);

    std::vector<uint32_t> persistResult;
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

    std::vector<uint32_t> unPersistResult;
    std::vector<PolicyInfo> policyParent;
    policyParent.emplace_back(infoParent);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);

    std::vector<PolicyInfo> policySub;
    policySub.emplace_back(infoSub1);
    policySub.emplace_back(infoSub2);
    unPersistResult.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policySub, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
}

/**
 * @tc.name: PersistPolicyParentAndChildDirTest008
 * @tc.desc: Test persistent authorization for both subdirectories and parent directories simultaneously.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyParentAndChildDirTest008, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    uint64_t policyFlag = 1;
    policy.emplace_back(infoSub1);
    policy.emplace_back(infoSub2);
    policy.emplace_back(infoParent);

    std::vector<uint32_t> persistResult;
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

    std::vector<uint32_t> unPersistResult;
    std::vector<PolicyInfo> policyParent;
    policyParent.emplace_back(infoParent);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);

    std::vector<PolicyInfo> policySub;
    policySub.emplace_back(infoSub1);
    policySub.emplace_back(infoSub2);
    unPersistResult.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policySub, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
}

/**
 * @tc.name: PersistPolicyTestChildDirMode001
 * @tc.desc: Subdirectories can inherit the persistent authorization of the parent directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyTestChildDirMode001, TestSize.Level0)
{
    std::vector<PolicyInfo> policyParent;
    std::vector<PolicyInfo> policySub;
    std::vector<uint32_t> persistResult;
    uint64_t policyFlag = 1;
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE
    };
    policySub.emplace_back(infoSub1);
    policySub.emplace_back(infoSub2);
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    policyParent.emplace_back(infoParent);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyParent, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policyParent, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(GetSelfTokenID(), policySub, checkResult));
    EXPECT_EQ(true, checkResult[0]);
    EXPECT_EQ(true, checkResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}

/**
 * @tc.name: PersistPolicyTestChildDirMode002
 * @tc.desc: Subdirectories can inherit the persistent authorization of the parent directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyTestChildDirMode002, TestSize.Level0)
{
    std::vector<PolicyInfo> policyParent;
    std::vector<PolicyInfo> policySub;
    std::vector<uint32_t> persistResult;
    uint64_t policyFlag = 1;
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::CREATE_MODE
    };
    policySub.emplace_back(infoSub1);
    policySub.emplace_back(infoSub2);
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::CREATE_MODE
    };
    policyParent.emplace_back(infoParent);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyParent, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policyParent, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(GetSelfTokenID(), policySub, checkResult));
    EXPECT_EQ(true, checkResult[0]);
    EXPECT_EQ(true, checkResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}

/**
 * @tc.name: PersistPolicyTestChildDirMode003
 * @tc.desc: Subdirectories can inherit the persistent authorization of the parent directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyTestChildDirMode003, TestSize.Level0)
{
    std::vector<PolicyInfo> policyParent;
    std::vector<PolicyInfo> policySub;
    std::vector<uint32_t> persistResult;
    uint64_t policyFlag = 1;
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::DELETE_MODE
    };
    policySub.emplace_back(infoSub1);
    policySub.emplace_back(infoSub2);
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::DELETE_MODE
    };
    policyParent.emplace_back(infoParent);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyParent, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policyParent, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(GetSelfTokenID(), policySub, checkResult));
    EXPECT_EQ(true, checkResult[0]);
    EXPECT_EQ(true, checkResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}

/**
 * @tc.name: PersistPolicyTestChildDirMode004
 * @tc.desc: Subdirectories can inherit the persistent authorization of the parent directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyTestChildDirMode004, TestSize.Level0)
{
    std::vector<PolicyInfo> policyParent;
    std::vector<PolicyInfo> policySub;
    std::vector<uint32_t> persistResult;
    uint64_t policyFlag = 1;
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::RENAME_MODE
    };
    policySub.emplace_back(infoSub1);
    policySub.emplace_back(infoSub2);
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::RENAME_MODE
    };
    policyParent.emplace_back(infoParent);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyParent, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policyParent, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(GetSelfTokenID(), policySub, checkResult));
    EXPECT_EQ(true, checkResult[0]);
    EXPECT_EQ(true, checkResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}

/**
 * @tc.name: PersistPolicyTestChildDirMode005
 * @tc.desc: Subdirectories can inherit the persistent authorization of the parent directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyTestChildDirMode005, TestSize.Level0)
{
    std::vector<PolicyInfo> policyParent;
    std::vector<PolicyInfo> policySub;
    std::vector<uint32_t> persistResult;
    uint64_t policyFlag = 1;
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policySub.emplace_back(infoSub1);
    policySub.emplace_back(infoSub2);
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policyParent.emplace_back(infoParent);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyParent, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policyParent, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(GetSelfTokenID(), policySub, checkResult));
    EXPECT_EQ(true, checkResult[0]);
    EXPECT_EQ(true, checkResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}

/**
 * @tc.name: PersistPolicyTestChildDirMode006
 * @tc.desc: Subdirectories can inherit the persistent authorization of the parent directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyTestChildDirMode006, TestSize.Level0)
{
    std::vector<PolicyInfo> policyParent;
    std::vector<PolicyInfo> policySub;
    std::vector<uint32_t> persistResult;
    uint64_t policyFlag = 1;
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    policySub.emplace_back(infoSub1);
    policySub.emplace_back(infoSub2);
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    policyParent.emplace_back(infoParent);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyParent, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policyParent, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(GetSelfTokenID(), policySub, checkResult));
    EXPECT_EQ(true, checkResult[0]);
    EXPECT_EQ(true, checkResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}

/**
 * @tc.name: PersistPolicyTestChildDirMode007
 * @tc.desc: Subdirectories can inherit the persistent authorization of the parent directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyTestChildDirMode007, TestSize.Level0)
{
    std::vector<PolicyInfo> policyParent;
    std::vector<PolicyInfo> policySub;
    std::vector<uint32_t> persistResult;
    uint64_t policyFlag = 1;
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    policySub.emplace_back(infoSub1);
    policySub.emplace_back(infoSub2);
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    policyParent.emplace_back(infoParent);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyParent, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policyParent, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(GetSelfTokenID(), policySub, checkResult));
    EXPECT_EQ(true, checkResult[0]);
    EXPECT_EQ(true, checkResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}

/**
 * @tc.name: PersistPolicyTestChildDirMode008
 * @tc.desc: Subdirectories can inherit the persistent authorization of the parent directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyTestChildDirMode008, TestSize.Level0)
{
    std::vector<PolicyInfo> policyParent;
    std::vector<PolicyInfo> policySub;
    std::vector<uint32_t> persistResult;
    uint64_t policyFlag = 1;
    PolicyInfo infoSub1 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    policySub.emplace_back(infoSub1);
    policySub.emplace_back(infoSub2);
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    policyParent.emplace_back(infoParent);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyParent, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policyParent, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(GetSelfTokenID(), policySub, checkResult));
    EXPECT_EQ(true, checkResult[0]);
    EXPECT_EQ(true, checkResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}

/**
 * @tc.name: PersistPolicyParentDirFailTest001
 * @tc.desc: The parent directory cannot inherit persistent authorization from subdirectories.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyParentDirFailTest001, TestSize.Level0)
{
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE
    };
    policySub.emplace_back(infoSub1);
    policyParent.emplace_back(infoParent);
    policyParent.emplace_back(infoSub2);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK,
        SandboxManagerKit::CheckPersistPolicy(GetSelfTokenID(), policyParent, checkResult));
    EXPECT_EQ(false, checkResult[0]);
    EXPECT_EQ(false, checkResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);

    unPersistResult.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policySub, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}

/**
 * @tc.name: PersistPolicyParentDirFailTest002
 * @tc.desc: The parent directory cannot inherit persistent authorization from subdirectories.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyParentDirFailTest002, TestSize.Level0)
{
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C",
        .mode = OperateMode::CREATE_MODE
    };
    policySub.emplace_back(infoSub1);
    policyParent.emplace_back(infoParent);
    policyParent.emplace_back(infoSub2);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK,
        SandboxManagerKit::CheckPersistPolicy(GetSelfTokenID(), policyParent, checkResult));
    EXPECT_EQ(false, checkResult[0]);
    EXPECT_EQ(false, checkResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);

    unPersistResult.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policySub, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}

/**
 * @tc.name: PersistPolicyParentDirFailTest003
 * @tc.desc: The parent directory cannot inherit persistent authorization from subdirectories.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyParentDirFailTest003, TestSize.Level0)
{
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C",
        .mode = OperateMode::DELETE_MODE
    };
    policySub.emplace_back(infoSub1);
    policyParent.emplace_back(infoParent);
    policyParent.emplace_back(infoSub2);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK,
        SandboxManagerKit::CheckPersistPolicy(GetSelfTokenID(), policyParent, checkResult));
    EXPECT_EQ(false, checkResult[0]);
    EXPECT_EQ(false, checkResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);

    unPersistResult.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policySub, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}

/**
 * @tc.name: PersistPolicyParentDirFailTest004
 * @tc.desc: The parent directory cannot inherit persistent authorization from subdirectories.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyParentDirFailTest004, TestSize.Level0)
{
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C",
        .mode = OperateMode::RENAME_MODE
    };
    policySub.emplace_back(infoSub1);
    policyParent.emplace_back(infoParent);
    policyParent.emplace_back(infoSub2);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK,
        SandboxManagerKit::CheckPersistPolicy(GetSelfTokenID(), policyParent, checkResult));
    EXPECT_EQ(false, checkResult[0]);
    EXPECT_EQ(false, checkResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);

    unPersistResult.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policySub, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}

/**
 * @tc.name: PersistPolicyParentDirFailTest005
 * @tc.desc: The parent directory cannot inherit persistent authorization from subdirectories.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyParentDirFailTest005, TestSize.Level0)
{
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policySub.emplace_back(infoSub1);
    policyParent.emplace_back(infoParent);
    policyParent.emplace_back(infoSub2);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK,
        SandboxManagerKit::CheckPersistPolicy(GetSelfTokenID(), policyParent, checkResult));
    EXPECT_EQ(false, checkResult[0]);
    EXPECT_EQ(false, checkResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);

    unPersistResult.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policySub, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}

/**
 * @tc.name: PersistPolicyParentDirFailTest006
 * @tc.desc: The parent directory cannot inherit persistent authorization from subdirectories.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyParentDirFailTest006, TestSize.Level0)
{
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };
    policySub.emplace_back(infoSub1);
    policyParent.emplace_back(infoParent);
    policyParent.emplace_back(infoSub2);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK,
        SandboxManagerKit::CheckPersistPolicy(GetSelfTokenID(), policyParent, checkResult));
    EXPECT_EQ(false, checkResult[0]);
    EXPECT_EQ(false, checkResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);

    unPersistResult.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policySub, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}

/**
 * @tc.name: PersistPolicyParentDirFailTest007
 * @tc.desc: The parent directory cannot inherit persistent authorization from subdirectories.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyParentDirFailTest007, TestSize.Level0)
{
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::DELETE_MODE
    };
    policySub.emplace_back(infoSub1);
    policyParent.emplace_back(infoParent);
    policyParent.emplace_back(infoSub2);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK,
        SandboxManagerKit::CheckPersistPolicy(GetSelfTokenID(), policyParent, checkResult));
    EXPECT_EQ(false, checkResult[0]);
    EXPECT_EQ(false, checkResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);

    unPersistResult.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policySub, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}

/**
 * @tc.name: PersistPolicyParentDirFailTest008
 * @tc.desc: The parent directory cannot inherit persistent authorization from subdirectories.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitModeTest, PersistPolicyParentDirFailTest008, TestSize.Level0)
{
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub1 = {
        .path = "/A/B/C/D",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    PolicyInfo infoSub2 = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::RENAME_MODE
    };
    policySub.emplace_back(infoSub1);
    policyParent.emplace_back(infoParent);
    policyParent.emplace_back(infoSub2);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK,
        SandboxManagerKit::CheckPersistPolicy(GetSelfTokenID(), policyParent, checkResult));
    EXPECT_EQ(false, checkResult[0]);
    EXPECT_EQ(false, checkResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);

    unPersistResult.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policySub, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}
#endif
} // SandboxManager
} // AccessControl
} // OHOS
