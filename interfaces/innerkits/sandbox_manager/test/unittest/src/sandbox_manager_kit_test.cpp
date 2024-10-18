/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "sandbox_manager_kit_test.h"

#include <cstdint>
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
#define private public
#include "sandbox_manager_client.h"
#undef private
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"
#include "sandbox_manager_kit.h"
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
const std::string ACCESS_PERSIST_PERMISSION = "ohos.permission.FILE_ACCESS_PERSIST";
const Security::AccessToken::AccessTokenID INVALID_TOKENID = 0;
const uint64_t POLICY_VECTOR_SIZE_LIMIT = 500;
#ifdef DEC_ENABLED
const int32_t FOUNDATION_UID = 5523;
#endif
const size_t MAX_POLICY_NUM = 8;
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
Security::AccessToken::HapInfoParams g_testInfoParms = {
    .userID = 1,
    .bundleName = "sandbox_manager_test",
    .instIndex = 0,
    .appIDDesc = "test"
};

Security::AccessToken::HapPolicyParams g_testPolicyPrams = {
    .apl = Security::AccessToken::APL_NORMAL,
    .domain = "test.domain",
    .permList = {},
    .permStateList = {g_testState1, g_testState2}
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
    struct PathInfo pathInfos[MAX_POLICY_NUM];
    uint32_t pathNum = 0;
    bool persist = false;
};

static void SetDeny(const std::string& path)
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
        return;
    }
    auto ret = ioctl(fd, DENY_DEC_POLICY_CMD, &policyInfo);
    std::cout << "set deny ret: " << ret << std::endl;
    close(fd);
}
void SandboxManagerKitTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    SetDeny("/A");
    SetDeny("/C/D");
}

void SandboxManagerKitTest::TearDownTestCase()
{
    Security::AccessToken::AccessTokenKit::DeleteToken(g_mockToken);
}

void SandboxManagerKitTest::SetUp()
{
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
    EXPECT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    g_mockToken = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
}

void SandboxManagerKitTest::TearDown()
{
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
}

#ifdef DEC_ENABLED
/**
 * @tc.name: PersistPolicy003
 * @tc.desc: PersistPolicy with permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy003, TestSize.Level1)
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

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<bool> checkResult1;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policy, checkResult1));
    EXPECT_EQ(true, checkResult1[0]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));

    std::vector<bool> checkResult2;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policy, checkResult2));
    ASSERT_EQ(false, checkResult2[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PersistPolicyByTokenID001
 * @tc.desc: PersistPolicyByTokenId with permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicyByTokenID001, TestSize.Level1)
{
    PolicyInfo info = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    std::vector<uint32_t> policyResult;
    uint64_t policyFlag = 1;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    const uint32_t tokenId = 123456; // 123456 is a mocked tokenid.
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(tokenId, policy, policyFlag, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(tokenId, policy, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<bool> checkResult1;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(tokenId, policy, checkResult1));
    EXPECT_EQ(true, checkResult1[0]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(tokenId, policy, unPersistResult));

    std::vector<bool> checkResult2;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(tokenId, policy, checkResult2));
    ASSERT_EQ(false, checkResult2[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PersistPolicy004
 * @tc.desc: PersistPolicy with invalid path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy004, TestSize.Level1)
{
    PolicyInfo info = {
        .path = "",
        .mode = OperateMode::WRITE_MODE
    };
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);
    std::vector<uint32_t> result1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, result1));
    EXPECT_EQ(1, result1.size());
    EXPECT_EQ(INVALID_PATH, result1[0]);

    info.path = "/A/B/";
    info.mode = 222221; // 222221 means invalid mode.
    policy.emplace_back(info);
    std::vector<uint32_t> result2;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, result2));
    EXPECT_EQ(2, result2.size());
    EXPECT_EQ(INVALID_MODE, result2[1]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PersistPolicy005
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy005, TestSize.Level1)
{
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoSub = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE
    };
    uint64_t policyFlag = 1;
    std::vector<PolicyInfo> policyParent;
    policyParent.emplace_back(infoParent);

    std::vector<uint32_t> persistResult;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyParent, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policyParent, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    persistResult.clear();
    std::vector<PolicyInfo> policySub;
    policySub.emplace_back(infoSub);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policySub.emplace_back(infoParent);
    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policySub, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PersistPolicy006
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy006, TestSize.Level1)
{
    PolicyInfo infoSub = {
        .path = "/A/B/C",
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::WRITE_MODE
    };
    uint64_t policyFlag = 1;
    std::vector<uint32_t> persistResult;
    std::vector<PolicyInfo> policySub;
    policySub.emplace_back(infoSub);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<PolicyInfo> policyParent;
    policyParent.emplace_back(infoParent);
    persistResult.clear();

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyParent, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policyParent, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policyParent.emplace_back(infoSub);
    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PersistPolicy007
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy007, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    PolicyInfo infoSub = {
        .path = "/A/B/C",
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::WRITE_MODE
    };
    uint64_t policyFlag = 1;
    policy.emplace_back(infoSub);
    policy.emplace_back(infoParent);

    std::vector<uint32_t> persistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, persistResult));
    ASSERT_EQ(2, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, persistResult));
    EXPECT_EQ(2, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);

    std::vector<uint32_t> unPersistResult;
    std::vector<PolicyInfo> policyParent;
    policyParent.emplace_back(infoParent);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);

    std::vector<PolicyInfo> policySub;
    policySub.emplace_back(infoSub);
    unPersistResult.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policySub, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PersistPolicy008
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy008, TestSize.Level1)
{
    std::vector<PolicyInfo> policyParent;
    std::vector<PolicyInfo> policySub;
    std::vector<uint32_t> persistResult;
    uint64_t policyFlag = 1;
    PolicyInfo infoSub = {
        .path = "/A/B/C",
        .mode = OperateMode::WRITE_MODE
    };
    policySub.emplace_back(infoSub);
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::WRITE_MODE
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

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PersistPolicy009
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy009, TestSize.Level1)
{
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::WRITE_MODE
    };
    policyParent.emplace_back(infoParent);
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

    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK,
        SandboxManagerKit::CheckPersistPolicy(GetSelfTokenID(), policyParent, checkResult));
    EXPECT_EQ(false, checkResult[0]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policyParent, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);

    unPersistResult.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policySub, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PersistPolicy010
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy010, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::WRITE_MODE
    };
    policyParent.emplace_back(infoParent);
    PolicyInfo infoSub = {
        .path = "/A/B/C",
        .mode = OperateMode::WRITE_MODE
    };
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyParent, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policyParent, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(2, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PersistPolicy011
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy011, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policySub;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::WRITE_MODE
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
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(2, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PersistPolicy012
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy012, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo infoSub = {
        .path = "/A/B/C",
        .mode = OperateMode::WRITE_MODE
    };

    policy.emplace_back(infoSub);
    policy.emplace_back(infoParent);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, persistResult));
    ASSERT_EQ(2, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, persistResult));
    EXPECT_EQ(2, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);

    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, startResult));
    EXPECT_EQ(2, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PersistPolicy013
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy013, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo infoSub = {
        .path = "/A/B/C",
        .mode = OperateMode::WRITE_MODE
    };
    policyParent.emplace_back(infoParent);
    policySub.emplace_back(infoSub);
    uint64_t policyFlag = 1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policySub, policyFlag, persistResult));
    ASSERT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, startResult));
    EXPECT_EQ(2, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[1]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);
}
#endif

/**
 * @tc.name: PersistPolicy014
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy014, TestSize.Level1)
{
    uint32_t tokenId = 0;
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> result;
    uint64_t policyFlag = 0;
    std::vector<bool> flag;
    PolicyInfo infoParent = {.path = "/A/B", .mode = OperateMode::WRITE_MODE};
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::PersistPolicy(tokenId, policy, result));
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::UnPersistPolicy(tokenId, policy, result));
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER,
              SandboxManagerKit::SetPolicy(tokenId, policy, policyFlag, result));
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::CheckPersistPolicy(tokenId, policy, flag));
    tokenId = 1;
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::PersistPolicy(tokenId, policy, result));
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::UnPersistPolicy(tokenId, policy, result));
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER,
              SandboxManagerKit::SetPolicy(tokenId, policy, policyFlag, result));
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::CheckPersistPolicy(tokenId, policy, flag));

    tokenId = 0;
    policy.emplace_back(infoParent);
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::PersistPolicy(tokenId, policy, result));
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::UnPersistPolicy(tokenId, policy, result));
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER,
              SandboxManagerKit::SetPolicy(tokenId, policy, policyFlag, result));
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::CheckPersistPolicy(tokenId, policy, flag));
    tokenId = 1;
    EXPECT_NE(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::PersistPolicy(tokenId, policy, result));
    EXPECT_NE(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::UnPersistPolicy(tokenId, policy, result));
    EXPECT_NE(SandboxManagerErrCode::INVALID_PARAMTER,
              SandboxManagerKit::SetPolicy(tokenId, policy, policyFlag, result));
    EXPECT_NE(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::CheckPersistPolicy(tokenId, policy, flag));

    for (int i = 0; i < POLICY_VECTOR_SIZE_LIMIT; i++) {
        policy.emplace_back(infoParent);
    }
    tokenId = 0;
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::PersistPolicy(tokenId, policy, result));
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::UnPersistPolicy(tokenId, policy, result));
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER,
              SandboxManagerKit::SetPolicy(tokenId, policy, policyFlag, result));
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::CheckPersistPolicy(tokenId, policy, flag));
    tokenId = 1;
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::PersistPolicy(tokenId, policy, result));
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::UnPersistPolicy(tokenId, policy, result));
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER,
              SandboxManagerKit::SetPolicy(tokenId, policy, policyFlag, result));
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::CheckPersistPolicy(tokenId, policy, flag));
}

/**
 * @tc.name: PersistPolicy015
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy015, TestSize.Level1)
{
    uint32_t tokenId = 0;
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> result;
    uint64_t policyFlag = 0;
    std::vector<bool> flag;
    PolicyInfo infoParent = {.path = "/A/B", .mode = OperateMode::WRITE_MODE};
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicy(tokenId, policy, policyFlag, result));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicyAsync(tokenId, policy, policyFlag));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetPolicy(tokenId, infoParent));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetPolicyAsync(tokenId, infoParent));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::CheckPolicy(tokenId, policy, flag));
}

#ifdef DEC_ENABLED
/**
 * @tc.name: PersistPolicy016
 * @tc.desc: PersistPolicy with permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy016, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> searchPolicy;
    uint64_t policyFlag = 1;
    uint64_t policySize = 2; // 2 is policy size
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParent1 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoParent2 = {
        .path = "/A/B",
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo searchInfoPolicy = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policy.emplace_back(infoParent1);
    policy.emplace_back(infoParent2);
    searchPolicy.emplace_back(searchInfoPolicy);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, policyResult));
    ASSERT_EQ(policySize, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[1]);

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(policySize, result.size());
    EXPECT_TRUE(result[0]);
    EXPECT_TRUE(result[1]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, policyResult));
    ASSERT_EQ(policySize, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[1]);

    std::vector<bool> checkResult1;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, searchPolicy, checkResult1));
    ASSERT_EQ(1, checkResult1.size());
    EXPECT_EQ(true, checkResult1[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CheckPolicyTest001
 * @tc.desc: Check allowed policy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest001, TestSize.Level1)
{
    std::vector<PolicyInfo> policyA;
    uint64_t policyFlag = 0;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policyA.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyA, policyFlag, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<bool> result;
    infoParent.mode = OperateMode::READ_MODE;
    std::vector<PolicyInfo> policyB;
    policyB.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyB, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    infoParent.mode = OperateMode::WRITE_MODE;
    std::vector<PolicyInfo> policyC;
    policyC.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyC, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    infoParent.mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
    std::vector<PolicyInfo> policyD;
    policyD.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyD, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, policyA[0]));
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CheckPolicyTest002
 * @tc.desc: Check allowed policy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest002, TestSize.Level1)
{
    std::vector<PolicyInfo> policyA;
    uint64_t policyFlag = 0;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policyA.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyA, policyFlag, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<bool> result;
    infoParent.path = "/A/B/C";
    infoParent.mode = OperateMode::READ_MODE;
    std::vector<PolicyInfo> policyE;
    policyE.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyE, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    infoParent.mode = OperateMode::WRITE_MODE;
    std::vector<PolicyInfo> policyF;
    policyF.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyF, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    infoParent.mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
    std::vector<PolicyInfo> policyG;
    policyG.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyG, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, policyA[0]));
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CheckPolicyTest003
 * @tc.desc: Check parent directory policy with r+w
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest003, TestSize.Level1)
{
    std::vector<PolicyInfo> policyA;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policyA.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyA, policyFlag, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<bool> result;
    infoParent.path = "/A",
    infoParent.mode = OperateMode::READ_MODE;
    std::vector<PolicyInfo> policyB;
    policyB.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyB, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);

    infoParent.mode = OperateMode::WRITE_MODE;
    std::vector<PolicyInfo> policyC;
    policyC.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyC, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);

    infoParent.mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
    std::vector<PolicyInfo> policyD;
    policyD.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyD, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, policyA[0]));
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CheckPolicyTest004
 * @tc.desc: Check parent directory policy with r
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest004, TestSize.Level1)
{
    std::vector<PolicyInfo> policyA;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    policyA.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyA, policyFlag, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<bool> result;
    infoParent.mode = OperateMode::READ_MODE;
    std::vector<PolicyInfo> policyB;
    policyB.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyB, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    infoParent.mode = OperateMode::WRITE_MODE;
    std::vector<PolicyInfo> policyC;
    policyC.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyC, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);

    infoParent.mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
    std::vector<PolicyInfo> policyD;
    policyD.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyD, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);

    infoParent.path = "/A/B/C";
    infoParent.mode = OperateMode::READ_MODE;
    std::vector<PolicyInfo> policyE;
    policyE.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyE, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, policyA[0]));
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CheckPolicyTest005
 * @tc.desc: Check parent directory policy with w
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest005, TestSize.Level1)
{
    std::vector<PolicyInfo> policyA;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::WRITE_MODE
    };
    policyA.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyA, policyFlag, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<bool> result;
    infoParent.mode = OperateMode::READ_MODE;
    std::vector<PolicyInfo> policyB;
    policyB.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyB, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);

    infoParent.mode = OperateMode::WRITE_MODE;
    std::vector<PolicyInfo> policyC;
    policyC.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyC, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    infoParent.mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
    std::vector<PolicyInfo> policyD;
    policyD.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyD, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);

    infoParent.path = "/A/B/C";
    infoParent.mode = OperateMode::WRITE_MODE;
    std::vector<PolicyInfo> policyE;
    policyE.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyE, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, policyA[0]));
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CheckPolicyTest006
 * @tc.desc: Check parent directory policy with w
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest006, TestSize.Level1)
{
    std::vector<PolicyInfo> policyA;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParentA = {
        .path = "/A/B",
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo infoParentB = {
        .path = "/A/B/C",
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo infoParentC = {
        .path = "/C/D",
        .mode = OperateMode::WRITE_MODE
    };
    policyA.emplace_back(infoParentA);
    policyA.emplace_back(infoParentB);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyA, policyFlag, policyResult));
    ASSERT_EQ(2, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[1]);

    std::vector<bool> result;
    std::vector<PolicyInfo> policyB;
    policyB.emplace_back(infoParentA);
    policyB.emplace_back(infoParentB);
    policyB.emplace_back(infoParentC);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyB, result));
    ASSERT_EQ(3, result.size());
    EXPECT_TRUE(result[0]);
    EXPECT_TRUE(result[1]);
    EXPECT_FALSE(result[2]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CheckPolicyTest007
 * @tc.desc: Check allowed policy with invalid tokenID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest007, TestSize.Level1)
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

    std::vector<bool> result;
    ASSERT_EQ(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::CheckPolicy(INVALID_TOKENID, policy, result));
    EXPECT_EQ(0, result.size());

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_selfTokenId, policy, result));
    EXPECT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, policy[0]));
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CheckPolicyTest008
 * @tc.desc: Check allowed policy with invalid policy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest008, TestSize.Level1)
{
    std::vector<PolicyInfo> policyA;
    std::vector<bool> result;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    policyA.emplace_back(infoParent);
    for (int i = 0; i < POLICY_VECTOR_SIZE_LIMIT; i++) {
        policyA.emplace_back(infoParent);
    }
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER,
        SandboxManagerKit::CheckPolicy(g_mockToken, policyA, result));
    EXPECT_EQ(0, result.size());

    PolicyInfo infoParent1 = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    for (int i = 0; i < 100; i++) {
        infoParent1.path += "/A/B/C";
    }
    std::vector<PolicyInfo> policyB;
    policyB.emplace_back(infoParent1);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyB, result));
    EXPECT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);

    std::vector<PolicyInfo> policyC;
    infoParent.mode = 0;
    policyC.emplace_back(infoParent);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyC, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);

    std::vector<PolicyInfo> policyD;
    // err mode number
    infoParent.mode = OperateMode::WRITE_MODE + OperateMode::WRITE_MODE;
    policyD.emplace_back(infoParent);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyD, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: UnSetPolicyTest001
 * @tc.desc: Unset policy with invalid tokenID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, UnSetPolicyTest001, TestSize.Level1)
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

    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::UnSetPolicy(INVALID_TOKENID, policy[0]));
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_selfTokenId, policy[0]));
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, policy[0]));
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: UnSetPolicyTest002
 * @tc.desc: Unset allowed policy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, UnSetPolicyTest002, TestSize.Level1)
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

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    std::vector<uint32_t> retType;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(g_mockToken, policy, retType));
    ASSERT_EQ(1, retType.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, policy[0]));

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, retType));
    ASSERT_EQ(1, retType.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, policy[0]));
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: UnSetPolicyTest003
 * @tc.desc: Unset parent policy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, UnSetPolicyTest003, TestSize.Level1)
{
    std::vector<PolicyInfo> policyA;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policyA.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyA, policyFlag, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyA, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    infoParent.path = "/A";
    std::vector<PolicyInfo> policyB;
    policyB.emplace_back(infoParent);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, policyB[0]));
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, policyA[0]));
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: UnSetPolicyTest004
 * @tc.desc: Unset policy without permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, UnSetPolicyTest004, TestSize.Level1)
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

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    ASSERT_EQ(0, SetSelfTokenID(g_selfTokenId));
    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::UnSetPolicy(g_mockToken, policy[0]));
    ASSERT_EQ(0, SetSelfTokenID(g_mockToken));
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, policy[0]));
}
#endif

/**
 * @tc.name: PolicyAsyncTest001
 * @tc.desc: Set/Unset policy with invalid tokenID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PolicyAsyncTest001, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    uint64_t policyFlag = 1;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policy.emplace_back(infoParent);
    ASSERT_EQ(SandboxManagerErrCode::INVALID_PARAMTER,
        SandboxManagerKit::SetPolicyAsync(INVALID_TOKENID, policy, policyFlag));

    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER,
        SandboxManagerKit::UnSetPolicyAsync(INVALID_TOKENID, policy[0]));

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicyAsync(g_selfTokenId, policy, policyFlag));
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicyAsync(g_selfTokenId, policy[0]));
}

#ifdef DEC_ENABLED
/**
 * @tc.name: PolicyAsyncTest002
 * @tc.desc: Set/Unset allowed policy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PolicyAsyncTest002, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    uint64_t policyFlag = 1;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policy.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicyAsync(g_mockToken, policy, policyFlag));
    sleep(1);
    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    std::vector<uint32_t> retType;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(g_mockToken, policy, retType));
    ASSERT_EQ(1, retType.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicyAsync(g_mockToken, policy[0]));
    sleep(1);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, retType));
    ASSERT_EQ(1, retType.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicyAsync(g_mockToken, policy[0]));
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PolicyAsyncTest003
 * @tc.desc: Set/UnSet parent policy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PolicyAsyncTest003, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    uint64_t policyFlag = 1;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policy.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicyAsync(g_mockToken, policy, policyFlag));
    sleep(1);
    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    infoParent.path = "/A";
    std::vector<PolicyInfo> policyB;
    policyB.emplace_back(infoParent);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicyAsync(g_mockToken, policyB[0]));
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PolicyAsyncTest004
 * @tc.desc: Set/UnSet policy without permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PolicyAsyncTest004, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    uint64_t policyFlag = 1;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policy.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicyAsync(g_mockToken, policy, policyFlag));
    sleep(1);
    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    ASSERT_EQ(0, SetSelfTokenID(g_selfTokenId));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicyAsync(g_mockToken, policy, policyFlag));
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicyAsync(g_mockToken, policy[0]));
    ASSERT_EQ(0, SetSelfTokenID(g_mockToken));
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicyAsync(g_mockToken, policy[0]));
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CleanPersistPolicyByPathTest001
 * @tc.desc: Clean persist policy by path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CleanPersistPolicyByPathTest001, TestSize.Level1)
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

    std::vector<uint32_t> retType;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(g_mockToken, policy, retType));
    ASSERT_EQ(1, retType.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    Security::AccessToken::AccessTokenID tokenID =
        Security::AccessToken::AccessTokenKit::GetNativeTokenId("file_manager_service");
    EXPECT_NE(0, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));

    std::vector<std::string> filePaths;
    filePaths.emplace_back(infoParent.path);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPersistPolicyByPath(filePaths));
    sleep(1);
    std::vector<bool> result1;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result1));
    ASSERT_EQ(1, result1.size());
    EXPECT_FALSE(result1[0]);

    std::vector<bool> result2;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policy, result2));
    ASSERT_EQ(1, result2.size());
    EXPECT_FALSE(result2[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CleanPersistPolicyByPathTest002
 * @tc.desc: Clean child persist policy by path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CleanPersistPolicyByPathTest002, TestSize.Level1)
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

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    std::vector<uint32_t> retType;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(g_mockToken, policy, retType));
    ASSERT_EQ(1, retType.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);

    infoParent.path = "/A/B/C";
    std::vector<PolicyInfo> policyB;
    policyB.emplace_back(infoParent);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(g_mockToken, policyB, retType));
    ASSERT_EQ(1, retType.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);

    Security::AccessToken::AccessTokenID tokenID =
        Security::AccessToken::AccessTokenKit::GetNativeTokenId("file_manager_service");
    EXPECT_NE(0, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));

    std::vector<std::string> filePaths;
    infoParent.path = "/A/B";
    filePaths.emplace_back(infoParent.path);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPersistPolicyByPath(filePaths));
    sleep(1);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policyB, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CleanPersistPolicyByPathTest003
 * @tc.desc: Clean child persist policy by path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CleanPersistPolicyByPathTest003, TestSize.Level1)
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

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    std::vector<uint32_t> retType;
    infoParent.path = "/A/B/C";
    std::vector<PolicyInfo> policyB;
    policyB.emplace_back(infoParent);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(g_mockToken, policyB, retType));
    ASSERT_EQ(1, retType.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);

    Security::AccessToken::AccessTokenID tokenID =
        Security::AccessToken::AccessTokenKit::GetNativeTokenId("file_manager_service");
    EXPECT_NE(0, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));

    std::vector<std::string> filePaths;
    filePaths.emplace_back(infoParent.path);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPersistPolicyByPath(filePaths));
    sleep(1);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyB, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policyB, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);
}
#endif

/**
 * @tc.name: CleanPersistPolicyByPathTest004
 * @tc.desc: Clean persist policy by path with invalid path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CleanPersistPolicyByPathTest004, TestSize.Level1)
{
    std::string filePath = "/A/B";
    std::vector<std::string> filePaths;
    for (int i = 0; i < POLICY_VECTOR_SIZE_LIMIT; i++) {
        filePaths.emplace_back(filePath);
    }
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPersistPolicyByPath(filePaths));
}

#ifdef DEC_ENABLED
/**
 * @tc.name: CleanPersistPolicyByPathTest005
 * @tc.desc: Clean persist policy by path with invalid path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CleanPersistPolicyByPathTest005, TestSize.Level1)
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

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    std::vector<uint32_t> retType;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(g_mockToken, policy, retType));
    ASSERT_EQ(1, retType.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);

    std::vector<std::string> filePaths;
    filePaths.emplace_back(infoParent.path);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPersistPolicyByPath(filePaths));
    ASSERT_EQ(0, SetSelfTokenID(g_mockToken));
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPersistPolicyByPath(filePaths));
}
#endif

/**
 * @tc.name: StartAccessingByTokenIdTest001
 * @tc.desc: Start accessing by invalid tokenId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, StartAccessingByTokenIdTest001, TestSize.Level1)
{
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::StartAccessingByTokenId(0));
}

/**
 * @tc.name: StartAccessingByTokenIdTest002
 * @tc.desc: Start accessing without permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, StartAccessingByTokenIdTest002, TestSize.Level1)
{
    ASSERT_EQ(0, SetSelfTokenID(g_selfTokenId));
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingByTokenId(g_selfTokenId));
}

#ifdef DEC_ENABLED
/**
 * @tc.name: StartAccessingByTokenIdTest003
 * @tc.desc: Start accessing by tokenID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, StartAccessingByTokenIdTest003, TestSize.Level1)
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
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
    std::vector<uint32_t> retType;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(g_mockToken, policyA, retType));
    ASSERT_EQ(1, retType.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, policyA[0]));

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingByTokenId(g_mockToken));
    sleep(1);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyA, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policyA, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, policyA[0]));
    setuid(uid);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingByTokenId(g_mockToken));
    sleep(1);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyA, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policyA, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: UnSetAllPolicyByTokenTest001
 * @tc.desc: destroy all mac policy in kernel with given tokenid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, UnSetAllPolicyByTokenTest001, TestSize.Level1)
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

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetAllPolicyByToken(g_mockToken));
    sleep(1);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyA, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);
}
#endif
} // SandboxManager
} // AccessControl
} // OHOS