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
#include "sandbox_manager_load_callback.h"
#include "sandbox_manager_log.h"
#include "sandbox_manager_kit.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
const std::string SET_POLICY_PERMISSION = "ohos.permission.SET_SANDBOX_POLICY";
const std::string ACCESS_PERSIST_PERMISSION = "ohos.permission.FILE_ACCESS_PERSIST";
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

void NativeTokenGet()
{
    uint64_t fullTokenId;
    const char **perms = new const char *[1];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_core",
    };

    infoInstance.processName = "TestCase";
    fullTokenId = GetAccessTokenId(&infoInstance);
    EXPECT_EQ(0, SetSelfTokenID(fullTokenId));
    Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

void SandboxManagerKitTest::SetUpTestCase()
{
    NativeTokenGet();
    Security::AccessToken::AccessTokenID tokenID =
        Security::AccessToken::AccessTokenKit::GetNativeTokenId("foundation");
    EXPECT_NE(0, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
    EXPECT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    g_mockToken = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIdExStruct.tokenID));
}

void SandboxManagerKitTest::TearDownTestCase()
{
    Security::AccessToken::AccessTokenKit::DeleteToken(g_mockToken);
}

void SandboxManagerKitTest::SetUp()
{
}

void SandboxManagerKitTest::TearDown()
{
}

/**
 * @tc.name: PersistPolicy003
 * @tc.desc: PersistPolicy with permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy003, TestSize.Level1)
{
    PolicyInfo info = {
        .path = "/data/log",
        .mode = OperateMode::READ_MODE
    };
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);
    std::vector<uint32_t> result;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, result[0]);

    std::vector<bool> checkResult1;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(GetSelfTokenID(), policy, checkResult1));
    EXPECT_EQ(true, checkResult1[0]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));

    std::vector<bool> checkResult2;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(GetSelfTokenID(), policy, checkResult2));
    ASSERT_EQ(false, checkResult2[0]);
}

/**
 * @tc.name: PersistPolicyByTokenID001
 * @tc.desc: PersistPolicyByTokenId with permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicyByTokenID001, TestSize.Level1)
{
    PolicyInfo info = {
        .path = "/data/log",
        .mode = OperateMode::READ_MODE
    };
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);
    std::vector<uint32_t> result;

    const uint32_t tokenId = 123456; // 123456 is a mocked tokenid.

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(tokenId, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, result[0]);

    std::vector<bool> checkResult1;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(tokenId, policy, checkResult1));
    EXPECT_EQ(true, checkResult1[0]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(tokenId, policy, unPersistResult));

    std::vector<bool> checkResult2;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(tokenId, policy, checkResult2));
    ASSERT_EQ(false, checkResult2[0]);
}

/**
 * @tc.name: PersistPolicy004
 * @tc.desc: PersistPolicy with invalid path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy004, TestSize.Level1)
{    PolicyInfo info = {
        .path = "",
        .mode = OperateMode::WRITE_MODE
    };
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);
    std::vector<uint32_t> result1;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, result1));
    EXPECT_EQ(1, result1.size());
    EXPECT_EQ(INVALID_PATH, result1[0]);

    info.path = "/data/log/";
    info.mode = 222221; // 222221 means invalid mode.
    policy.emplace_back(info);
    std::vector<uint32_t> result2;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, result2));
    EXPECT_EQ(2, result2.size());
    EXPECT_EQ(INVALID_MODE, result2[1]);
}

/**
 * @tc.name: StartAccessingPolicy003
 * @tc.desc: StartAccessingPolicy without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, StartAccessingPolicy003, TestSize.Level1)
{
    PolicyInfo infoA = {
        .path = "/data/log",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoB = {
        .path = "/system/usr",
        .mode = OperateMode::READ_MODE
    };
    std::vector<PolicyInfo> policy;
    policy.emplace_back(infoA);
    policy.emplace_back(infoB);
    std::vector<uint32_t> persistResult;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, persistResult));
    ASSERT_EQ(2, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[1]);

    std::vector<uint32_t> result1;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, result1));
    ASSERT_EQ(2, result1.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, result1[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, result1[1]);

    result1.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, result1));
    ASSERT_EQ(2, result1.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, result1[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, result1[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));

    std::vector<uint32_t> result2;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, result2));
    ASSERT_EQ(2, result2.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, result2[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, result2[1]);

    result2.clear();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, result2));
    ASSERT_EQ(2, result2.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, result2[0]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, result2[1]);
}

/**
 * @tc.name: PersistPolicy005
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy005, TestSize.Level1)
{
    PolicyInfo infoParent = {
        .path = "/data/log",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoSub = {
        .path = "/data/log/hilog",
        .mode = OperateMode::READ_MODE
    };
    std::vector<PolicyInfo> policyParent;
    policyParent.emplace_back(infoParent);

    std::vector<uint32_t> persistResult;
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

/**
 * @tc.name: PersistPolicy006
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy006, TestSize.Level1)
{
    PolicyInfo infoSub = {
        .path = "/data/log/hilog",
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo infoParent = {
        .path = "/data/log",
        .mode = OperateMode::WRITE_MODE
    };
    std::vector<uint32_t> persistResult;
    std::vector<PolicyInfo> policySub;
    policySub.emplace_back(infoSub);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policySub, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    std::vector<PolicyInfo> policyParent;
    policyParent.emplace_back(infoParent);
    persistResult.clear();
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

/**
 * @tc.name: PersistPolicy007
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy007, TestSize.Level1)
{
    std::vector<uint32_t> persistResult;
    std::vector<PolicyInfo> policy;
    PolicyInfo infoSub = {
        .path = "/data/log/hilog",
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo infoParent = {
        .path = "/data/log",
        .mode = OperateMode::WRITE_MODE
    };
    policy.emplace_back(infoSub);
    policy.emplace_back(infoParent);
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
    
    PolicyInfo infoSub = {
        .path = "/data/log/hilog",
        .mode = OperateMode::WRITE_MODE
    };
    policySub.emplace_back(infoSub);
    PolicyInfo infoParent = {
        .path = "/data/log",
        .mode = OperateMode::WRITE_MODE
    };
    policyParent.emplace_back(infoParent);

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
        .path = "/data/log",
        .mode = OperateMode::WRITE_MODE
    };
    policyParent.emplace_back(infoParent);
    PolicyInfo infoSub = {
        .path = "/data/log/hilog",
        .mode = OperateMode::WRITE_MODE
    };
    policySub.emplace_back(infoSub);

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

/**
 * @tc.name: PersistPolicy009
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy010, TestSize.Level1)
{
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/data/log",
        .mode = OperateMode::WRITE_MODE
    };
    policyParent.emplace_back(infoParent);
    PolicyInfo infoSub = {
        .path = "/data/log/hilog",
        .mode = OperateMode::WRITE_MODE
    };
    policySub.emplace_back(infoSub);

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

/**
 * @tc.name: PersistPolicy009
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy011, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/data/log",
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo infoSub = {
        .path = "/data/log/hilog",
        .mode = OperateMode::WRITE_MODE
    };
    policyParent.emplace_back(infoParent);
    policySub.emplace_back(infoSub);

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

/**
 * @tc.name: PersistPolicy009
 * @tc.desc: PersistPolicy directory.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy012, TestSize.Level1)
{
    std::vector<PolicyInfo> policySub;
    std::vector<PolicyInfo> policy;
    std::vector<PolicyInfo> policyParent;
    std::vector<uint32_t> persistResult;
    PolicyInfo infoParent = {
        .path = "/data/log",
        .mode = OperateMode::WRITE_MODE
    };
    policyParent.emplace_back(infoParent);
    PolicyInfo infoSub = {
        .path = "/data/log/hilog",
        .mode = OperateMode::WRITE_MODE
    };
    policySub.emplace_back(infoSub);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policyParent, persistResult));
    EXPECT_EQ(1, persistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, persistResult[0]);

    policy.emplace_back(infoSub);
    policy.emplace_back(infoParent);
    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, startResult));
    EXPECT_EQ(2, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(2, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[1]);
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, unPersistResult[0]);
}

/**
 * @tc.name: PersistPolicy009
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
        .path = "/data/log",
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo infoSub = {
        .path = "/data/log/hilog",
        .mode = OperateMode::WRITE_MODE
    };
    policyParent.emplace_back(infoParent);
    policySub.emplace_back(infoSub);

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
    PolicyInfo infoParent = {.path = "/data/log", .mode = OperateMode::WRITE_MODE};
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

    for (int i = 0; i < 500; i++) {
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
 * @tc.desc: add test.
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
    PolicyInfo infoParent = {.path = "/data/log", .mode = OperateMode::WRITE_MODE};
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicy(tokenId, policy, policyFlag, result));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicyAsync(tokenId, policy, policyFlag));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetPolicy(tokenId, infoParent));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnSetPolicyAsync(tokenId, infoParent));
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::CheckPolicy(tokenId, policy, flag));
}
} //SandboxManager
} //AccessControl
} // OHOS