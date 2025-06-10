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

#include "sandbox_manager_kit_test.h"

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
#define private public
#include "sandbox_manager_client.h"
#undef private
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"
#include "sandbox_manager_kit.h"
#include "sandbox_test_common.h"
#include "token_setproc.h"
#include "mac_adapter.h"
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
const Security::AccessToken::AccessTokenID INVALID_TOKENID = 0;
const uint64_t POLICY_VECTOR_SIZE = 5000;
#ifdef DEC_ENABLED
const int32_t FOUNDATION_UID = 5523;
const uint32_t INVALID_OPERATE_MODE = 0;
const uint32_t MAX_PATH_LENGTH = 4095;
const int SET_DENY_FAIL = -1;
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

#ifdef DEC_ENABLED
static void GeneratePath(const uint32_t len, std::string& path)
{
    path = "/";
    char tmp;
    for (uint32_t i = 1; i < len; i++) {
        tmp = random() % 36;
        if (tmp < 10) {
            tmp += '0';
        } else {
            tmp -= 10;
            tmp += 'A';
        }
        path += tmp;
    }
}
#endif

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
void SandboxManagerKitTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    SetDeny("/A");
    SetDeny("/C/D");
    SetDeny("/data/temp");
}

void SandboxManagerKitTest::TearDownTestCase()
{
    Security::AccessToken::AccessTokenKit::DeleteToken(g_mockToken);
}

void SandboxManagerKitTest::SetUp()
{
    int mockRet = MockTokenId("foundation");
    EXPECT_NE(0, mockRet);
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
HWTEST_F(SandboxManagerKitTest, PersistPolicy003, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, PersistPolicyByTokenID001, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, PersistPolicy004, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, PersistPolicy005, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, PersistPolicy006, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, PersistPolicy007, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, PersistPolicy008, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, PersistPolicy009, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, PersistPolicy010, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, PersistPolicy011, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, PersistPolicy012, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, PersistPolicy013, TestSize.Level0)
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

    for (int i = 0; i < POLICY_VECTOR_SIZE; i++) {
        policy.emplace_back(infoParent);
    }
    tokenId = 0;
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::PersistPolicy(tokenId, policy, result));
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::UnPersistPolicy(tokenId, policy, result));
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER,
              SandboxManagerKit::SetPolicy(tokenId, policy, policyFlag, result));
    EXPECT_EQ(SandboxManagerErrCode::INVALID_PARAMTER, SandboxManagerKit::CheckPersistPolicy(tokenId, policy, flag));
    tokenId = 1;
    EXPECT_EQ(SandboxManagerErrCode::SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(tokenId, policy, result));
    EXPECT_EQ(SandboxManagerErrCode::SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(tokenId, policy, result));
    EXPECT_EQ(SandboxManagerErrCode::SANDBOX_MANAGER_OK,
              SandboxManagerKit::SetPolicy(tokenId, policy, policyFlag, result));
    EXPECT_EQ(SandboxManagerErrCode::SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(tokenId, policy, flag));
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
HWTEST_F(SandboxManagerKitTest, PersistPolicy016, TestSize.Level0)
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
 * @tc.name: PersistPolicy017
 * @tc.desc: persistpolicy without temp policy. sandbox_1500
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy017, TestSize.Level1)
{
    std::vector<PolicyInfo> policys;
    std::vector<uint32_t> setPersistResult;
    PolicyInfo infoDir = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    policys.emplace_back(std::move(infoDir));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policys, setPersistResult));
    ASSERT_EQ(1, setPersistResult.size());
    EXPECT_EQ(FORBIDDEN_TO_BE_PERSISTED, setPersistResult[0]);
    std::vector<bool> checkPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policys, checkPersistResult));
    ASSERT_EQ(1, checkPersistResult.size());
    EXPECT_FALSE(checkPersistResult[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PersistPolicy018
 * @tc.desc: persistpolicy with temp policy and checkpersistpolicy, sandbox_1600
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy018, TestSize.Level1)
{
    std::vector<PolicyInfo> policys;
    std::vector<uint32_t> setResult;
    uint64_t policyFlag = 1;
    PolicyInfo infoDirA = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoSubDirA = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE
    };
    policys.emplace_back(infoDirA);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policys, policyFlag, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[0]);
    policys.emplace_back(infoSubDirA);
    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policys, checkResult));
    ASSERT_EQ(2, checkResult.size());
    EXPECT_TRUE(checkResult[0]);
    EXPECT_TRUE(checkResult[1]);
    std::vector<uint32_t> setPersistResult;
    policys.pop_back();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policys, setPersistResult));
    ASSERT_EQ(1, setPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setPersistResult[0]);
    std::vector<bool> checkPersistResult;
    policys.emplace_back(infoSubDirA);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policys, checkPersistResult));
    ASSERT_EQ(2, checkPersistResult.size());
    EXPECT_TRUE(checkPersistResult[0]);
    EXPECT_TRUE(checkPersistResult[1]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PersistPolicy019
 * @tc.desc: persistpolicy with policyflag 0, sandbox_1700
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy019, TestSize.Level1)
{
    std::vector<PolicyInfo> policys;
    std::vector<uint32_t> setResult;
    uint64_t policyFlag = 0;
    PolicyInfo infoDirA = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoSubDirA = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE
    };
    policys.emplace_back(infoDirA);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policys, policyFlag, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[0]);
    policys.emplace_back(infoSubDirA);
    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policys, checkResult));
    ASSERT_EQ(2, checkResult.size());
    EXPECT_TRUE(checkResult[0]);
    EXPECT_TRUE(checkResult[1]);
    std::vector<uint32_t> setPersistResult;
    policys.pop_back();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policys, setPersistResult));
    ASSERT_EQ(1, setPersistResult.size());
    EXPECT_EQ(FORBIDDEN_TO_BE_PERSISTED, setPersistResult[0]);
    std::vector<bool> checkPersistResult;
    policys.emplace_back(infoSubDirA);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policys, checkPersistResult));
    ASSERT_EQ(2, checkPersistResult.size());
    EXPECT_FALSE(checkPersistResult[0]);
    EXPECT_FALSE(checkPersistResult[1]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PersistPolicy020
 * @tc.desc: persistpolicy with invalid tokenid, sandbox_1800
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy020, TestSize.Level1)
{
    std::vector<PolicyInfo> policys;
    std::vector<uint32_t> setResult;
    uint64_t policyFlag = 1;
    PolicyInfo infoDirA = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    policys.emplace_back(infoDirA);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policys, policyFlag, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[0]);

    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    policys[0].mode = OperateMode::READ_MODE | (OperateMode::WRITE_MODE << 1);
    std::vector<uint32_t> setPersistResult;
    ASSERT_EQ(PERMISSION_DENIED, SandboxManagerKit::PersistPolicy(policys, setPersistResult));
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PersistPolicy021
 * @tc.desc: persistpolicy with invalid tokenid, sandbox_1900
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PersistPolicy021, TestSize.Level1)
{
    std::vector<PolicyInfo> policys;
    std::vector<uint32_t> setResult;
    uint64_t policyFlag = 1;
    PolicyInfo infoDirA = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    policys.emplace_back(infoDirA);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policys, policyFlag, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[0]);

    policys[0].path = string();
    EXPECT_EQ(SET_DENY_FAIL, SetDeny(policys[0].path));
    std::vector<uint32_t> setPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policys, setPersistResult));
    ASSERT_EQ(1, setPersistResult.size());
    EXPECT_EQ(INVALID_PATH, setPersistResult[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: MassiveIPCTest001
 * @tc.desc: IPC with massive policyinfos.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, MassiveIPCTest001, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    uint64_t policySize = 90000;
    uint64_t policyFlag = 1;

    for (uint64_t i = 0; i < policySize; i++) {
        PolicyInfo info;
        info.mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
        char path[1024];
        sprintf_s(path, sizeof(path), "/data/temp/a/b/c/d/e/f/g/h/i/j/persistbytoken/%d", i);
        info.path.assign(path);
        policy.emplace_back(info);
    }

    std::vector<uint32_t> ret;
    const uint32_t tokenId = 654321; // 123456 is a mocked tokenid.
    auto start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(tokenId, policy, policyFlag, ret));
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    std::cout << "SetPolicy cost " << duration.count() << "s" << std::endl;

    ASSERT_EQ(policySize, ret.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_EQ(OPERATE_SUCCESSFULLY, ret[i]);
    }
    std::vector<bool> result;
    start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(tokenId, policy, result));
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "CheckPolicy cost " << duration.count() << "s" << std::endl;

    ASSERT_EQ(policySize, result.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_TRUE(result[i]);
    }

    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(tokenId, policy[i]));
    }
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: MassiveIPCTest002
 * @tc.desc: IPC with massive policyinfos.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, MassiveIPCTest002, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    uint64_t policySize = 90000;
    uint64_t policyFlag = 1;

    for (uint64_t i = 0; i < policySize; i++) {
        PolicyInfo info;
        info.mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
        char path[1024];
        sprintf_s(path, sizeof(path), "/data/temp/a/b/c/d/e/f/g/h/i/j/persistbytoken/%d", i);
        info.path.assign(path);
        policy.emplace_back(info);
    }

    std::vector<uint32_t> ret;
    const uint32_t tokenId = 654321; // 123456 is a mocked tokenid.
    auto start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(tokenId, policy, policyFlag, ret));
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    std::cout << "SetPolicy cost " << duration.count() << "s" << std::endl;

    ASSERT_EQ(policySize, ret.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_EQ(OPERATE_SUCCESSFULLY, ret[i]);
    }

    std::vector<uint32_t> policyResult;
    start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(tokenId, policy, policyResult));
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "PersistPolicy cost " << duration.count() << "s" << std::endl;
    ASSERT_EQ(policySize, policyResult.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[i]);
    }

    std::vector<bool> checkResult1;
    start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(tokenId, policy, checkResult1));
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "CheckPersistPolicy cost " << duration.count() << "s" << std::endl;
    ASSERT_EQ(policySize, checkResult1.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_TRUE(checkResult1[i]);
    }

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(tokenId, policy, unPersistResult));
    ASSERT_EQ(policySize, unPersistResult.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[i]);
    }
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: MassiveIPCTest003
 * @tc.desc: IPC with massive policyinfos.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, MassiveIPCTest003, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    uint64_t policySize = 90000;
    uint64_t policyFlag = 1;

    for (uint64_t i = 0; i < policySize; i++) {
        PolicyInfo info;
        info.mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
        char path[1024];
        sprintf_s(path, sizeof(path), "/data/temp/a/b/c/d/e/f/g/h/i/j/persistbytoken/%d", i);
        info.path.assign(path);
        policy.emplace_back(info);
    }

    std::vector<uint32_t> ret;
    const uint32_t tokenId = 654321; // 123456 is a mocked tokenid.
    auto start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(tokenId, policy, policyFlag, ret));
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    std::cout << "SetPolicy cost " << duration.count() << "s" << std::endl;
    ASSERT_EQ(policySize, ret.size());

    std::vector<uint32_t> policyResult;
    start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(tokenId, policy, policyResult));
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "PersistPolicy cost " << duration.count() << "s" << std::endl;
    ASSERT_EQ(policySize, policyResult.size());

    std::vector<uint32_t> unPersistResult;
    start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(tokenId, policy, unPersistResult));
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "UnPersistPolicy cost " << duration.count() << "s" << std::endl;
    ASSERT_EQ(policySize, unPersistResult.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[i]);
    }

    std::vector<bool> checkResult2;
    start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(tokenId, policy, checkResult2));
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "CheckPersistPolicy cost " << duration.count() << "s" << std::endl;
    ASSERT_EQ(policySize, checkResult2.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_FALSE(checkResult2[i]);
    }
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: MassiveIPCTest004
 * @tc.desc: IPC with massive policyinfos.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, MassiveIPCTest004, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    uint64_t policySize = 90000;
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
    start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, policyResult));
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "PersistPolicy cost " << duration.count() << "s" << std::endl;
    ASSERT_EQ(policySize, policyResult.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[i]);
    }

    std::vector<bool> checkResult1;
    start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policy, checkResult1));
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "CheckPersistPolicy cost " << duration.count() << "s" << std::endl;
    ASSERT_EQ(policySize, checkResult1.size());
    for (uint64_t i = 0; i < policySize; i++) {
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

#ifdef DEC_ENABLED
/**
 * @tc.name: MassiveIPCTest005
 * @tc.desc: IPC with massive policyinfos.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, MassiveIPCTest005, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    uint64_t policySize = 90000;
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

    std::vector<uint32_t> policyResult;
    start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, policyResult));
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "PersistPolicy cost " << duration.count() << "s" << std::endl;
    ASSERT_EQ(policySize, policyResult.size());

    std::vector<uint32_t> unPersistResult;
    start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "UnPersistPolicy cost " << duration.count() << "s" << std::endl;
    ASSERT_EQ(policySize, unPersistResult.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[i]);
    }

    std::vector<bool> checkResult2;
    start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policy, checkResult2));
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "CheckPersistPolicy cost " << duration.count() << "s" << std::endl;
    ASSERT_EQ(policySize, unPersistResult.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_FALSE(checkResult2[i]);
    }
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: MassiveIPCTest006
 * @tc.desc: IPC with massive policyinfos.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, MassiveIPCTest006, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    uint64_t policySize = 90000;
    uint64_t policyFlag = 1;

    for (uint64_t i = 0; i < policySize; i++) {
        PolicyInfo info;
        info.mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
        char path[1024];
        sprintf_s(path, sizeof(path), "/data/temp/a/b/c/d/e/f/g/h/i/j/async_accessing/%d", i);
        info.path.assign(path);
        policy.emplace_back(info);
    }
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicyAsync(g_mockToken, policy, policyFlag));
    sleep(5);

    std::vector<uint32_t> retType;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(g_mockToken, policy, retType));
    ASSERT_EQ(policySize, retType.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[i]);
    }

    auto start = std::chrono::high_resolution_clock::now();
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicyAsync(g_mockToken, policy[0]));
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    std::cout << "UnSetPolicyAsync cost " << duration.count() << "s" << std::endl;
    sleep(1);

    start  = std::chrono::high_resolution_clock::now();
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, retType));
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "StartAccessingPolicy cost " << duration.count() << "s" << std::endl;
    ASSERT_EQ(policySize, retType.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[i]);
    }

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    ASSERT_EQ(policySize, result.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_TRUE(result[i]);
    }

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    ASSERT_EQ(policySize, unPersistResult.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[i]);
    }
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: MassiveIPCTest007
 * @tc.desc: IPC with massive policyinfos.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, MassiveIPCTest007, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    uint64_t policySize = 90000;
    uint64_t policyFlag = 1;

    for (uint64_t i = 0; i < policySize; i++) {
        PolicyInfo info;
        info.mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
        char path[1024];
        sprintf_s(path, sizeof(path), "/data/temp/a/b/c/d/e/f/g/h/i/j/stop_access/%d", i);
        info.path.assign(path);
        policy.emplace_back(info);
    }
    std::vector<uint32_t> result;
    auto start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, result));
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    std::cout << "SetPolicy cost " << duration.count() << "s" << std::endl;
    ASSERT_EQ(policySize, result.size());

    std::vector<uint32_t> persistResult;
    start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(policy, persistResult));
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "PersistPolicy cost " << duration.count() << "s" << std::endl;
    ASSERT_EQ(policySize, persistResult.size());

    std::vector<uint32_t> startResult;
    start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StopAccessingPolicy(policy, startResult));
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "StopAccessingPolicy cost " << duration.count() << "s" << std::endl;
    ASSERT_EQ(policySize, startResult.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[i]);
    }

    std::vector<uint32_t> unPersistResult;
    start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "UnPersistPolicy cost " << duration.count() << "s" << std::endl;
    ASSERT_EQ(policySize, unPersistResult.size());
    for (uint64_t i = 0; i < policySize; i++) {
        EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[i]);
    }
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CheckPerformanceTest001
 * @tc.desc: Unmarshall 50000 policyinfos
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CheckPerformanceTest001, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    uint64_t policySize = 50000;
 
    for (uint64_t i = 0;i < policySize; i++) {
        PolicyInfo info;
        info.mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
        char path[1024];
        sprintf_s(path, sizeof(path), "/data/temp/a/b/c/d/e/f/g/h/i/j/%d", i);
        info.path.assign(path);
        policy.emplace_back(info);
    }
    std::vector<bool> result;
    auto start = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policy, result));
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    EXPECT_LT(duration.count(), 2);

    ASSERT_EQ(policySize, result.size());
    EXPECT_TRUE(result[0]);
    EXPECT_TRUE(result[1]);
    for (uint64_t i = 0;i < policySize; i++) {
        EXPECT_TRUE(result[i]);
    }
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CheckPolicyTest001
 * @tc.desc: Check allowed policy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest001, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest002, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest003, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest004, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest005, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest006, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest007, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest008, TestSize.Level0)
{
    std::vector<PolicyInfo> policyA;
    std::vector<bool> result;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    policyA.emplace_back(infoParent);
    for (int i = 0; i < POLICY_VECTOR_SIZE; i++) {
        policyA.emplace_back(infoParent);
    }
    EXPECT_EQ(SandboxManagerErrCode::SANDBOX_MANAGER_OK,
        SandboxManagerKit::CheckPolicy(g_mockToken, policyA, result));
    EXPECT_EQ(POLICY_VECTOR_SIZE + 1, result.size());

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
 * @tc.name: CheckPolicyTest009
 * @tc.desc: Check allowed policy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest009, TestSize.Level0)
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
        .path = "/A/B/C.txt",
        .mode = OperateMode::WRITE_MODE
    };
    policyA.emplace_back(infoParentA);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyA, policyFlag, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);
 
    std::vector<bool> result;
    std::vector<PolicyInfo> policyB;
    policyB.emplace_back(infoParentA);
    policyB.emplace_back(infoParentB);
    policyB.emplace_back(infoParentC);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyB, result));
    ASSERT_EQ(3, result.size());
    EXPECT_TRUE(result[0]);
    EXPECT_TRUE(result[1]);
    EXPECT_TRUE(result[2]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CheckPolicyTest010
 * @tc.desc: Set invalid operate mode and check, sandbox_0500
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest010, TestSize.Level1)
{
    std::vector<PolicyInfo> policys;
    std::vector<uint32_t> setResult;
    uint64_t policyFlag = 0;
    PolicyInfo infoDirA = {
        .path = "/A/B",
        .mode = INVALID_OPERATE_MODE
    };
    PolicyInfo infoDirB = {
        .path = "/A/C",
        .mode = INVALID_OPERATE_MODE
    };
    PolicyInfo infoSubDirA = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE
    };
    policys.emplace_back(std::move(infoDirA));
    policys.emplace_back(std::move(infoDirB));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policys, policyFlag, setResult));
    ASSERT_EQ(2, setResult.size());
    EXPECT_EQ(INVALID_MODE, setResult[0]);
    EXPECT_EQ(INVALID_MODE, setResult[1]);
    policys.emplace_back(std::move(infoSubDirA));
    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policys, checkResult));
    ASSERT_EQ(3, checkResult.size());
    EXPECT_FALSE(checkResult[0]);
    EXPECT_FALSE(checkResult[1]);
    EXPECT_FALSE(checkResult[2]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CheckPolicyTest011
 * @tc.desc: Set invalid token, sandbox_0600
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest011, TestSize.Level1)
{
    std::vector<PolicyInfo> policys;
    std::vector<uint32_t> setResult;
    uint64_t policyFlag = 0;
    PolicyInfo infoDir = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    policys.emplace_back(std::move(infoDir));
    ASSERT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicy(INVALID_TOKENID, policys, policyFlag, setResult));
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CheckPolicyTest012
 * @tc.desc: Set invalid operate mode, sandbox_0700
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest012, TestSize.Level1)
{
    std::vector<PolicyInfo> policys;
    std::vector<uint32_t> setResult;
    uint64_t policyFlag = 0;
    PolicyInfo infoDir = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | (OperateMode::WRITE_MODE << 1)
    };
    policys.emplace_back(std::move(infoDir));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policys, policyFlag, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(INVALID_MODE, setResult[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CheckPolicyTest013
 * @tc.desc: Set and check MAX_PATH_LEN, sandbox_0900
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest013, TestSize.Level1)
{
    std::vector<PolicyInfo> policys;
    std::vector<uint32_t> setResult;
    uint64_t policyFlag = 1;
    string path;
    GeneratePath(MAX_PATH_LENGTH, path);
    SetDeny(path);
    PolicyInfo infoDir = {
        .path = path,
        .mode = OperateMode::READ_MODE
    };
    policys.emplace_back(std::move(infoDir));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policys, policyFlag, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[0]);
    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policys, checkResult));
    ASSERT_EQ(1, checkResult.size());
    EXPECT_TRUE(checkResult[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CheckPolicyTest014
 * @tc.desc: Set and Check 256 length path, sandbox_1000
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest014, TestSize.Level1)
{
    std::vector<PolicyInfo> policys;
    std::vector<uint32_t> setResult;
    uint64_t policyFlag = 0;
    string path;
    GeneratePath(256, path);
    SetDeny(path);
    PolicyInfo infoDir = {
        .path = path,
        .mode = OperateMode::READ_MODE
    };
    policys.emplace_back(std::move(infoDir));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policys, policyFlag, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[0]);
    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policys, checkResult));
    ASSERT_EQ(1, checkResult.size());
    EXPECT_TRUE(checkResult[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CheckPolicyTest015
 * @tc.desc: Set and Check root path, sandbox_1100
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest015, TestSize.Level1)
{
    std::vector<PolicyInfo> policys;
    std::vector<uint32_t> setResult;
    uint64_t policyFlag = 0;
    PolicyInfo infoDir = {
        .path = "/",
        .mode = OperateMode::READ_MODE
    };
    SetDeny(infoDir.path);
    policys.emplace_back(std::move(infoDir));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policys, policyFlag, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[0]);
    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policys, checkResult));
    ASSERT_EQ(1, checkResult.size());
    EXPECT_TRUE(checkResult[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CheckPolicyTest016
 * @tc.desc: path without '/', kernel fault, sandbox_1200
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest016, TestSize.Level1)
{
    std::vector<PolicyInfo> policys;
    std::vector<uint32_t> setResult;
    uint64_t policyFlag = 0;
    PolicyInfo infoDir = {
        .path = "a",
        .mode = OperateMode::READ_MODE
    };
    SetDeny(infoDir.path);
    policys.emplace_back(std::move(infoDir));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policys, policyFlag, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(POLICY_MAC_FAIL, setResult[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CheckPolicyTest017
 * @tc.desc: empty path, sandbox_1300
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CheckPolicyTest017, TestSize.Level1)
{
    std::vector<PolicyInfo> policys;
    std::vector<uint32_t> setResult;
    uint64_t policyFlag = 0;
    PolicyInfo infoDir = {
        .path = string(),
        .mode = OperateMode::READ_MODE
    };
    EXPECT_EQ(SET_DENY_FAIL, SetDeny(infoDir.path));
    policys.emplace_back(std::move(infoDir));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policys, policyFlag, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(INVALID_PATH, setResult[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PolicyFlagTest001
 * @tc.desc: invalid policy flag, sandbox_1400
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PolicyFlagTest001, TestSize.Level1)
{
    std::vector<PolicyInfo> policys;
    std::vector<uint32_t> setResult;
    uint64_t policyFlag = 2;
    PolicyInfo infoDir = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    policys.emplace_back(std::move(infoDir));
    ASSERT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicy(g_mockToken, policys, policyFlag, setResult));
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PathLengthTest001
 * @tc.desc: Set invalid PathLength, sandbox_0800
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PathLengthTest001, TestSize.Level1)
{
    std::vector<PolicyInfo> policys;
    std::vector<uint32_t> setResult;
    uint64_t policyFlag = 1;
    string path;
    GeneratePath(MAX_PATH_LENGTH + 1, path);
    PolicyInfo infoDir = {
        .path = path,
        .mode = OperateMode::READ_MODE
    };
    policys.emplace_back(std::move(infoDir));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policys, policyFlag, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(INVALID_PATH, setResult[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: UnSetPolicyTest001
 * @tc.desc: Unset policy with invalid tokenID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, UnSetPolicyTest001, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, UnSetPolicyTest002, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, UnSetPolicyTest003, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, UnSetPolicyTest004, TestSize.Level0)
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

#ifdef DEC_ENABLED
/**
 * @tc.name: UnSetPolicyTest005
 * @tc.desc: Unset policy without permission, sandbox_0300
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, UnSetPolicyTest005, TestSize.Level1)
{
    std::vector<PolicyInfo> policys;
    std::vector<uint32_t> setResult;
    PolicyInfo infoDir = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoSubDir = {
        .path = "/A/B/C",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoSubFile = {
        .path = "/A/B/C.txt",
        .mode = OperateMode::READ_MODE
    };
    policys.emplace_back(std::move(infoDir));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policys, 0, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, setResult[0]);
    policys.emplace_back(std::move(infoSubDir));
    policys.emplace_back(std::move(infoSubFile));
    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policys, checkResult));
    ASSERT_EQ(3, checkResult.size());
    EXPECT_TRUE(checkResult[0]);
    EXPECT_TRUE(checkResult[1]);
    EXPECT_TRUE(checkResult[2]);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetPolicy(g_mockToken, policys[0]));
    std::vector<bool> checkResult1;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policys, checkResult1));
    ASSERT_EQ(3, checkResult.size());
    EXPECT_FALSE(checkResult1[0]);
    EXPECT_FALSE(checkResult1[1]);
    EXPECT_FALSE(checkResult1[2]);
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
HWTEST_F(SandboxManagerKitTest, PolicyAsyncTest002, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, PolicyAsyncTest003, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, PolicyAsyncTest004, TestSize.Level0)
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
 * @tc.name: PolicyAsyncTest005
 * @tc.desc: Set and Check parent_dir, sub_dir and sub_file, sandbox_0200
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PolicyAsyncTest005, TestSize.Level1)
{
    std::vector<PolicyInfo> policys;
    std::vector<uint32_t> setResult;
    PolicyInfo infoDir = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoSubDir = {
        .path = "/A/B/C",
        .mode = OperateMode::WRITE_MODE
    };
    PolicyInfo infoSubFile = {
        .path = "/A/B/C.txt",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policys.emplace_back(std::move(infoDir));
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicyAsync(g_mockToken, policys, 0));
    sleep(1);
    policys.emplace_back(std::move(infoSubDir));
    policys.emplace_back(std::move(infoSubFile));
    std::vector<bool> checkResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policys, checkResult));
    ASSERT_EQ(3, checkResult.size());
    EXPECT_TRUE(checkResult[0]);
    EXPECT_FALSE(checkResult[1]);
    EXPECT_FALSE(checkResult[2]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CleanPersistPolicyByPathTest001
 * @tc.desc: Clean persist policy by path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CleanPersistPolicyByPathTest001, TestSize.Level0)
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

    Security::AccessToken::AccessTokenID tokenID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_NE(0, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));

    std::vector<std::string> filePaths;
    filePaths.emplace_back(infoParent.path);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPersistPolicyByPath(filePaths));
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
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
HWTEST_F(SandboxManagerKitTest, CleanPersistPolicyByPathTest002, TestSize.Level0)
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

    Security::AccessToken::AccessTokenID tokenID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_NE(0, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));

    std::vector<std::string> filePaths;
    infoParent.path = "/A/B";
    filePaths.emplace_back(infoParent.path);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPersistPolicyByPath(filePaths));
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
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
HWTEST_F(SandboxManagerKitTest, CleanPersistPolicyByPathTest003, TestSize.Level0)
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

    Security::AccessToken::AccessTokenID tokenID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_NE(0, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));

    std::vector<std::string> filePaths;
    filePaths.emplace_back(infoParent.path);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPersistPolicyByPath(filePaths));
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
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
    for (int i = 0; i < POLICY_VECTOR_SIZE; i++) {
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
HWTEST_F(SandboxManagerKitTest, CleanPersistPolicyByPathTest005, TestSize.Level0)
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

#ifdef DEC_ENABLED
/**
 * @tc.name: CleanPersistPolicyByPathTest006
 * @tc.desc: Clean persist policy by path with invalid path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CleanPersistPolicyByPathTest006, TestSize.Level0)
{
    std::vector<PolicyInfo> policy;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParentA = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoParentB = {
        .path = "/A/C",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoParentC = {
        .path = "/A/B/C",
        .mode = OperateMode::WRITE_MODE
    };
    policy.emplace_back(infoParentA);
    policy.emplace_back(infoParentB);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, policyResult));
    ASSERT_EQ(2, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<uint32_t> retType;
    std::vector<PolicyInfo> policyB;
    policyB.emplace_back(infoParentB);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(g_mockToken, policyB, retType));
    ASSERT_EQ(1, retType.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);

    Security::AccessToken::AccessTokenID tokenID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_NE(0, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));

    std::vector<std::string> filePaths;
    infoParentC.path = "/A/B/C 2";
    infoParentB.path = "/A/C 1";
    filePaths.emplace_back(infoParentC.path);
    filePaths.emplace_back(infoParentB.path);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPersistPolicyByPath(filePaths));
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
    sleep(1);

    std::vector<PolicyInfo> policyCheck;
    std::vector<bool> checkrResult;
    infoParentB.path = "/A/C";
    policyCheck.emplace_back(infoParentB);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policyCheck, checkrResult));
    ASSERT_EQ(1, checkrResult.size());
    EXPECT_TRUE(checkrResult[0]);
}
#endif


#ifdef DEC_ENABLED
/**
 * @tc.name: CleanPolicyByUserIdTest001
 * @tc.desc: Clean persist policy by path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CleanPolicyByUserIdTest001, TestSize.Level1)
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

    Security::AccessToken::AccessTokenID tokenID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_NE(0, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));

    int32_t userId = 0;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "CleanPolicyByUserIdTest, get user id failed error=%{public}d", ret);
        userId = 0; // set default userId
    }
    std::vector<std::string> filePaths;
    filePaths.emplace_back(infoParent.path);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPolicyByUserId(userId, filePaths));
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
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
 * @tc.name: CleanPolicyByUserIdTest002
 * @tc.desc: Clean child persist policy by path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CleanPolicyByUserIdTest002, TestSize.Level1)
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

    Security::AccessToken::AccessTokenID tokenID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_NE(0, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));

    int32_t userId = 0;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "CleanPolicyByUserIdTest, get user id failed error=%{public}d", ret);
        userId = 0; // set default userId
    }
    std::vector<std::string> filePaths;
    infoParent.path = "/A/B";
    filePaths.emplace_back(infoParent.path);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPolicyByUserId(userId, filePaths));
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
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
 * @tc.name: CleanPolicyByUserIdTest003
 * @tc.desc: Clean child persist policy by path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CleanPolicyByUserIdTest003, TestSize.Level1)
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

    Security::AccessToken::AccessTokenID tokenID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_NE(0, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));

    int32_t userId = 0;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "CleanPolicyByUserIdTest, get user id failed error=%{public}d", ret);
        userId = 0; // set default userId
    }
    std::vector<std::string> filePaths;
    filePaths.emplace_back(infoParent.path);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPolicyByUserId(userId, filePaths));
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
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
 * @tc.name: CleanPolicyByUserIdTest004
 * @tc.desc: Clean persist policy by path with invalid path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CleanPolicyByUserIdTest004, TestSize.Level1)
{
    std::string filePath = "/A/B";
    std::vector<std::string> filePaths;
    for (int i = 0; i < POLICY_VECTOR_SIZE; i++) {
        filePaths.emplace_back(filePath);
    }
    int32_t userId = 0;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "CleanPolicyByUserIdTest, get user id failed error=%{public}d", ret);
        userId = 0; // set default userId
    }
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPolicyByUserId(userId, filePaths));
}

#ifdef DEC_ENABLED
/**
 * @tc.name: CleanPolicyByUserIdTest005
 * @tc.desc: Clean persist policy by path with invalid path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CleanPolicyByUserIdTest005, TestSize.Level1)
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

    int32_t userId = 0;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "CleanPolicyByUserIdTest, get user id failed error=%{public}d", ret);
        userId = 0; // set default userId
    }
    std::vector<std::string> filePaths;
    filePaths.emplace_back(infoParent.path);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPolicyByUserId(userId, filePaths));
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: CleanPolicyByUserIdTest006
 * @tc.desc: Clean persist policy by path with invalid path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CleanPolicyByUserIdTest006, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParentA = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoParentB = {
        .path = "/A/C",
        .mode = OperateMode::READ_MODE
    };
    PolicyInfo infoParentC = {
        .path = "/A/B/C",
        .mode = OperateMode::WRITE_MODE
    };
    policy.emplace_back(infoParentA);
    policy.emplace_back(infoParentB);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policy, policyFlag, policyResult));
    ASSERT_EQ(2, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<uint32_t> retType;
    std::vector<PolicyInfo> policyB;
    policyB.emplace_back(infoParentB);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(g_mockToken, policyB, retType));
    ASSERT_EQ(1, retType.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);

    Security::AccessToken::AccessTokenID tokenID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_NE(0, tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));

    int32_t userId = 0;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "CleanPolicyByUserIdTest, get user id failed error=%{public}d", ret);
        userId = 0; // set default userId
    }
    std::vector<std::string> filePaths;
    infoParentC.path = "/A/B/C 2";
    infoParentB.path = "/A/C 1";
    filePaths.emplace_back(infoParentC.path);
    filePaths.emplace_back(infoParentB.path);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CleanPolicyByUserId(userId, filePaths));
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
    sleep(1);

    std::vector<PolicyInfo> policyCheck;
    std::vector<bool> checkrResult;
    infoParentB.path = "/A/C";
    policyCheck.emplace_back(infoParentB);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(g_mockToken, policyCheck, checkrResult));
    ASSERT_EQ(1, checkrResult.size());
    EXPECT_TRUE(checkrResult[0]);
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
HWTEST_F(SandboxManagerKitTest, StartAccessingByTokenIdTest003, TestSize.Level0)
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
HWTEST_F(SandboxManagerKitTest, UnSetAllPolicyByTokenTest001, TestSize.Level0)
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

/**
 * @tc.name: UnSetAllPolicyByTokenTest002
 * @tc.desc: destroy all mac policy in kernel with given tokenid, sandbox_0400
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, UnSetAllPolicyByTokenTest002, TestSize.Level1)
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

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetAllPolicyByToken(g_mockToken));
    sleep(1);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policys, checkResult));
    ASSERT_EQ(2, checkResult.size());
    EXPECT_FALSE(checkResult[0]);
    EXPECT_FALSE(checkResult[1]);
}

HWTEST_F(SandboxManagerKitTest, TimestampTest001, TestSize.Level0)
{
    SetDeny("/a/b");
    std::vector<PolicyInfo> policyA;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParentA = {
        .path = "/a/b/c",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policyA.emplace_back(infoParentA);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyA, policyFlag, policyResult, 5));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyA, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetAllPolicyByToken(g_mockToken, 4));
    sleep(1);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyA, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetAllPolicyByToken(g_mockToken, 6));
    sleep(1);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyA, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);
}

HWTEST_F(SandboxManagerKitTest, TimestampTest002, TestSize.Level0)
{
    SetDeny("/a/b");
    std::vector<PolicyInfo> policyA;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParentA = {
        .path = "/a/b/c",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policyA.emplace_back(infoParentA);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyA, policyFlag, policyResult, 5));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyA, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetAllPolicyByToken(g_mockToken, 4));
    sleep(1);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyA, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(g_mockToken, policyA, policyFlag, policyResult, 2));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetAllPolicyByToken(g_mockToken, 4));
    sleep(1);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(g_mockToken, policyA, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);
}

HWTEST_F(SandboxManagerKitTest, UserIdTest001, TestSize.Level0)
{
    MacAdapter macAdapter;
    macAdapter.Init();
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> u32Res;
    MacParams macParams;
    macParams.tokenId = 100;
    macParams.policyFlag = 1;
    macParams.timestamp = 0;
    macParams.userId = 100;
    PolicyInfo infoParentA = {
        .path = "/a/b/c",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policy.emplace_back(infoParentA);
    u32Res.resize(policy.size());
    SetDeny("/a/b");
    EXPECT_EQ(SANDBOX_MANAGER_OK, macAdapter.SetSandboxPolicy(policy, u32Res, macParams));
    macParams.tokenId = 101;
    macParams.userId = 101;
    EXPECT_EQ(SANDBOX_MANAGER_OK, macAdapter.SetSandboxPolicy(policy, u32Res, macParams));
    std::vector<bool> boolRes;
    boolRes.resize(policy.size());
    EXPECT_EQ(SANDBOX_MANAGER_OK, macAdapter.QuerySandboxPolicy(100, policy, boolRes));
    EXPECT_TRUE(boolRes[0]);
    EXPECT_EQ(SANDBOX_MANAGER_OK, macAdapter.QuerySandboxPolicy(101, policy, boolRes));
    EXPECT_TRUE(boolRes[0]);
    EXPECT_EQ(SANDBOX_MANAGER_OK, macAdapter.UnSetSandboxPolicyByUser(100, policy, boolRes));
    EXPECT_EQ(SANDBOX_MANAGER_OK, macAdapter.QuerySandboxPolicy(100, policy, boolRes));
    EXPECT_FALSE(boolRes[0]);
    EXPECT_EQ(SANDBOX_MANAGER_OK, macAdapter.QuerySandboxPolicy(101, policy, boolRes));
    EXPECT_TRUE(boolRes[0]);
}

#ifdef DEC_ENABLED
/**
 * @tc.name: ohos.permission.CHECK_SANDBOX_POLICY test001
 * @tc.desc: Permissions required for checking non-self temporary authorization and persistent authorization
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, CheckSandboxPolicyPermissionsTest001, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    const uint32_t tokenId = 123456; // 123456 is a mocked tokenid.
    policy.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(tokenId, policy, policyFlag, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<uint32_t> retType;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(tokenId, policy, retType));
    ASSERT_EQ(1, retType.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(tokenId, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    std::vector<bool> result1;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(tokenId, policy, result1));
    ASSERT_EQ(1, result1.size());
    EXPECT_TRUE(result1[0]);

    Security::AccessToken::AccessTokenID tokenFileManagerID = GetTokenIdFromProcess("file_manager_service");
    EXPECT_NE(0, tokenFileManagerID);
    EXPECT_EQ(0, SetSelfTokenID(tokenFileManagerID));

    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(tokenId, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(tokenId, policy, result1));
    ASSERT_EQ(1, result1.size());
    EXPECT_TRUE(result1[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PhysicalPathDenyTest001
 * @tc.desc: test deny physical path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PhysicalPathDenyTest001, TestSize.Level1)
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

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnSetAllPolicyByToken(g_mockToken));
    dir = opendir(DISTRIBUTE_PATH);
    ASSERT_NE(dir, nullptr);
    closedir(dir);
}

/**
 * @tc.name: PhysicalPathDenyTest002
 * @tc.desc: test deny physical path with invalid mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, PhysicalPathDenyTest002, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo info1 = {
        .path = "/data/service/el1/100/",
        .mode = OperateMode::MAX_MODE
    };

    PolicyInfo info2 = {
        .path = "/data/service/el1/100/",
        .mode = 0
    };
    const uint32_t tokenId = g_mockToken;
    policy.emplace_back(info1);
    policy.emplace_back(info2);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicy(tokenId, policy, policyFlag, policyResult));
    ASSERT_EQ(2, policyResult.size());
    EXPECT_EQ(INVALID_MODE, policyResult[0]);
    EXPECT_EQ(INVALID_MODE, policyResult[1]);
}

#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: SetPolicyByBundleNameTest001
 * @tc.desc: set policy by bundle name, and other basic operations.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, SetPolicyByBundleNameTest001, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParent = {
        .path = "/A/B",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };

    std::string bundleName = "sandbox_manager_test";
    const uint32_t tokenId = g_mockToken;
    ASSERT_NE(tokenId, 0);

    policy.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicyByBundleName(bundleName, 0,
        policy, policyFlag, policyResult));
    ASSERT_EQ(1, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);

    std::vector<uint32_t> retType;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(tokenId, policy, retType));
    ASSERT_EQ(1, retType.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[0]);

    std::vector<bool> result;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(tokenId, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_TRUE(result[0]);

    std::vector<bool> result1;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(tokenId, policy, result1));
    ASSERT_EQ(1, result1.size());
    EXPECT_TRUE(result1[0]);

    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(1, startResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[0]);

    std::vector<uint32_t> unPersistResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::UnPersistPolicy(policy, unPersistResult));
    EXPECT_EQ(1, unPersistResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, unPersistResult[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPolicy(tokenId, policy, result));
    ASSERT_EQ(1, result.size());
    EXPECT_FALSE(result[0]);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::CheckPersistPolicy(tokenId, policy, result1));
    ASSERT_EQ(1, result1.size());
    EXPECT_FALSE(result1[0]);
}

/**
 * @tc.name: SetPolicyByBundleNameTest002
 * @tc.desc: set policy by bundle name with invalid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, SetPolicyByBundleNameTest002, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo info1 = {
        .path = "/A/B",
        .mode = OperateMode::MAX_MODE
    };

    PolicyInfo info2 = {
        .path = "/A/B",
        .mode = 0
    };

    PolicyInfo info3 = {
        .path = "A/B",
        .mode = OperateMode::CREATE_MODE
    };

    std::string bundleName = "sandbox_manager_test";
    const uint32_t tokenId = g_mockToken;
    ASSERT_NE(tokenId, 0);

    policy.emplace_back(info1);
    policy.emplace_back(info2);
    policy.emplace_back(info3);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicyByBundleName(bundleName, 0,
        policy, policyFlag, policyResult));
    ASSERT_EQ(3, policyResult.size());
    EXPECT_EQ(INVALID_MODE, policyResult[0]);
    EXPECT_EQ(INVALID_MODE, policyResult[1]);
    EXPECT_EQ(POLICY_MAC_FAIL, policyResult[2]);

    ASSERT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicyByBundleName(bundleName, 1,
        policy, policyFlag, policyResult));
    ASSERT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicyByBundleName("invalid_bundlename", 0,
        policy, policyFlag, policyResult));
    ASSERT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicyByBundleName(bundleName, 0, policy, 3, policyResult));
    policy.clear();
    ASSERT_EQ(INVALID_PARAMTER, SandboxManagerKit::SetPolicyByBundleName(bundleName, 0,
        policy, policyFlag, policyResult));
}

/**
 * @tc.name: SetPolicyByBundleNameTest003
 * @tc.desc: set and persist with different new modes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitTest, SetPolicyByBundleNameTest003, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    uint64_t policyFlag = 1;
    std::vector<uint32_t> policyResult;
    PolicyInfo info1 = {
        .path = "/storage/Users/currentUser/Documents/A.txt",
        .mode = OperateMode::WRITE_MODE | OperateMode::CREATE_MODE
    };

    PolicyInfo info2 = {
        .path = "/storage/Users/currentUser/Documents/B.txt",
        .mode = OperateMode::READ_MODE | OperateMode::CREATE_MODE
    };

    std::string bundleName = "sandbox_manager_test";
    const uint32_t tokenId = g_mockToken;
    ASSERT_NE(tokenId, 0);

    policy.emplace_back(info1);
    policy.emplace_back(info2);

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::SetPolicyByBundleName(bundleName, 0,
        policy, policyFlag, policyResult));
    ASSERT_EQ(2, policyResult.size());
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[1]);
    policy[0].mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
    policy[1].mode = OperateMode::READ_MODE;

    std::vector<uint32_t> retType;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::PersistPolicy(tokenId, policy, retType));
    ASSERT_EQ(2, retType.size());
    EXPECT_EQ(FORBIDDEN_TO_BE_PERSISTED, retType[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, retType[1]);

    std::vector<uint32_t> startResult;
    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::StartAccessingPolicy(policy, startResult));
    EXPECT_EQ(2, startResult.size());
    EXPECT_EQ(POLICY_HAS_NOT_BEEN_PERSISTED, startResult[0]);
    EXPECT_EQ(OPERATE_SUCCESSFULLY, startResult[1]);
}
#endif

#endif
} // SandboxManager
} // AccessControl
} // OHOS