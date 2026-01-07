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

#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "generic_values.h"
#include "hap_token_info.h"
#include "policy_field_const.h"
#include "policy_info.h"
#define private public
#include "policy_info_manager.h"
#include "share_files.h"
#undef private
#include "sandbox_manager_const.h"
#include "sandbox_manager_rdb.h"
#include "sandbox_manager_log.h"
#include "sandbox_manager_err_code.h"
#include <sys/mount.h>
#include "dec_test.h"
#include "token_setproc.h"
#include "sandbox_test_common.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
const std::string DOWNLOAD_PERMISSION = "ohos.permission.READ_WRITE_DOWNLOAD_DIRECTORY";
const std::string DESKTOP_PERMISSION = "ohos.permission.READ_WRITE_DESKTOP_DIRECTORY";
const std::string DOCUMENTS_PERMISSION = "ohos.permission.READ_WRITE_DOCUMENTS_DIRECTORY";
uint32_t g_mockToken;

Security::AccessToken::PermissionStateFull g_testState1 = {
    .permissionName = DOWNLOAD_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_testState2 = {
    .permissionName = DESKTOP_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_testState3 = {
    .permissionName = DOCUMENTS_PERMISSION,
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
    .permStateList = {g_testState1, g_testState2, g_testState3}
};
};

class PolicyInfoManagerTest : public testing::Test  {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    uint32_t selfTokenId_;
};

static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerRdbTest"
};

#ifdef DEC_ENABLED
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
    auto ret = ioctl(fd, CONSTRAINT_DEC_RULE_CMD, &policyInfo);
    close(fd);
    return ret;
}
#endif

void PolicyInfoManagerTest::SetUpTestCase(void)
{
    // remove all in db
    GenericValues conditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, conditions);
}

void PolicyInfoManagerTest::TearDownTestCase(void)
{
    // remove all in db
    GenericValues conditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, conditions);
}

void PolicyInfoManagerTest::SetUp(void)
{
    selfTokenId_ = 0;
    PolicyInfoManager::GetInstance().Init();
    EXPECT_TRUE(MockTokenId("foundation"));
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
    EXPECT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    g_mockToken = tokenIdEx.tokenIdExStruct.tokenID;
}

void PolicyInfoManagerTest::TearDown(void)
{
    if (PolicyInfoManager::GetInstance().macAdapter_.fd_ > 0) {
        close(PolicyInfoManager::GetInstance().macAdapter_.fd_);
        PolicyInfoManager::GetInstance().macAdapter_.fd_ = -1;
        PolicyInfoManager::GetInstance().macAdapter_.isMacSupport_ = false;
    }
    Security::AccessToken::AccessTokenKit::DeleteToken(g_mockToken);
}

void PrintDbRecords()
{
    GenericValues conditions;
    GenericValues symbols;
    std::vector<GenericValues> dbResult;
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Find(SANDBOX_MANAGER_PERSISTED_POLICY,
        conditions, symbols, dbResult));
    for (size_t i = 0; i < dbResult.size(); i++) {
        int64_t tokenid;
        int64_t mode;
        int64_t depth;
        int64_t flag;
        std::string path;

        tokenid = dbResult[i].GetInt(PolicyFiledConst::FIELD_TOKENID);
        mode = dbResult[i].GetInt(PolicyFiledConst::FIELD_MODE);
        path = dbResult[i].GetString(PolicyFiledConst::FIELD_PATH);
        depth = dbResult[i].GetInt(PolicyFiledConst::FIELD_DEPTH);
        flag = dbResult[i].GetInt(PolicyFiledConst::FIELD_FLAG);

        SANDBOXMANAGER_LOG_INFO(LABEL,
            "tokenid:%{public}" PRIu64"-mode:%{public}" PRIu64
            "-depth:%{public}" PRId64"-path:%{public}s-flag:%{public}" PRId64,
            tokenid, mode, depth, path.c_str(), flag);
    }
}

#ifdef DEC_ENABLED
/**
 * @tc.name: PolicyInfoManagerTest002
 * @tc.desc: Test AddPolicy - normal cases
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest002, TestSize.Level0)
{
    PolicyInfo info;
    uint64_t sizeLimit = 1;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = "/data/log";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);

    std::vector<uint32_t> result11;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, result11));
    EXPECT_EQ(sizeLimit, result11.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, result11[0]);

    // add duplicate policy
    info.path = "/data/log/";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> result12;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, result12));
    EXPECT_EQ(sizeLimit, result12.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, result12[0]);

    // add duplicate policy with diff mode
    info.path = "/data/log";
    info.mode = OperateMode::READ_MODE;
    policy[0] = info;
    std::vector<uint32_t> result13;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, result13));
    EXPECT_EQ(sizeLimit, result13.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, result13[0]);
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY,
        PolicyInfoManager::GetInstance().UnSetAllPolicyByToken(selfTokenId_));

    PrintDbRecords();
    // db should have result9, result10, result11, result13
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PolicyInfoManagerTest003
 * @tc.desc: Test AddPolicy - block list path cases
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest003, TestSize.Level0)
{
    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = "/storage/Users/currentUser/appdata";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::INVALID_PATH, setResult[0]);

    info.path = "/storage/Users/currentUser/appdata/el1";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy[0] = info;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::INVALID_PATH, setResult[0]);

    info.path = "/storage/Users/currentUser/appdata/el1/a";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy[0] = info;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::INVALID_PATH, setResult[0]);

    info.path = "/storage/Users/currentUser/appdata/el1/a/b";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy[0] = info;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PolicyInfoManagerTest004
 * @tc.desc: Test AddPolicy - block list path traversal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest004, TestSize.Level0)
{
    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> setResult;

    info.path = "/storage";
    policy[0] = info;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
    EXPECT_EQ(SandboxRetType::INVALID_PATH, setResult[0]);

    info.path = "/storage/a";
    policy[0] = info;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
    EXPECT_EQ(SandboxRetType::INVALID_PATH, setResult[0]);

    info.path = "/storage/a/b";
    policy[0] = info;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);

    info.path = "/storage/Users/a";
    policy[0] = info;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
    EXPECT_EQ(SandboxRetType::INVALID_PATH, setResult[0]);

    info.path = "/storage/Users/currentUser";
    policy[0] = info;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);

    info.path = "/storage/Users/currentUser/a";
    policy[0] = info;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);

    info.path = "/storage/Users/currentUser/appdata";
    policy[0] = info;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
    EXPECT_EQ(SandboxRetType::INVALID_PATH, setResult[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: PolicyInfoManagerTest005
 * @tc.desc: Test MatchPolicy - normal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest005, TestSize.Level0)
{
    PolicyInfo info;
    uint64_t sizeLimit = 1;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = "/data/log";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> result11;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().MatchPolicy(selfTokenId_, policy, result11));
    EXPECT_EQ(sizeLimit, result11.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, result11[0]);

    info.path = "/data/log/";
    info.mode = OperateMode::READ_MODE;
    policy[0] = info;
    std::vector<uint32_t> result12;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().MatchPolicy(selfTokenId_, policy, result12));
    EXPECT_EQ(sizeLimit, result12.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, result12[0]);

    info.path = "/data/log";
    info.mode = OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> result13;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().MatchPolicy(selfTokenId_, policy, result13));
    EXPECT_EQ(sizeLimit, result13.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, result13[0]);

    info.path = "/data/log/hilog";
    info.mode = OperateMode::READ_MODE;
    policy[0] = info;
    std::vector<uint32_t> result14;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().MatchPolicy(selfTokenId_, policy, result14));
    EXPECT_EQ(sizeLimit, result14.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, result14[0]);
}
#endif

/**
 * @tc.name: PolicyInfoManagerTest006
 * @tc.desc: Test RemoveBundlePolicy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest006, TestSize.Level0)
{
    EXPECT_EQ(true, PolicyInfoManager::GetInstance().RemoveBundlePolicy(selfTokenId_));

    PolicyInfo info = {
        .path = "/data/log",
        .mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE,
    };
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);
    std::vector<uint32_t> result;
    uint64_t sizeLimit = 1;

    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().MatchPolicy(selfTokenId_, policy, result));
    EXPECT_EQ(sizeLimit, result.size());
    EXPECT_EQ(SandboxRetType::POLICY_HAS_NOT_BEEN_PERSISTED, result[0]);
}

/**
 * @tc.name: PolicyInfoManagerTest007
 * @tc.desc: Test RemoveBundlePolicy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest007, TestSize.Level0)
{
    PolicyInfo searchPolicy {
        .path = "/test/",
        .mode = 0b01,
    };
    PolicyInfo referPolicy {
        .path = "/testa/testb",
        .mode = 0b01,
    };
    int64_t searchDepth = PolicyInfoManager::GetInstance().GetDepth(searchPolicy.path);
    int64_t referDepth = PolicyInfoManager::GetInstance().GetDepth(referPolicy.path);
    ASSERT_TRUE(searchDepth < referDepth);

    EXPECT_FALSE(PolicyInfoManager::GetInstance().IsPolicyMatch(
        searchPolicy, searchDepth, referPolicy, referDepth));
}

/**
 * @tc.name: PolicyInfoManagerTest008
 * @tc.desc: Test CheckPathIsBlocked
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest008, TestSize.Level0)
{
    std::string path1 = "/storage/Users/currentUser/appdata";
    std::string path2 = "/storage/Users/currentUser/appdata/el1";
    std::string path3 = "/storage/Users/currentUser/appdata/el6";
    std::string path4 = "/storage/Users/currentUser/appdata/test";
    std::string path5 = "/storage/Users/currentUser/appdata/el1/base";
    std::string path6 = "/storage/Users/currentUser/appdata/el6/test";
    std::string path7 = "/storage/Users/currentUser/appdata/el1/base/test";
    std::string path8 = "/storage/Users/currentUser/appdata/";

    PolicyInfo policy;
    int32_t useId;
    policy.path = path1;
    EXPECT_EQ(SandboxRetType::INVALID_PATH, PolicyInfoManager::GetInstance().CheckPathIsBlocked(0, useId, policy));
    policy.path = path2;
    EXPECT_EQ(SandboxRetType::INVALID_PATH, PolicyInfoManager::GetInstance().CheckPathIsBlocked(0, useId, policy));
    policy.path = path3;
    EXPECT_EQ(SandboxRetType::INVALID_PATH, PolicyInfoManager::GetInstance().CheckPathIsBlocked(0, useId, policy));
    policy.path = path4;
    EXPECT_EQ(SandboxRetType::INVALID_PATH, PolicyInfoManager::GetInstance().CheckPathIsBlocked(0, useId, policy));
    policy.path = path5;
    EXPECT_EQ(SandboxRetType::INVALID_PATH, PolicyInfoManager::GetInstance().CheckPathIsBlocked(0, useId, policy));
    policy.path = path6;
    EXPECT_EQ(SandboxRetType::INVALID_PATH, PolicyInfoManager::GetInstance().CheckPathIsBlocked(0, useId, policy));
    policy.path = path7;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().CheckPathIsBlocked(0, useId, policy));
    policy.path = path8;
    EXPECT_EQ(SandboxRetType::INVALID_PATH, PolicyInfoManager::GetInstance().CheckPathIsBlocked(0, useId, policy));
}

/**
 * @tc.name: PolicyInfoManagerTest009
 * @tc.desc: Test CheckPathIsBlocked
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest009, TestSize.Level0)
{
    std::string path1 = "/storage/Users/currentUser/appdata";
    std::string path2 = "/storage/Users/currentUser/appdata/el1/base/com.test";
    std::string path3 = "/storage/Users/currentUser/appdata/el1/base/com.test";
    std::string path4 = "/storage/Users/currentUser/appdata/el1/base/com.test";
    std::string path5 = "/storage/Users/currentUser/appdata/el1/base/com.test";
    std::string path6 = "/storage/Users/currentUser/appdata/el1/base/com.test";
    std::string path7 = "/storage/Users/currentUser/appdata/el1/base/com.test";
    std::string path8 = "/storage/Users/currentUser/appdata/el1/base/com.test/a";

    PolicyInfo policy;
    int32_t useId;
    policy.path = path1;
    policy.type = PolicyType::SELF_PATH;
    EXPECT_EQ(SandboxRetType::INVALID_PATH,
        PolicyInfoManager::GetInstance().CheckPathIsBlocked(0, useId, policy));
    policy.path = path2;
    policy.type = PolicyType::SELF_PATH;
    EXPECT_EQ(SandboxRetType::INVALID_PATH,
        PolicyInfoManager::GetInstance().CheckPathIsBlocked(0, useId, policy));
    policy.path = path3;
    policy.type = PolicyType::UNKNOWN;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().CheckPathIsBlocked(0, useId, policy, "com.test"));
    policy.path = path4;
    policy.type = PolicyType::UNKNOWN;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().CheckPathIsBlocked(0, useId, policy, ""));
    policy.path = path5;
    policy.type = PolicyType::SELF_PATH;
    EXPECT_EQ(SandboxRetType::INVALID_PATH,
        PolicyInfoManager::GetInstance().CheckPathIsBlocked(0, useId, policy, "com.testt"));
    policy.path = path6;
    policy.type = PolicyType::SELF_PATH;
    EXPECT_EQ(SandboxRetType::INVALID_PATH,
        PolicyInfoManager::GetInstance().CheckPathIsBlocked(0, useId, policy, ""));
    policy.path = path7;
    policy.type = PolicyType::SELF_PATH;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().CheckPathIsBlocked(0, useId, policy, "com.test"));
    policy.path = path8;
    policy.type = PolicyType::SELF_PATH;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().CheckPathIsBlocked(g_mockToken, useId, policy, "com.test"));
}

/**
 * @tc.name: PolicyInfoManagerTest011
 * @tc.desc: Test CheckPolicyValidity
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest011, TestSize.Level0)
{
    PolicyInfo err1 {
        .path = "",
        .mode = 0b10,
    };
    PolicyInfo err2 {
        .path = std::string(POLICY_PATH_LIMIT + 1, '0'),
        .mode = 0b11,
    };
    PolicyInfo err3 {
        .path = "test",
        .mode = 0xff,
    };
    PolicyInfo err4 {
        .path = "test",
        .mode = 0b00,
    };
    EXPECT_EQ(SandboxRetType::INVALID_PATH, PolicyInfoManager::GetInstance().CheckPolicyValidity(err1));
    EXPECT_EQ(SandboxRetType::INVALID_PATH, PolicyInfoManager::GetInstance().CheckPolicyValidity(err2));
    EXPECT_EQ(SandboxRetType::INVALID_MODE, PolicyInfoManager::GetInstance().CheckPolicyValidity(err3));
    EXPECT_EQ(SandboxRetType::INVALID_MODE, PolicyInfoManager::GetInstance().CheckPolicyValidity(err4));
}

#ifdef DEC_ENABLED
/**
 * @tc.name: PolicyInfoManagerTest014
 * @tc.desc: Test single mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest014, TestSize.Level0)
{
    std::vector<std::pair<OperateMode, SandboxRetType>> tests = {
        {OperateMode::READ_MODE, SandboxRetType::OPERATE_SUCCESSFULLY},
        {OperateMode::WRITE_MODE, SandboxRetType::OPERATE_SUCCESSFULLY},
        {OperateMode::RENAME_MODE, SandboxRetType::OPERATE_SUCCESSFULLY},
        {OperateMode::DELETE_MODE, SandboxRetType::OPERATE_SUCCESSFULLY},
    };

    for (const auto &[mode, expectRet] : tests) {
        PolicyInfo info {
            .path = "/data/test/single_mode",
            .mode = mode
        };

        std::vector<PolicyInfo> policy;
        policy.emplace_back(info);
        std::vector<uint32_t> setResult;
        EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
        ASSERT_EQ(1, setResult.size());
        EXPECT_EQ(expectRet, setResult[0]);

        std::vector<uint32_t> addResult;
        EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, addResult));
        ASSERT_EQ(1, addResult.size());
        EXPECT_EQ(expectRet, addResult[0]);

        std::vector<uint32_t> matchResult;
        EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().MatchPolicy(selfTokenId_, policy, matchResult));
        ASSERT_EQ(1, matchResult.size());
        EXPECT_EQ(expectRet, matchResult[0]);

        PolicyInfoManager::GetInstance().UnSetAllPolicyByToken(selfTokenId_);
    }
}

/**
 * @tc.name: PolicyInfoManagerTest015
 * @tc.desc: Test combined mode and subset matching
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest015, TestSize.Level0)
{
    PolicyInfo baseInfo {
        .path = "/data/test/single_mode",
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    std::vector<PolicyInfo> basePolicy;
    basePolicy.emplace_back(baseInfo);
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, basePolicy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SANDBOX_MANAGER_OK, setResult[0]);

    std::vector<uint32_t> addResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, basePolicy, addResult));
    ASSERT_EQ(1, addResult.size());
    EXPECT_EQ(SANDBOX_MANAGER_OK, addResult[0]);

    PolicyInfo info {
        .path = "/data/test/single_mode",
        .mode = OperateMode::READ_MODE | OperateMode::CREATE_MODE
    };

    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);
    std::vector<uint32_t> matchResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().MatchPolicy(selfTokenId_, policy, matchResult));
    ASSERT_EQ(1, matchResult.size());
    EXPECT_EQ(SandboxRetType::POLICY_HAS_NOT_BEEN_PERSISTED, matchResult[0]);

    PolicyInfoManager::GetInstance().UnSetAllPolicyByToken(selfTokenId_);
}

/**
 * @tc.name: PolicyInfoManagerTest016
 * @tc.desc: Test invalid mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest016, TestSize.Level0) {
    std::vector<OperateMode> invalidModes = {
        static_cast<OperateMode>(0),
        static_cast<OperateMode>(MAX_MODE * 2),
        static_cast<OperateMode>(~0ULL),
        static_cast<OperateMode>(OperateMode::READ_MODE | (1 << 20)),
    };

    for (const auto& mode : invalidModes) {
        PolicyInfo info {
            .path = "/data/test/invalid_mode",
            .mode = mode
        };

        std::vector<PolicyInfo> policy;
        policy.emplace_back(info);
        std::vector<uint32_t> setResult;
        std::vector<uint32_t> addResult;

        EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
        ASSERT_EQ(1, setResult.size());
        EXPECT_EQ(SandboxRetType::INVALID_MODE, setResult[0]);

        EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, addResult));
        ASSERT_EQ(1, addResult.size());
        EXPECT_EQ(SandboxRetType::INVALID_MODE, addResult[0]);
    }
}

/**
 * @tc.name: PolicyInfoManagerTest017
 * @tc.desc: Test batch add policies and repeated mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest017, TestSize.Level0)
{
    PolicyInfo info1 {
        .path = "/data/test",
        .mode = OperateMode::READ_MODE
    };

    PolicyInfo info2 {
        .path = "/data/test",
        .mode = OperateMode::WRITE_MODE
    };

    PolicyInfo info3 {
        .path = "/storage/Users/currentUser/appdata/a/b",
        .mode = OperateMode::READ_MODE
    };

    std::vector<PolicyInfo> policy;
    policy.emplace_back(info1);
    policy.emplace_back(info2);
    policy.emplace_back(info3);
    std::vector<uint32_t> setResult;
    std::vector<uint32_t> addResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
    ASSERT_EQ(3, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[1]);
    EXPECT_EQ(SandboxRetType::INVALID_PATH, setResult[2]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, addResult));
    ASSERT_EQ(3, addResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, addResult[0]);
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, addResult[1]);
    EXPECT_EQ(SandboxRetType::FORBIDDEN_TO_BE_PERSISTED, addResult[2]);

    PolicyInfo infoRW = {
        .path = "/data/test",
        .mode = OperateMode::WRITE_MODE | OperateMode::READ_MODE
    };
    std::vector<PolicyInfo> policyRW;
    policyRW.emplace_back(infoRW);

    std::vector<uint32_t> matchRes1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().MatchPolicy(selfTokenId_, policyRW, matchRes1));
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, matchRes1[0]);

    PolicyInfoManager::GetInstance().UnSetAllPolicyByToken(selfTokenId_);
}

/**
 * @tc.name: PolicyInfoManagerTest018
 * @tc.desc: Test add r and w and del mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest018, TestSize.Level0)
{
    PolicyInfo infoR {
        .path = "/data/log",
        .mode = OperateMode::READ_MODE
    };

    PolicyInfo infoW {
        .path = "/data/log",
        .mode = OperateMode::WRITE_MODE
    };

    std::vector<PolicyInfo> policy;
    policy.emplace_back(infoR);
    policy.emplace_back(infoW);

    std::vector<uint32_t> setResult;
    std::vector<uint32_t> addResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
    ASSERT_EQ(2, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[1]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, addResult));
    ASSERT_EQ(2, addResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, addResult[0]);
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, addResult[1]);

    std::vector<PolicyInfo> policyR;
    policyR.emplace_back(infoR);
    std::vector<PolicyInfo> policyW;
    policyW.emplace_back(infoW);

    std::vector<uint32_t> u32Res;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().RemovePolicy(selfTokenId_, policyR, u32Res));
    ASSERT_EQ(1, u32Res.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, u32Res[0]);

    std::vector<uint32_t> matchRes1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().MatchPolicy(selfTokenId_, policyW, matchRes1));
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, matchRes1[0]);

    PolicyInfoManager::GetInstance().UnSetAllPolicyByToken(selfTokenId_);
}

/**
 * @tc.name: PolicyInfoManagerTest019
 * @tc.desc: Test add rw and del mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest019, TestSize.Level0)
{
    PolicyInfo infoR {
        .path = "/data/Test019",
        .mode = OperateMode::READ_MODE
    };

    PolicyInfo infoW {
        .path = "/data/Test019",
        .mode = OperateMode::WRITE_MODE
    };

    std::vector<PolicyInfo> policy;
    policy.emplace_back(infoR);
    policy.emplace_back(infoW);

    std::vector<uint32_t> setResult;
    std::vector<uint32_t> addResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
    ASSERT_EQ(2, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[1]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, addResult));
    ASSERT_EQ(2, addResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, addResult[0]);
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, addResult[1]);

    std::vector<PolicyInfo> policyWR;
    policyWR.emplace_back(infoR);
    policyWR.emplace_back(infoW);

    std::vector<uint32_t> u32Res;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().RemovePolicy(selfTokenId_, policyWR, u32Res));
    ASSERT_EQ(2, u32Res.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, u32Res[0]);

    std::vector<PolicyInfo> policyW;
    policyW.emplace_back(infoW);
    std::vector<uint32_t> matchRes1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().MatchPolicy(selfTokenId_, policyW, matchRes1));
    EXPECT_EQ(SandboxRetType::POLICY_HAS_NOT_BEEN_PERSISTED, matchRes1[0]);

    PolicyInfoManager::GetInstance().UnSetAllPolicyByToken(selfTokenId_);
}

/**
 * @tc.name: PolicyInfoManagerTest020
 * @tc.desc: Test add rw and del mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest020, TestSize.Level0)
{
    PolicyInfo infoR {
        .path = "/data/Test020",
        .mode = OperateMode::READ_MODE
    };

    PolicyInfo infoW {
        .path = "/data/Test020",
        .mode = OperateMode::WRITE_MODE
    };

    std::vector<PolicyInfo> policy;
    policy.emplace_back(infoR);
    policy.emplace_back(infoW);

    std::vector<uint32_t> setResult;
    std::vector<uint32_t> addResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
    ASSERT_EQ(2, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[1]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, addResult));
    ASSERT_EQ(2, addResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, addResult[0]);
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, addResult[1]);

    std::vector<PolicyInfo> policyWR;
    policyWR.emplace_back(infoR);
    policyWR.emplace_back(infoW);

    std::vector<uint32_t> u32Res;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().RemovePolicy(selfTokenId_, policyWR, u32Res));
    ASSERT_EQ(2, u32Res.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, u32Res[0]);

    std::vector<PolicyInfo> policyR;
    policyR.emplace_back(infoW);
    std::vector<uint32_t> matchRes1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().MatchPolicy(selfTokenId_, policyR, matchRes1));
    EXPECT_EQ(SandboxRetType::POLICY_HAS_NOT_BEEN_PERSISTED, matchRes1[0]);

    PolicyInfoManager::GetInstance().UnSetAllPolicyByToken(selfTokenId_);
}

/**
 * @tc.name: PolicyInfoManagerTest021
 * @tc.desc: Test add rw and del mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest021, TestSize.Level0)
{
    PolicyInfo infoR {
        .path = "/data/Test021",
        .mode = OperateMode::READ_MODE
    };

    PolicyInfo infoW {
        .path = "/data/Test021",
        .mode = OperateMode::WRITE_MODE
    };

    PolicyInfo infoWR {
        .path = "/data/Test021",
        .mode = OperateMode::WRITE_MODE | READ_MODE
    };

    std::vector<PolicyInfo> policy;
    policy.emplace_back(infoWR);

    std::vector<uint32_t> setResult;
    std::vector<uint32_t> addResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, addResult));
    ASSERT_EQ(1, addResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, addResult[0]);

    std::vector<PolicyInfo> policyR;
    policyR.emplace_back(infoR);
    std::vector<PolicyInfo> policyW;
    policyW.emplace_back(infoW);

    std::vector<uint32_t> u32Res;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().RemovePolicy(selfTokenId_, policyW, u32Res));
    ASSERT_EQ(1, u32Res.size());
    EXPECT_EQ(SandboxRetType::POLICY_HAS_NOT_BEEN_PERSISTED, u32Res[0]);

    std::vector<uint32_t> matchRes1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().MatchPolicy(selfTokenId_, policyR, matchRes1));
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, matchRes1[0]);

    PolicyInfoManager::GetInstance().UnSetAllPolicyByToken(selfTokenId_);
}

/**
 * @tc.name: PolicyInfoManagerTest022
 * @tc.desc: Test add rw and del mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest022, TestSize.Level0)
{
    PolicyInfo infoR {
        .path = "/data/Test022",
        .mode = OperateMode::READ_MODE
    };

    PolicyInfo infoW {
        .path = "/data/Test022",
        .mode = OperateMode::WRITE_MODE
    };

    PolicyInfo infoWR {
        .path = "/data/Test022",
        .mode = OperateMode::WRITE_MODE | READ_MODE
    };

    std::vector<PolicyInfo> policy;
    policy.emplace_back(infoWR);

    std::vector<uint32_t> setResult;
    std::vector<uint32_t> addResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, addResult));
    ASSERT_EQ(1, addResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, addResult[0]);

    std::vector<PolicyInfo> policyW;
    policyW.emplace_back(infoW);
    std::vector<PolicyInfo> policyWR;
    policyWR.emplace_back(infoWR);

    std::vector<uint32_t> u32Res;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().RemovePolicy(selfTokenId_, policyW, u32Res));
    ASSERT_EQ(1, u32Res.size());
    EXPECT_EQ(SandboxRetType::POLICY_HAS_NOT_BEEN_PERSISTED, u32Res[0]);

    std::vector<uint32_t> matchRes1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().MatchPolicy(selfTokenId_, policyWR, matchRes1));
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, matchRes1[0]);

    PolicyInfoManager::GetInstance().UnSetAllPolicyByToken(selfTokenId_);
}

/**
 * @tc.name: PolicyInfoManagerTest023
 * @tc.desc: Test add rw and del mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest023, TestSize.Level0)
{
    PolicyInfo infoR {
        .path = "/data/log",
        .mode = OperateMode::READ_MODE
    };

    PolicyInfo infoW {
        .path = "/data/log",
        .mode = OperateMode::WRITE_MODE
    };

    PolicyInfo infoWR {
        .path = "/data/log",
        .mode = OperateMode::WRITE_MODE | READ_MODE
    };

    std::vector<PolicyInfo> policy;
    policy.emplace_back(infoW);
    policy.emplace_back(infoWR);

    std::vector<uint32_t> setResult;
    std::vector<uint32_t> addResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
    ASSERT_EQ(2, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[1]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, addResult));
    ASSERT_EQ(2, addResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, addResult[0]);
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, addResult[1]);

    std::vector<PolicyInfo> policyW;
    policyW.emplace_back(infoW);
    std::vector<PolicyInfo> policyWR;
    policyWR.emplace_back(infoWR);

    std::vector<uint32_t> u32Res;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().RemovePolicy(selfTokenId_, policyW, u32Res));
    ASSERT_EQ(1, u32Res.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, u32Res[0]);

    std::vector<uint32_t> matchRes1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().MatchPolicy(selfTokenId_, policyWR, matchRes1));
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, matchRes1[0]);

    PolicyInfoManager::GetInstance().UnSetAllPolicyByToken(selfTokenId_);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: QuerySandboxPolicyTest001
 * @tc.desc: Test AddPolicy with unset flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, QuerySandboxPolicyTest001, TestSize.Level0)
{
    SetDeny("/data/testquery");
    PolicyInfo info;
    uint64_t sizeLimit = 1;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = "/data/testquery";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 0, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);

    std::vector<uint32_t> result11;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(g_mockToken, policy, result11));
    EXPECT_EQ(sizeLimit, result11.size());
    EXPECT_EQ(SandboxRetType::FORBIDDEN_TO_BE_PERSISTED, result11[0]);
}

/**
 * @tc.name: QuerySandboxPolicyTest002
 * @tc.desc: Test AddPolicy with unset flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, QuerySandboxPolicyTest002, TestSize.Level0)
{
    SetDeny("/data/testquery");
    PolicyInfo info;
    uint64_t sizeLimit = 1;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = "/data/testquery";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy[0] = info;

    std::vector<uint32_t> result11;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(g_mockToken, policy, result11));
    EXPECT_EQ(sizeLimit, result11.size());
    EXPECT_EQ(SandboxRetType::FORBIDDEN_TO_BE_PERSISTED, result11[0]);
}

/**
 * @tc.name: QuerySandboxPolicyTest003
 * @tc.desc: Test AddPolicy with unset flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, QuerySandboxPolicyTest003, TestSize.Level0)
{
    PolicyInfo info;
    uint64_t sizeLimit = 1;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = "/storage/Users/currentUser/Download";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy[0] = info;

    std::vector<uint32_t> u32Res;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().UnSetPolicy(g_mockToken, info));

    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 0, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);

    std::vector<uint32_t> result11;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(g_mockToken, policy, result11));
    EXPECT_EQ(sizeLimit, result11.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, result11[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().RemovePolicy(g_mockToken, policy, u32Res));
    ASSERT_EQ(1, u32Res.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, u32Res[0]);
}

/**
 * @tc.name: QuerySandboxPolicyTest004
 * @tc.desc: Test AddPolicy with unset flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, QuerySandboxPolicyTest004, TestSize.Level0)
{
    PolicyInfo info;
    uint64_t sizeLimit = 1;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = "/storage/Users/currentUser/Desktop/child";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 0, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);

    std::vector<uint32_t> result11;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(g_mockToken, policy, result11));
    EXPECT_EQ(sizeLimit, result11.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, result11[0]);

    std::vector<uint32_t> u32Res;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().RemovePolicy(g_mockToken, policy, u32Res));
    ASSERT_EQ(1, u32Res.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, u32Res[0]);
}

/**
 * @tc.name: QuerySandboxPolicyTest005
 * @tc.desc: Test AddPolicy with unset flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, QuerySandboxPolicyTest005, TestSize.Level0)
{
    PolicyInfo info;
    uint64_t sizeLimit = 1;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = "/mnt/data/fuse";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 0, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);

    std::vector<uint32_t> result11;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(g_mockToken, policy, result11));
    EXPECT_EQ(sizeLimit, result11.size());
    EXPECT_EQ(SandboxRetType::FORBIDDEN_TO_BE_PERSISTED, result11[0]);
}

/**
 * @tc.name: QuerySandboxPolicyTest006
 * @tc.desc: Test AddPolicy with unset flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, QuerySandboxPolicyTest006, TestSize.Level0)
{
    PolicyInfo info;

    info.path = "/mnt/data/fuse";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    EXPECT_FALSE(PolicyInfoManager::GetInstance().IsVerifyPermissionPass(g_mockToken, info));
    info.path = "/a/b";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    EXPECT_FALSE(PolicyInfoManager::GetInstance().IsVerifyPermissionPass(g_mockToken, info));
    info.path = "/storage/Users/currentUser/Desktop";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    EXPECT_TRUE(PolicyInfoManager::GetInstance().IsVerifyPermissionPass(g_mockToken, info));
    info.path = "/storage/Users/currentUser/Desktop/child";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    EXPECT_TRUE(PolicyInfoManager::GetInstance().IsVerifyPermissionPass(g_mockToken, info));
    info.path = "/storage/Users/currentUser/Desktop/";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    EXPECT_TRUE(PolicyInfoManager::GetInstance().IsVerifyPermissionPass(g_mockToken, info));
    info.path = "/storage/Users/currentUser/Deskto";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    EXPECT_FALSE(PolicyInfoManager::GetInstance().IsVerifyPermissionPass(g_mockToken, info));
    info.path = "/storage/Users/currentUser/Desktopp";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    EXPECT_FALSE(PolicyInfoManager::GetInstance().IsVerifyPermissionPass(g_mockToken, info));
}
#endif

/**
 * @tc.name: GenericValuesTest001
 * @tc.desc: Test generic_values.cpp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, GenericValuesTest001, TestSize.Level0)
{
    GenericValues conditions;
    int32_t result = -1;
    conditions.Get(PolicyFiledConst::FIELD_TOKENID);
    EXPECT_EQ(result, conditions.GetInt(PolicyFiledConst::FIELD_TOKENID));
    EXPECT_EQ(result, conditions.GetInt64(PolicyFiledConst::FIELD_TOKENID));

    int64_t tokenId = 0;
    conditions.Put(PolicyFiledConst::FIELD_TOKENID, tokenId);
    EXPECT_EQ(tokenId, conditions.GetInt64(PolicyFiledConst::FIELD_TOKENID));
    conditions.Remove(PolicyFiledConst::FIELD_TOKENID);

    VariantValue variantValue;
    EXPECT_EQ(-1, variantValue.GetInt());
    EXPECT_EQ(-1, variantValue.GetInt64());
    std::string str;
    EXPECT_EQ(str, variantValue.GetString());
}

#ifdef DEC_ENABLED
/**
 * @tc.name: CleanPersistPolicyByPathTest001
 * @tc.desc: Test CleanPersistPolicyByPath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, CleanPersistPolicyByPathTest001, TestSize.Level0)
{
    PolicyInfo info;
    uint64_t sizeLimit = 1;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = "/data/log";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);

    std::vector<uint32_t> result11;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, result11));
    EXPECT_EQ(sizeLimit, result11.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, result11[0]);

    std::vector<uint32_t> result13;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().MatchPolicy(selfTokenId_, policy, result13));
    EXPECT_EQ(sizeLimit, result13.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, result13[0]);

    std::vector<std::string> paths;
    paths.emplace_back(info.path);
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().CleanPersistPolicyByPath(paths));

    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().MatchPolicy(selfTokenId_, policy, result13));
    EXPECT_EQ(sizeLimit, result13.size());
    EXPECT_EQ(SandboxRetType::POLICY_HAS_NOT_BEEN_PERSISTED, result13[0]);
}
#endif

/**
 * @tc.name: MacAdapterTest001
 * @tc.desc: Test MacAdapterTest - not inited
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, MacAdapterTest001, TestSize.Level0)
{
    MacAdapter macAdapter;
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> u32Res;
    MacParams macParams;
    macParams.tokenId = selfTokenId_;
    EXPECT_EQ(SANDBOX_MANAGER_MAC_NOT_INIT, macAdapter.SetSandboxPolicy(policy, u32Res, macParams));
    std::vector<bool> boolRes;
    EXPECT_EQ(SANDBOX_MANAGER_MAC_NOT_INIT, macAdapter.QuerySandboxPolicy(selfTokenId_, policy, u32Res));
    EXPECT_EQ(SANDBOX_MANAGER_MAC_NOT_INIT, macAdapter.CheckSandboxPolicy(selfTokenId_, policy, boolRes));
    EXPECT_EQ(SANDBOX_MANAGER_MAC_NOT_INIT, macAdapter.UnSetSandboxPolicy(selfTokenId_, policy, boolRes));
    PolicyInfo info;
    EXPECT_EQ(SANDBOX_MANAGER_MAC_NOT_INIT, macAdapter.UnSetSandboxPolicy(selfTokenId_, info));
    EXPECT_EQ(SANDBOX_MANAGER_MAC_NOT_INIT, macAdapter.DestroySandboxPolicy(selfTokenId_, 0));
}

#ifdef DEC_ENABLED
#ifndef NOT_RESIDENT
/**
 * @tc.name: DenyTest001
 * @tc.desc: Test DenyTest normal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, DenyTest001, TestSize.Level0)
{
    std::string stringJson1 = R"([{"path":"/data/test", "rename":1, "delete":1, "inherit":1}])";
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().macAdapter_.SetDenyCfg(stringJson1));
}

/**
 * @tc.name: DenyTest002
 * @tc.desc: Test DenyTest delete error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, DenyTest002, TestSize.Level0)
{
    std::string stringJson1 = R"([
        {"path":"/etc/test", "rename":1, "delete":"test", "inherit":1}])";
    EXPECT_EQ(SANDBOX_MANAGER_DENY_ERR, PolicyInfoManager::GetInstance().macAdapter_.SetDenyCfg(stringJson1));
}

/**
 * @tc.name: DenyTest003
 * @tc.desc: Test DenyTest rename error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, DenyTest003, TestSize.Level0)
{
    std::string stringJson1 = R"([
        {"path":"/etc/test", "rename":"test", "delete":1, "inherit":1}])";
    EXPECT_EQ(SANDBOX_MANAGER_DENY_ERR, PolicyInfoManager::GetInstance().macAdapter_.SetDenyCfg(stringJson1));
}

/**
 * @tc.name: DenyTest004
 * @tc.desc: Test DenyTest inherit error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, DenyTest004, TestSize.Level0)
{
    std::string stringJson1 = R"([
        {"path":"/etc/test", "rename":1, "delete":1, "inherit":"test"}])";
    EXPECT_EQ(SANDBOX_MANAGER_DENY_ERR, PolicyInfoManager::GetInstance().macAdapter_.SetDenyCfg(stringJson1));
}

/**
 * @tc.name: DenyTest005
 * @tc.desc: Test DenyTest pass error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, DenyTest005, TestSize.Level0)
{
    std::string stringJson1 = R"([
        {"path":1, "rename":1, "delete":1, "inherit":1}])";
    EXPECT_EQ(SANDBOX_MANAGER_DENY_ERR, PolicyInfoManager::GetInstance().macAdapter_.SetDenyCfg(stringJson1));
}

/**
 * @tc.name: DenyTest006
 * @tc.desc: Test DenyTest empty json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, DenyTest006, TestSize.Level0)
{
    std::string stringJson1 = R"([])";
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().macAdapter_.SetDenyCfg(stringJson1));
}

/**
 * @tc.name: DenyTest007
 * @tc.desc: Test DenyTest long json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, DenyTest007, TestSize.Level0)
{
    std::string stringJson1 = R"([
        {"path":"/etc/test", "rename":1, "delete":1, "inherit":1},
        {"path":"/etc/test2", "rename":1, "delete":1, "inherit":1},
        {"path":"/etc/test3", "rename":1, "delete":1, "inherit":1},
        {"path":"/etc/test4", "rename":1, "delete":1, "inherit":1},
        {"path":"/etc/test5", "rename":1, "delete":1, "inherit":1},
        {"path":"/etc/test6", "rename":1, "delete":1, "inherit":1},
        {"path":"/etc/test7", "rename":1, "delete":1, "inherit":1},
        {"path":"/etc/test8", "rename":1, "delete":1, "inherit":1},
        {"path":"/etc/test9", "rename":1, "delete":1, "inherit":1}
    ])";
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().macAdapter_.SetDenyCfg(stringJson1));
}

/**
 * @tc.name: DenyTest008
 * @tc.desc: Test DenyTest json item lost
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, DenyTest008, TestSize.Level0)
{
    std::string stringJson1 = R"([
        {"path":"/etc/test", "delete":1, "inherit":1}])";
    EXPECT_EQ(SANDBOX_MANAGER_DENY_ERR, PolicyInfoManager::GetInstance().macAdapter_.SetDenyCfg(stringJson1));
}

/**
 * @tc.name: DenyTest009
 * @tc.desc: Test DenyTest path error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, DenyTest009, TestSize.Level0)
{
    const char *jsonPath = "etc/sandbox_manager_service/test";
    std::string inputString;
    EXPECT_EQ(SANDBOX_MANAGER_DENY_ERR,
        PolicyInfoManager::GetInstance().macAdapter_.ReadDenyFile(jsonPath, inputString));
}

/**
 * @tc.name: DenyTest010
 * @tc.desc: Test DenyTest path right
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, DenyTest010, TestSize.Level0)
{
    const char *jsonPath = "etc/sandbox/appdata-sandbox.json";
    std::string inputString;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().macAdapter_.ReadDenyFile(jsonPath, inputString));
}
#endif
#endif

#ifdef DEC_ENABLED
#ifndef NOT_RESIDENT
const char *source = "/data/dec";
const char *target = "/data/mntDenyTest";
const char *fsType = "sharefs";
const char *mountData = "override_support_delete,user_id=100";
const char *testPathParent = "/data/mntDenyTest/test1";
const char *testPathChild = "/data/mntDenyTest/test1/a";
const char *testPathChildNew = "/data/mntDenyTest/test1/b";

#define SANDBOX_IOCTL_BASE 's'
#define DEL_DENY_POLICY_ID 10
#define DEL_DENY_DEC_RULE_CMD _IOWR(SANDBOX_IOCTL_BASE, DEL_DENY_POLICY_ID, struct SandboxPolicyInfo)

static int UnSetDeny(const std::string& path)
{
    struct PathInfo info;
    string infoPath = path;
    info.path = const_cast<char *>(infoPath.c_str());
    info.pathLen = infoPath.length();
    info.mode = 0;
    struct SandboxPolicyInfo policyInfo;
    policyInfo.tokenId = 0;
    policyInfo.pathInfos[0] = info;
    policyInfo.pathNum = 1;
    policyInfo.persist = true;
    auto fd = open("/dev/dec", O_RDWR);
    if (fd < 0) {
        std::cout << "fd open err" << std::endl;
        return fd;
    }
    auto ret = ioctl(fd, DEL_DENY_DEC_RULE_CMD, &policyInfo);
    std::cout << "set deny ret: " << ret << std::endl;
    close(fd);
    return ret;
}

/**
 * @tc.name: DenyTest011
 * @tc.desc: Test Deny
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, DenyTest011, TestSize.Level0)
{
    mkdir(source, 0777);
    mkdir(target, 0777);
    ASSERT_EQ(0, mount(source, target, fsType, MS_MGC_VAL, mountData));
    ConstraintPath(target);

    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParent = {
        .path = target,
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    uint32_t token = GetSelfTokenID();
    policy.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(token, policy, 1, policyResult));
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);
    mkdir(testPathParent, 0777);
    mkdir(testPathChild, 0777);
    std::string stringJson1 = R"([{"path":"/data/mntDenyTest/test1/a", "rename":1, "delete":1, "inherit":1}])";
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().macAdapter_.SetDenyCfg(stringJson1));

    ASSERT_NE(0, rename(testPathChild, testPathChildNew));
    UnSetDeny(testPathChild);
    ASSERT_EQ(0, rename(testPathChild, testPathChildNew));
    ASSERT_EQ(0, rmdir(testPathChildNew));
    ASSERT_EQ(0, umount2(target, MNT_DETACH));
    rmdir(testPathParent);
    rmdir(target);
    rmdir(source);
}

/**
 * @tc.name: DenyTest012
 * @tc.desc: Test Deny delete
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, DenyTest012, TestSize.Level0)
{
    mkdir(source, 0777);
    mkdir(target, 0777);
    ASSERT_EQ(0, mount(source, target, fsType, MS_MGC_VAL, mountData));
    ConstraintPath(target);
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParent = {
        .path = target,
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    uint32_t token = GetSelfTokenID();
    policy.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(token, policy, 1, policyResult));
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);
    mkdir(testPathParent, 0777);
    mkdir(testPathChild, 0777);
    std::string stringJson1 = R"([{"path":"/data/mntDenyTest/test1/a", "rename":1, "delete":1, "inherit":1}])";
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().macAdapter_.SetDenyCfg(stringJson1));

    ASSERT_NE(0, rmdir(testPathChild));
    UnSetDeny(testPathChild);
    ASSERT_EQ(0, rmdir(testPathChild));
    ASSERT_EQ(0, umount2(target, MNT_DETACH));
    rmdir(testPathParent);
    rmdir(target);
    rmdir(source);
}

/**
 * @tc.name: DenyTest013
 * @tc.desc: Test Deny inherit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, DenyTest013, TestSize.Level0)
{
    mkdir(source, 0777);
    mkdir(target, 0777);
    ASSERT_EQ(0, mount(source, target, fsType, MS_MGC_VAL, mountData));
    ConstraintPath(target);
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> policyResult;
    PolicyInfo infoParent = {
        .path = target,
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };

    uint32_t token = GetSelfTokenID();
    policy.emplace_back(infoParent);
    ASSERT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(token, policy, 1, policyResult));
    EXPECT_EQ(OPERATE_SUCCESSFULLY, policyResult[0]);
    mkdir(testPathParent, 0777);
    mkdir(testPathChild, 0777);
    std::string stringJson1 = R"([{"path":"/data/mntDenyTest/test1/a", "rename":1, "delete":1, "inherit":1}])";

    std::vector<PolicyInfo> policy2;
    PolicyInfo infochild = {
        .path = testPathChild,
        .mode = OperateMode::READ_MODE | OperateMode::WRITE_MODE
    };
    policy2.emplace_back(infochild);
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().macAdapter_.SetDenyCfg(stringJson1));
    std::vector<bool> boolRes;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().CheckPolicy(token, policy2, boolRes));
    ASSERT_EQ(1, boolRes.size());
    EXPECT_EQ(false, boolRes[0]);

    UnSetDeny(testPathChild);
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().CheckPolicy(token, policy2, boolRes));
    ASSERT_EQ(1, boolRes.size());
    EXPECT_EQ(true, boolRes[0]);

    ASSERT_EQ(0, rmdir(testPathChild));
    ASSERT_EQ(0, umount2(target, MNT_DETACH));
    rmdir(testPathParent);
    rmdir(target);
    rmdir(source);
}
#endif
#endif

/**
 * @tc.name: MaskRealPath001
 * @tc.desc: normal path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, MaskRealPath001, TestSize.Level0)
{
    std::string input1 = "/aa/bb/cc/dd.txt";
    std::string expect = "/a***/b***/c***/d***";
    std::string path = SandboxManagerLog::MaskRealPath(input1.c_str());
    EXPECT_EQ(true, expect == path);
}

/**
 * @tc.name: MaskRealPath002
 * @tc.desc: normal path short name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, MaskRealPath002, TestSize.Level0)
{
    std::string input1 = "/aa/bb/cc/d.txt";
    std::string expect = "/a***/b***/c***/d***";
    std::string path = SandboxManagerLog::MaskRealPath(input1.c_str());
    EXPECT_EQ(true, expect == path);
}

/**
 * @tc.name: MaskRealPath003
 * @tc.desc: short path  and short name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, MaskRealPath003, TestSize.Level0)
{
    std::string input1 = "/aa/dd.txt";
    std::string expect = "/a***/d***";
    std::string path = SandboxManagerLog::MaskRealPath(input1.c_str());
    EXPECT_EQ(true, expect == path);
}

/**
 * @tc.name: MaskRealPath004
 * @tc.desc: path with more '/'
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, MaskRealPath004, TestSize.Level0)
{
    std::string input1 = "/aa/////bb/cc/dd.txt";
    std::string expect = "/a***/////b***/c***/d***";
    std::string path = SandboxManagerLog::MaskRealPath(input1.c_str());
    EXPECT_EQ(true, expect == path);
}

/**
 * @tc.name: MaskRealPath005
 * @tc.desc: path begin without '/'
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, MaskRealPath005, TestSize.Level0)
{
    std::string input1 = "aa/bb";
    std::string expect = "a***/b***";
    std::string path = SandboxManagerLog::MaskRealPath(input1.c_str());
    EXPECT_EQ(true, expect == path);
}

/**
 * @tc.name: MaskRealPath006
 * @tc.desc: path without info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, MaskRealPath006, TestSize.Level0)
{
    std::string input1 = "";
    std::string expect = "empty path";
    std::string path = SandboxManagerLog::MaskRealPath(input1.c_str());
    EXPECT_EQ(true, expect == path);
}

/**
 * @tc.name: MaskRealPath007
 * @tc.desc: path only '/'
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, MaskRealPath007, TestSize.Level0)
{
    std::string input1 = "/";
    std::string expect = "/";
    std::string path = SandboxManagerLog::MaskRealPath(input1.c_str());
    EXPECT_EQ(true, expect == path);
}

/**
 * @tc.name: MaskRealPath008
 * @tc.desc: path only '.'
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, MaskRealPath008, TestSize.Level0)
{
    std::string input1 = ".";
    std::string expect = ".";
    std::string path = SandboxManagerLog::MaskRealPath(input1.c_str());
    EXPECT_EQ(true, expect == path);
}

/**
 * @tc.name: MaskRealPath009
 * @tc.desc: path start with '.'
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, MaskRealPath009, TestSize.Level0)
{
    std::string input1 = "/./test";
    std::string expect = "/./t***";
    std::string path = SandboxManagerLog::MaskRealPath(input1.c_str());
    EXPECT_EQ(true, expect == path);
}

/**
 * @tc.name: MaskRealPath010
 * @tc.desc: path start with '..'
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, MaskRealPath010, TestSize.Level0)
{
    std::string input1 = "/../test";
    std::string expect = "/../t***";
    std::string path = SandboxManagerLog::MaskRealPath(input1.c_str());
    EXPECT_EQ(true, expect == path);
}

/**
 * @tc.name: MaskRealPath011
 * @tc.desc: path with '.'
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, MaskRealPath011, TestSize.Level0)
{
    std::string input1 = "/aa/../d.txt";
    std::string expect = "/a***/../d***";
    std::string path = SandboxManagerLog::MaskRealPath(input1.c_str());
    EXPECT_EQ(true, expect == path);
}

/**
 * @tc.name: MaskRealPath012
 * @tc.desc: path with '.' and ".."
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, MaskRealPath012, TestSize.Level0)
{
    std::string input1 = "/aa/.././bb/cc/dd.txt";
    std::string expect = "/a***/.././b***/c***/d***";
    std::string path = SandboxManagerLog::MaskRealPath(input1.c_str());
    EXPECT_EQ(true, expect == path);
}

/**
 * @tc.name: MaskRealPath013
 * @tc.desc: file name with more '.'
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, MaskRealPath013, TestSize.Level0)
{
    std::string input1 = "/aa/.././cc/aa.bb.txt";
    std::string expect = "/a***/.././c***/a***";
    std::string path = SandboxManagerLog::MaskRealPath(input1.c_str());
    EXPECT_EQ(true, expect == path);
}

/**
 * @tc.name: MaskRealPath014
 * @tc.desc: file name start with '.'
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, MaskRealPath014, TestSize.Level0)
{
    std::string input1 = "/aa/.././cc/.aa.bb.txt";
    std::string expect = "/a***/.././c***/.***";
    std::string path = SandboxManagerLog::MaskRealPath(input1.c_str());
    EXPECT_EQ(true, expect == path);
}

/**
 * @tc.name: MaskRealPath015
 * @tc.desc: path end with one '/'
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, MaskRealPath015, TestSize.Level0)
{
    std::string input1 = "/aa/.././cc/";
    std::string expect = "/a***/.././c***/";
    std::string path = SandboxManagerLog::MaskRealPath(input1.c_str());
    EXPECT_EQ(true, expect == path);
}

/**
 * @tc.name: MaskRealPath016
 * @tc.desc: path end with more '/'
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, MaskRealPath016, TestSize.Level0)
{
    std::string input1 = "/aa/////";
    std::string expect = "/a***/////";
    std::string path = SandboxManagerLog::MaskRealPath(input1.c_str());
    EXPECT_EQ(true, expect == path);
}

/**
 * @tc.name: PolicyInfoManagerTest012
 * @tc.desc: Test PolicyInfoManager - MAC not supported
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest012, TestSize.Level0)
{
    MacAdapter original = PolicyInfoManager::GetInstance().macAdapter_;
    MacAdapter mockMacAdapter;
    PolicyInfoManager::GetInstance().macAdapter_ = mockMacAdapter;
    std::vector<PolicyInfo> policy;
    PolicyInfo info;
    info.path = "/data/log";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy.emplace_back(info);
    uint32_t flag = 0;
    std::vector<uint32_t> u32Res;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, u32Res, flag));
    ASSERT_EQ(1, u32Res.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, u32Res[0]);

    u32Res.resize(0);
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().RemovePolicy(selfTokenId_, policy, u32Res));
    ASSERT_EQ(1, u32Res.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, u32Res[0]);

    u32Res.resize(0);
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().SetPolicy(selfTokenId_, policy, static_cast<uint64_t>(flag), u32Res));
    ASSERT_EQ(1, u32Res.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, u32Res[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().UnSetPolicy(selfTokenId_, info));

    std::vector<bool> boolRes;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().CheckPolicy(selfTokenId_, policy, boolRes));
    ASSERT_EQ(1, boolRes.size());
    EXPECT_EQ(true, boolRes[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().StartAccessingByTokenId(selfTokenId_));

    u32Res.resize(0);
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().StartAccessingPolicy(selfTokenId_, policy, u32Res));
    ASSERT_EQ(1, u32Res.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, u32Res[0]);

    u32Res.resize(0);
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().StopAccessingPolicy(selfTokenId_, policy, u32Res));
    ASSERT_EQ(1, u32Res.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, u32Res[0]);

    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().UnSetAllPolicyByToken(selfTokenId_));

    PolicyInfoManager::GetInstance().macAdapter_ = original;
    original = mockMacAdapter;
}

#ifdef DEC_ENABLED
#ifdef NOT_RESIDENT
HWTEST_F(PolicyInfoManagerTest, ShareTest001, TestSize.Level0)
{
    std::string stringJson1 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ]
        }
    })";

    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    const std::string path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/files";
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson1, bundleName, userId));
    EXPECT_EQ((OperateMode::READ_MODE | OperateMode::WRITE_MODE),
        SandboxManagerShare::GetInstance().FindPermission(bundleName, userId, path));
}

HWTEST_F(PolicyInfoManagerTest, ShareTest002, TestSize.Level0)
{
    std::string stringJson1 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/haps",
                    "permission": "r"
                }
            ]
        }
    })";

    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    const std::string path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/haps";
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson1, bundleName, userId));
    EXPECT_EQ(OperateMode::READ_MODE, SandboxManagerShare::GetInstance().FindPermission(bundleName, userId, path));
}

HWTEST_F(PolicyInfoManagerTest, ShareTest003, TestSize.Level0)
{
    std::string stringJson1 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/test1",
                }
            ]
        }
    })";

    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    const std::string path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/test1";
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson1, bundleName, userId));
    EXPECT_EQ(ShareStatus::SHARE_PATH_UNSET,
        SandboxManagerShare::GetInstance().FindPermission(bundleName, userId, path));
    std::string stringJson2 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/test/test1",
                }
            ]
        }
    })";
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson2, bundleName, userId));
    EXPECT_EQ(ShareStatus::SHARE_PATH_UNSET,
        SandboxManagerShare::GetInstance().FindPermission(bundleName, userId, path));
}

HWTEST_F(PolicyInfoManagerTest, ShareTest004, TestSize.Level0)
{
    std::string stringJson1 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ]
        }
    })";

    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    const std::string path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/files";
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson1, bundleName, userId));
    EXPECT_EQ((OperateMode::READ_MODE | OperateMode::WRITE_MODE),
        SandboxManagerShare::GetInstance().FindPermission(bundleName, userId, path));
    SandboxManagerShare::GetInstance().DeleteByBundleName(bundleName);
    EXPECT_EQ(ShareStatus::SHARE_BUNDLE_UNSET,
        SandboxManagerShare::GetInstance().FindPermission(bundleName, userId, path));
}

HWTEST_F(PolicyInfoManagerTest, ShareTest005, TestSize.Level0)
{
    std::string stringJson1 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ]
        }
    })";

    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    const std::string path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/files";
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson1, bundleName, userId));

    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/files";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);
}

HWTEST_F(PolicyInfoManagerTest, ShareTest006, TestSize.Level0)
{
    std::string stringJson1 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ]
        }
    })";

    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    const std::string path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/files";
    SandboxManagerShare::GetInstance().DeleteByBundleName(bundleName);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson1, bundleName, userId));

    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/test2";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::INVALID_PATH, setResult[0]);
}

HWTEST_F(PolicyInfoManagerTest, ShareTest007, TestSize.Level0)
{
    std::string stringJson1 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ]
        }
    })";

    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    const std::string path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/files";
    SandboxManagerShare::GetInstance().DeleteByBundleName(bundleName);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson1, bundleName, userId));

    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    SetInfo setInfo;
    setInfo.bundleName = "com.testshare";
    info.path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/files";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    info.type = PolicyType::SELF_PATH;
    policy[0] = info;
    std::vector<uint32_t> result;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 1, result, setInfo));
    ASSERT_EQ(1, result.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, result[0]);
}

HWTEST_F(PolicyInfoManagerTest, ShareTest008, TestSize.Level0)
{
    std::string stringJson1 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ]
        }
    })";
    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    const std::string path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/files";
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson1, bundleName, userId));

    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    SetInfo setInfo;
    setInfo.bundleName = "com.testshare";
    info.path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/test2";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    info.type = PolicyType::SELF_PATH;
    policy[0] = info;
    std::vector<uint32_t> result;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 1, result, setInfo));
    ASSERT_EQ(1, result.size());
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result[0]);
}

HWTEST_F(PolicyInfoManagerTest, ShareTest009, TestSize.Level0)
{
    const std::string bundleName = "com.testshare";
    const std::string path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/files";
    SandboxManagerShare::GetInstance().DeleteByBundleName(bundleName);

    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/files";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);
}

HWTEST_F(PolicyInfoManagerTest, ShareTest010, TestSize.Level0)
{
    std::string stringJson1 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/test10",
                    "permission": "r"
                }
            ]
        }
    })";

    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    const std::string path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/test10";
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson1, bundleName, userId));

    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/test10";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::INVALID_PATH, setResult[0]);
}

HWTEST_F(PolicyInfoManagerTest, ShareTest011, TestSize.Level0)
{
    std::string stringJson1 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/test10",
                    "permission": "r"
                }
            ]
        }
    })";

    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    const std::string path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/test10";
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson1, bundleName, userId));

    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/test10";
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    info.type = PolicyType::AUTHORIZATION_PATH;
    policy[0] = info;
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);
}

HWTEST_F(PolicyInfoManagerTest, ShareTest012, TestSize.Level0)
{
    std::string stringJson1 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/test10",
                    "permission": "r+w"
                }
            ]
        }
    })";

    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    const std::string path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/test10";
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson1, bundleName, userId));

    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/test10/child";
    info.mode = OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);

    info.path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/test10/";
    info.mode = OperateMode::WRITE_MODE;
    policy[0] = info;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);
}

HWTEST_F(PolicyInfoManagerTest, ShareTest013, TestSize.Level0)
{
    std::string stringJson1 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/test10/child",
                    "permission": "r+w"
                }
            ]
        }
    })";

    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson1, bundleName, userId));

    std::string stringJson2 = R"({
        "share_files": "test"
    })";
    EXPECT_EQ(INVALID_PARAMTER,
        SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson2, bundleName, userId));

    std::string stringJson3 = R"({
        "share_files": {
            "scopes": "test"
        }
    })";
    EXPECT_EQ(INVALID_PARAMTER,
        SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson3, bundleName, userId));
}

HWTEST_F(PolicyInfoManagerTest, ShareTest014, TestSize.Level0)
{
    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    std::string stringJson4 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": 1,
                    "permission": "r+w"
                }
            ]
        }
    })";
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson4, bundleName, userId));

    std::string stringJson5 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/test10",
                    "permission": 1
                }
            ]
        }
    })";
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson5, bundleName, userId));
}

HWTEST_F(PolicyInfoManagerTest, ShareTest015, TestSize.Level0)
{
    std::string stringJson1 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/test10",
                    "permission": "r+w"
                }
            ]
        }
    })";

    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson1, bundleName, userId));

    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = "/storage/Users/currentUser/appdata/el2/base/+clone-1+com.testshare/test10";
    info.mode = OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);
}

HWTEST_F(PolicyInfoManagerTest, ShareTest016, TestSize.Level0)
{
    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    const std::string path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/test10";
    uint32_t mode = 0;

    const std::string bundleName1 = "";
    SandboxManagerShare::GetInstance().AddToMap(bundleName1, userId, path, mode);
    SandboxManagerShare::GetInstance().AddToMap(bundleName, userId, path, 0);
    SandboxManagerShare::GetInstance().AddToMap(bundleName, userId, path, mode);
    SandboxManagerShare::GetInstance().DeleteByUserId(userId);
    EXPECT_EQ(ShareStatus::SHARE_BUNDLE_UNSET,
        SandboxManagerShare::GetInstance().FindPermission(bundleName, userId, path));
    SandboxManagerShare::GetInstance().Refresh(bundleName, 100);
    SandboxManagerShare::GetInstance().DeleteByTokenid(0);
    SandboxManagerShare::GetInstance().DeleteByTokenid(g_mockToken);
}

HWTEST_F(PolicyInfoManagerTest, ShareTest017, TestSize.Level0)
{
    std::string path1 = "/storage/Users/currentUser/appdat";
    std::string path2 = "/storage/Users/currentUser/appdata3";
    std::string path3 = "/storage/Users/currentUser/DATA/test/data/com.test/files/tmp";

    PolicyInfo policy;
    int32_t useId;
    policy.path = path1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().CheckPathIsBlocked(0, useId, policy));
    policy.path = path2;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().CheckPathIsBlocked(0, useId, policy));
    policy.path = path3;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().CheckPathIsBlocked(0, useId, policy));
}

/**
 * @tc.name: ShareTest019
 * @tc.desc: set "rw" then use "r" to overwrite, write failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, ShareTest019, TestSize.Level0)
{
    std::string stringJson1 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/haps",
                    "permission": "r+w"
                }
            ]
        }
    })";

    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson1, bundleName, userId));

    std::string stringJson2 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/haps",
                    "permission": "r"
                }
            ]
        }
    })";
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson2, bundleName, userId));

    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);
    info.path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/haps";
    info.mode = OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::INVALID_PATH, setResult[0]);
}

/**
 * @tc.name: ShareTest020
 * @tc.desc: set "rw" then use "r" to overwrite, read succ
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, ShareTest020, TestSize.Level0)
{
    std::string stringJson1 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/haps",
                    "permission": "r+w"
                }
            ]
        }
    })";

    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    SandboxManagerShare::GetInstance().DeleteByBundleName(bundleName);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson1, bundleName, userId));

    std::string stringJson2 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/haps",
                    "permission": "r"
                }
            ]
        }
    })";
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson2, bundleName, userId));

    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);
    info.path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/haps";
    info.mode = OperateMode::READ_MODE;
    policy[0] = info;
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);
}

/**
 * @tc.name: ShareTest021
 * @tc.desc: set "rw" then set "r" to other userId, read succ
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, ShareTest021, TestSize.Level0)
{
    std::string stringJson1 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/haps",
                    "permission": "r+w"
                }
            ]
        }
    })";
    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    SandboxManagerShare::GetInstance().DeleteByBundleName(bundleName);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson1, bundleName, userId));

    std::string stringJson2 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/haps",
                    "permission": "r"
                }
            ]
        }
    })";
    userId = 200;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson2, bundleName, userId));

    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);
    info.path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/haps";
    info.mode = OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);
}

/**
 * @tc.name: ShareTest022
 * @tc.desc: set path1 "rw" then set "r" to other path, write path1 succ
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, ShareTest022, TestSize.Level0)
{
    std::string stringJson1 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/haps",
                    "permission": "r+w"
                }
            ]
        }
    })";
    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    SandboxManagerShare::GetInstance().DeleteByBundleName(bundleName);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson1, bundleName, userId));

    std::string stringJson2 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r"
                }
            ]
        }
    })";
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson2, bundleName, userId));

    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);
    info.path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/haps";
    info.mode = OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);
}

/**
 * @tc.name: ShareTest023
 * @tc.desc: set "w" then use "wr" to overwrite, w succ
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, ShareTest023, TestSize.Level0)
{
    std::string stringJson1 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/haps",
                    "permission": "w"
                }
            ]
        }
    })";
    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    SandboxManagerShare::GetInstance().DeleteByBundleName(bundleName);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson1, bundleName, userId));

    std::string stringJson2 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/haps",
                    "permission": "r+w"
                }
            ]
        }
    })";
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson2, bundleName, userId));

    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);
    info.path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/haps";
    info.mode = OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);
}

/**
 * @tc.name: ShareTest024
 * @tc.desc: set "w" then use "r" to overwrite, then delete all, w succ
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, ShareTest024, TestSize.Level0)
{
    std::string stringJson1 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/haps",
                    "permission": "w"
                }
            ]
        }
    })";
    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    SandboxManagerShare::GetInstance().DeleteByBundleName(bundleName);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson1, bundleName, userId));

    std::string stringJson2 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/haps",
                    "permission": "r"
                }
            ]
        }
    })";
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson2, bundleName, userId));
    SandboxManagerShare::GetInstance().DeleteByBundleName(bundleName);
    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);
    info.path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/haps";
    info.mode = OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);
}

/**
 * @tc.name: ShareTest025
 * @tc.desc: set "w" then use "r" to overwrite, then delete userId, w succ
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, ShareTest025, TestSize.Level0)
{
    std::string stringJson1 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/haps",
                    "permission": "w"
                }
            ]
        }
    })";
    int32_t userId = 100;
    const std::string bundleName = "com.testshare";
    SandboxManagerShare::GetInstance().DeleteByBundleName(bundleName);
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson1, bundleName, userId));

    std::string stringJson2 = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/haps",
                    "permission": "r"
                }
            ]
        }
    })";
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxManagerShare::GetInstance().TransAndSetToMap(stringJson2, bundleName, userId));
    SandboxManagerShare::GetInstance().DeleteByUserId(userId);
    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);
    info.path = "/storage/Users/currentUser/appdata/el2/base/com.testshare/haps";
    info.mode = OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> setResult;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().SetPolicy(g_mockToken, policy, 1, setResult));
    ASSERT_EQ(1, setResult.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, setResult[0]);
}
#endif
#endif
} // SandboxManager
} // AccessControl
} // OHOS
