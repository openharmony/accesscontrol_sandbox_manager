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
#undef private
#include "sandbox_manager_const.h"
#include "sandbox_manager_rdb.h"
#include "sandbox_manager_log.h"
#include "sandbox_manager_err_code.h"
#include <sys/mount.h>
#include "dec_test.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
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
}

void PolicyInfoManagerTest::TearDown(void)
{
    if (PolicyInfoManager::GetInstance().macAdapter_.fd_ > 0) {
        close(PolicyInfoManager::GetInstance().macAdapter_.fd_);
        PolicyInfoManager::GetInstance().macAdapter_.fd_ = -1;
        PolicyInfoManager::GetInstance().macAdapter_.isMacSupport_ = false;
    }
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

    EXPECT_EQ(SandboxRetType::INVALID_PATH, PolicyInfoManager::GetInstance().CheckPathIsBlocked(path1));
    EXPECT_EQ(SandboxRetType::INVALID_PATH, PolicyInfoManager::GetInstance().CheckPathIsBlocked(path2));
    EXPECT_EQ(SandboxRetType::INVALID_PATH, PolicyInfoManager::GetInstance().CheckPathIsBlocked(path3));
    EXPECT_EQ(SandboxRetType::INVALID_PATH, PolicyInfoManager::GetInstance().CheckPathIsBlocked(path4));
    EXPECT_EQ(SandboxRetType::INVALID_PATH, PolicyInfoManager::GetInstance().CheckPathIsBlocked(path5));
    EXPECT_EQ(SandboxRetType::INVALID_PATH, PolicyInfoManager::GetInstance().CheckPathIsBlocked(path6));
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().CheckPathIsBlocked(path7));
    EXPECT_EQ(SandboxRetType::INVALID_PATH, PolicyInfoManager::GetInstance().CheckPathIsBlocked(path8));
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

    EXPECT_EQ(SandboxRetType::INVALID_PATH,
        PolicyInfoManager::GetInstance().CheckPathIsBlocked(path1, PolicyType::SELF_PATH));
    EXPECT_EQ(SandboxRetType::INVALID_PATH,
        PolicyInfoManager::GetInstance().CheckPathIsBlocked(path2, PolicyType::SELF_PATH));
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().CheckPathIsBlocked(path3, PolicyType::UNKNOWN, "com.test"));
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().CheckPathIsBlocked(path4, PolicyType::UNKNOWN, ""));
    EXPECT_EQ(SandboxRetType::INVALID_PATH,
        PolicyInfoManager::GetInstance().CheckPathIsBlocked(path5, PolicyType::SELF_PATH, "com.testt"));
    EXPECT_EQ(SandboxRetType::INVALID_PATH,
        PolicyInfoManager::GetInstance().CheckPathIsBlocked(path6, PolicyType::SELF_PATH, ""));
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().CheckPathIsBlocked(path7, PolicyType::SELF_PATH, "com.test"));
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().CheckPathIsBlocked(path8, PolicyType::SELF_PATH, "com.test"));
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
    EXPECT_EQ(SANDBOX_MANAGER_MAC_NOT_INIT, macAdapter.QuerySandboxPolicy(selfTokenId_, policy, boolRes));
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
const char *source = "/data/dec";
const char *target = "/data/mntDenyTest";
const char *fsType = "sharefs";
const char *mountData = "override_support_delete,user_id=100";
const char *testPathParent = "/data/mntDenyTest/test1";
const char *testPathChild = "/data/mntDenyTest/test1/a";
const char *testPathChildNew = "/data/mntDenyTest/test1/b";

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
} // SandboxManager
} // AccessControl
} // OHOS
