/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "mac_adapter.h"
#include "policy_field_const.h"
#include "policy_info.h"
#define private public
#include "policy_info_manager.h"
#undef private
#include "sandbox_manager_const.h"
#include "sandbox_manager_db.h"
#include "sandbox_manager_log.h"
#include "sandbox_manager_err_code.h"

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
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerDbTest"
};

void PolicyInfoManagerTest::SetUpTestCase(void)
{
    // remove all in db
    GenericValues conditions;
    SandboxManagerDb::GetInstance().Remove(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY, conditions);
}

void PolicyInfoManagerTest::TearDownTestCase(void)
{
    // remove all in db
    GenericValues conditions;
    SandboxManagerDb::GetInstance().Remove(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY, conditions);
}

void PolicyInfoManagerTest::SetUp(void)
{
    selfTokenId_ = 0;
    PolicyInfoManager::GetInstance().Init();
}

void PolicyInfoManagerTest::TearDown(void)
{}

void PrintDbRecords()
{
    GenericValues conditions;
    GenericValues symbols;
    std::vector<GenericValues> dbResult;
    EXPECT_EQ(0, SandboxManagerDb::GetInstance().Find(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
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

/**
 * @tc.name: PolicyInfoManagerTest002
 * @tc.desc: Test AddPolicy - normal cases
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest002, TestSize.Level1)
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

/**
 * @tc.name: PolicyInfoManagerTest004
 * @tc.desc: Test MatchPolicy - normal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest004, TestSize.Level1)
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

/**
 * @tc.name: PolicyInfoManagerTest006
 * @tc.desc: Test RemoveBundlePolicy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest006, TestSize.Level1)
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
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest007, TestSize.Level1)
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
 * @tc.name: PolicyInfoManagerTest011
 * @tc.desc: Test MatchSinglePolicy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyInfoManagerTest, PolicyInfoManagerTest011, TestSize.Level1)
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
HWTEST_F(PolicyInfoManagerTest, GenericValuesTest001, TestSize.Level1)
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
} // SandboxManager
} // AccessControl
} // OHOS