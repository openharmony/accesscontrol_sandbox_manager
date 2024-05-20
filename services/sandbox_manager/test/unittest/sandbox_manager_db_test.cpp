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

#include <cinttypes>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "generic_values.h"
#include "policy_field_const.h"
#define private public
#include "sandbox_manager_db.h"
#undef private
#include "sandbox_manager_log.h"


using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

class SandboxManagerDbTest : public testing::Test  {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerDbTest"
};

void ResultLogDB(const GenericValues value)
{
    int64_t tokenid;
    int64_t mode;
    int64_t depth;
    int64_t flag;
    std::string path;

    tokenid = value.GetInt(PolicyFiledConst::FIELD_TOKENID);
    mode = value.GetInt(PolicyFiledConst::FIELD_MODE);
    path = value.GetString(PolicyFiledConst::FIELD_PATH);
    depth = value.GetInt(PolicyFiledConst::FIELD_DEPTH);
    flag = value.GetInt(PolicyFiledConst::FIELD_FLAG);

    SANDBOXMANAGER_LOG_INFO(LABEL, "%{public}" PRIu64"-%{public}" PRIu64
        "-%{public}" PRId64"-%{public}s-flag:%{public}" PRId64,
        tokenid, mode, depth, path.c_str(), flag);
}

GenericValues g_value1, g_value2, g_value3, g_value4, g_value5;

void SandboxManagerDbTest::SetUpTestCase(void)
{
    g_value1.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(1));
    g_value1.Put(PolicyFiledConst::FIELD_PATH, "/user_grant/a");
    g_value1.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(0b01));
    g_value1.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(2)); // 2 means '/' included in path
    g_value1.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(0));

    g_value2.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(1));
    g_value2.Put(PolicyFiledConst::FIELD_PATH, "/user_grant/a/b");
    g_value2.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(0b11));
    g_value2.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(3)); // 3 means '/' included in path
    g_value2.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(0));

    g_value3.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(1));
    g_value3.Put(PolicyFiledConst::FIELD_PATH, "/user_grant/a/b/c");
    g_value3.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(0b10));
    g_value3.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(4)); // 4 means '/' included in path
    g_value3.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(0));

    g_value4.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(2)); // 2 means test tokenid
    g_value4.Put(PolicyFiledConst::FIELD_PATH, "/user_grant/a/b");
    g_value4.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(0b10));
    g_value4.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(3)); // 3 means '/' included in path
    g_value4.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(0));

    g_value5.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(2)); // 2 means test tokenid
    g_value5.Put(PolicyFiledConst::FIELD_PATH, "/user_grant");
    g_value5.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(0b11));
    g_value5.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(1)); // 1 means '/' included in path
    g_value5.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(0));
}

void SandboxManagerDbTest::TearDownTestCase(void)
{}

void SandboxManagerDbTest::SetUp(void)
{
    GenericValues conditions;
    SandboxManagerDb::GetInstance().Remove(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY, conditions);
}

void SandboxManagerDbTest::TearDown(void)
{
    GenericValues conditions;
    SandboxManagerDb::GetInstance().Remove(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY, conditions);
}

/**
 * @tc.name: SandboxManagerDbTest001
 * @tc.desc: Test add func
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerDbTest, SandboxManagerDbTest001, TestSize.Level1)
{
    std::vector<GenericValues> values = {g_value1, g_value2, g_value3, g_value4, g_value5};
    EXPECT_EQ(0, SandboxManagerDb::GetInstance().Add(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
        values));

    GenericValues conditions;
    GenericValues symbols;
    std::vector<GenericValues> dbResult;
    EXPECT_EQ(0, SandboxManagerDb::GetInstance().Find(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
        conditions, symbols, dbResult));
    uint64_t sizeLimit = 5;
    EXPECT_EQ(sizeLimit, dbResult.size());
}

/**
 * @tc.name: SandboxManagerDbTest002
 * @tc.desc: Test self-defined find func
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerDbTest, SandboxManagerDbTest002, TestSize.Level1)
{
    std::vector<GenericValues> values = {g_value1, g_value2, g_value3, g_value4, g_value5};
    EXPECT_EQ(0, SandboxManagerDb::GetInstance().Add(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
        values));

    // find token = 2, depth <= 1, g_value5
    GenericValues conditions;
    GenericValues symbols;
    conditions.Put(PolicyFiledConst::FIELD_TOKENID, 2);
    symbols.Put(PolicyFiledConst::FIELD_TOKENID, std::string("="));

    conditions.Put(PolicyFiledConst::FIELD_DEPTH, 1);
    symbols.Put(PolicyFiledConst::FIELD_DEPTH, std::string("<="));

    std::vector<GenericValues> dbResult;
    EXPECT_EQ(0, SandboxManagerDb::GetInstance().Find(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
        conditions, symbols, dbResult));
    SANDBOXMANAGER_LOG_INFO(LABEL, "dbResult:%{public}zu", dbResult.size());

    uint64_t sizeLimit = 1;
    EXPECT_EQ(sizeLimit, dbResult.size());

    int64_t tokenid;
    int64_t mode;
    int64_t depth;
    int64_t flag;
    std::string path;

    tokenid = dbResult[0].GetInt(PolicyFiledConst::FIELD_TOKENID);
    mode = dbResult[0].GetInt(PolicyFiledConst::FIELD_MODE);
    path = dbResult[0].GetString(PolicyFiledConst::FIELD_PATH);
    depth = dbResult[0].GetInt(PolicyFiledConst::FIELD_DEPTH);
    flag = dbResult[0].GetInt(PolicyFiledConst::FIELD_FLAG);
    ResultLogDB(dbResult[0]);
    EXPECT_EQ(2, tokenid);
    EXPECT_EQ(0b11, mode);
    EXPECT_EQ(1, depth);
    EXPECT_EQ("/user_grant", path);
    EXPECT_EQ(0, flag);
}

/**
 * @tc.name: SandboxManagerDbTest001
 * @tc.desc: Test remove func
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerDbTest, SandboxManagerDbTest003, TestSize.Level1)
{
    std::vector<GenericValues> values = {g_value1, g_value2, g_value3, g_value4, g_value5};
    EXPECT_EQ(0, SandboxManagerDb::GetInstance().Add(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
        values));

    EXPECT_EQ(0, SandboxManagerDb::GetInstance().Remove(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
        g_value1));
    
    GenericValues conditions;
    GenericValues symbols;
    std::vector<GenericValues> dbResult;
    EXPECT_EQ(0, SandboxManagerDb::GetInstance().Find(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
        conditions, symbols, dbResult));
    uint64_t sizeLimit = 4;
    EXPECT_EQ(sizeLimit, dbResult.size());
}

/**
 * @tc.name: SandboxManagerDbTest001
 * @tc.desc: Test remove func (not exist record)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerDbTest, SandboxManagerDbTest004, TestSize.Level1)
{
    std::vector<GenericValues> values = {g_value1, g_value2, g_value3, g_value4, g_value5};
    EXPECT_EQ(0, SandboxManagerDb::GetInstance().Add(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
        values));

    GenericValues tmpValue;
    tmpValue.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(3));
    tmpValue.Put(PolicyFiledConst::FIELD_PATH, "/t/a/b");
    tmpValue.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(0b11));
    tmpValue.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(3));
    tmpValue.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(3));
    EXPECT_EQ(0, SandboxManagerDb::GetInstance().Remove(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
        tmpValue));
    
    GenericValues conditions;
    GenericValues symbols;
    std::vector<GenericValues> dbResult;
    EXPECT_EQ(0, SandboxManagerDb::GetInstance().Find(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
        conditions, symbols, dbResult));

    uint64_t sizeLimit = 5;
    EXPECT_EQ(sizeLimit, dbResult.size());
}

/**
 * @tc.name: SandboxManagerDbTest001
 * @tc.desc: Test modify
 * @tc.type: FUNC
 * @tc.require: IMPORTANT: modify cannot change primary key (tokenid depth path)
 */
HWTEST_F(SandboxManagerDbTest, SandboxManagerDbTest005, TestSize.Level1)
{
    std::vector<GenericValues> values = {g_value1, g_value2, g_value3, g_value4, g_value5};
    EXPECT_EQ(0, SandboxManagerDb::GetInstance().Add(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
        values));

    GenericValues tmpValue;
    tmpValue.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(8));

    std::vector<GenericValues> tmpdbResult;
    GenericValues symbols;
    EXPECT_EQ(0, SandboxManagerDb::GetInstance().Find(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
        g_value5, symbols, tmpdbResult));
    uint64_t sizeLimit = 1;
    EXPECT_EQ(sizeLimit, tmpdbResult.size());
    GenericValues condition;
    condition.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(2));
    condition.Put(PolicyFiledConst::FIELD_PATH, "/user_grant");
    EXPECT_EQ(0, SandboxManagerDb::GetInstance().Modify(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
        tmpValue, condition));

    GenericValues conditions;


    std::vector<GenericValues> dbResult;
    EXPECT_EQ(0, SandboxManagerDb::GetInstance().Find(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
        tmpValue, symbols, dbResult));
    
    EXPECT_EQ(sizeLimit, dbResult.size());
    EXPECT_EQ(8, dbResult[0].GetInt(PolicyFiledConst::FIELD_DEPTH));
}

/**
 * @tc.name: SandboxManagerDbTest006
 * @tc.desc: Test remove func (not exist record)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerDbTest, SandboxManagerDbTest006, TestSize.Level1)
{
    //db_ != nullptr
    EXPECT_EQ(-1, SandboxManagerDb::GetInstance().RollbackTransaction());
    std::string sql = "PRAGMA user_version";
    EXPECT_NE(-1, SandboxManagerDb::GetInstance().ExecuteSql(sql));
    SandboxManagerDb::GetInstance().SpitError();

    SandboxManagerDb::GetInstance().OnCreate();
    SandboxManagerDb::GetInstance().OnUpdate();
    std::vector<GenericValues> values;
    EXPECT_NE(-1, SandboxManagerDb::GetInstance().RefreshAll(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
        values));
    values = {g_value1, g_value2, g_value3, g_value4, g_value5};
    EXPECT_EQ(0, SandboxManagerDb::GetInstance().RefreshAll(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
        values));
    SandboxManagerDb::GetInstance().Open();

    //db_ = nullptr
    SandboxManagerDb::GetInstance().Close();
    SandboxManagerDb::GetInstance().Close();
    EXPECT_EQ(-1, SandboxManagerDb::GetInstance().BeginTransaction());
    EXPECT_EQ(-1, SandboxManagerDb::GetInstance().CommitTransaction());
    EXPECT_EQ(-1, SandboxManagerDb::GetInstance().RollbackTransaction());
    EXPECT_EQ(-1, SandboxManagerDb::GetInstance().ExecuteSql(sql));
    SandboxManagerDb::GetInstance().SpitError();
    SandboxManagerDb::GetInstance().Open(); // recover
}

/**
 * @tc.name: SandboxManagerDbTest007
 * @tc.desc: Test when dataTypeToSqlTable_ nopt found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerDbTest, SandboxManagerDbTest007, TestSize.Level1)
{
    std::map<SandboxManagerDb::DataType, SandboxManagerDb::SqliteTable> oldTable =
        SandboxManagerDb::GetInstance().dataTypeToSqlTable_;
    SandboxManagerDb::GetInstance().dataTypeToSqlTable_ = {};
    EXPECT_EQ(SandboxManagerDb::FAILURE, SandboxManagerDb::GetInstance().CreatePersistedPolicyTable());
    std::vector<std::string> column;
    GenericValues symbol;
    std::string ret = SandboxManagerDb::GetInstance().CreateSelectPrepareSqlCmd(
        SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY, column, symbol);
    EXPECT_TRUE(ret.empty());

    std::vector<std::string> conditionColumns;
    std::vector<std::string> modifyColumns;
    modifyColumns.emplace_back("test");
    ret = SandboxManagerDb::GetInstance().CreateUpdatePrepareSqlCmd(
        SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY, modifyColumns, conditionColumns);
    EXPECT_TRUE(ret.empty());

    ret = SandboxManagerDb::GetInstance().CreateDeletePrepareSqlCmd(
        SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY, conditionColumns);
    EXPECT_TRUE(ret.empty());

    ret = SandboxManagerDb::GetInstance().CreateInsertPrepareSqlCmd(
        SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY);
    EXPECT_TRUE(ret.empty());
    SandboxManagerDb::GetInstance().dataTypeToSqlTable_ = oldTable;
}

/**
 * @tc.name: SandboxManagerDbTest008
 * @tc.desc: Test when dataTypeToSqlTable_ nopt found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerDbTest, SandboxManagerDbTest008, TestSize.Level1)
{
    std::vector<std::string> column = {"test"}; // this is a test
    GenericValues symbol;
    symbol.Put("test", ">"); // unrecognize symbol
    std::string ret = SandboxManagerDb::GetInstance().CreateSelectPrepareSqlCmd(
        SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY, column, symbol);
    EXPECT_TRUE(ret.empty());
}

/**
 * @tc.name: SandboxManagerDbTest009
 * @tc.desc: Test when dataTypeToSqlTable_ nopt found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerDbTest, SandboxManagerDbTest009, TestSize.Level1)
{
    std::vector<std::string> modifyColumns;
    std::vector<std::string> conditionColumns;
    std::string ret = SandboxManagerDb::GetInstance().CreateUpdatePrepareSqlCmd(
        SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY, modifyColumns, conditionColumns);
    EXPECT_TRUE(ret.empty());

    modifyColumns.emplace_back("test0");
    modifyColumns.emplace_back("test1");
    ret = SandboxManagerDb::GetInstance().CreateUpdatePrepareSqlCmd(
        SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY, modifyColumns, conditionColumns);
    std::string ok = "update persisted_policy_table set test0=:test0,test1=:test1";
    EXPECT_EQ(ok, ret);
}
} // SandboxManager
} // AccessControl
} // OHOS