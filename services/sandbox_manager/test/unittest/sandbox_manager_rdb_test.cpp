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

#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <functional>
#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <vector>
#include "generic_values.h"
#include "policy_field_const.h"
#define private public
#include "sandbox_manager_rdb.h"
#undef private
#include "sandbox_manager_log.h"


using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

class SandboxManagerRdbTest : public testing::Test  {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerRdbTest"
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

void SandboxManagerRdbTest::SetUpTestCase(void)
{
    SandboxManagerRdb::GetInstance().Init();
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

void SandboxManagerRdbTest::TearDownTestCase(void)
{}

void SandboxManagerRdbTest::SetUp(void)
{
    GenericValues conditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, conditions);
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY, conditions);
}

void SandboxManagerRdbTest::TearDown(void)
{
    GenericValues conditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, conditions);
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY, conditions);
}

/**
 * @tc.name: SandboxManagerRdbTest_FindSubPathIgnoreCase_001
 * @tc.desc: Test FindSubPathIgnoreCase func with different case paths
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest_FindSubPathIgnoreCase_001, TestSize.Level0)
{
    // Add data with different case paths
    GenericValues valueUpper;
    valueUpper.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(1));
    valueUpper.Put(PolicyFiledConst::FIELD_PATH, "/USER_GRANT/A");  // Uppercase path
    valueUpper.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(0b01));
    valueUpper.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(2)); // 2 means '/' included in path
    valueUpper.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(0));

    GenericValues valueLower;
    valueLower.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(1));
    valueLower.Put(PolicyFiledConst::FIELD_PATH, "/user_grant/b");  // Lowercase path
    valueLower.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(0b11));
    valueLower.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(2)); // 2 means '/' included in path
    valueLower.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(0));

    GenericValues valueMixed;
    valueMixed.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(1));
    valueMixed.Put(PolicyFiledConst::FIELD_PATH, "/User_Grant/C");  // Mixed case path
    valueMixed.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(0b10));
    valueMixed.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(2)); // 2 means '/' included in path
    valueMixed.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(0));

    std::vector<GenericValues> values = {valueUpper, valueLower, valueMixed};
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY,
        values));

    // Test FindSubPathIgnoreCase function, querying with lowercase path should return all matches regardless of case
    std::vector<GenericValues> dbResult;
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().FindSubPathIgnoreCase(SANDBOX_MANAGER_PERSISTED_POLICY,
        "/user_grant", dbResult));

    // Should return all three values since they all start with "/user_grant" (case insensitive)
    uint64_t sizeLimit = 3;
    EXPECT_EQ(sizeLimit, dbResult.size());

    // Verify the results contain the expected paths
    bool foundUpper = false, foundLower = false, foundMixed = false;
    for (const auto &result : dbResult) {
        std::string path = result.GetString(PolicyFiledConst::FIELD_PATH);
        if (path == "/USER_GRANT/A") foundUpper = true;
        else if (path == "/user_grant/b") foundLower = true;
        else if (path == "/User_Grant/C") foundMixed = true;
    }

    EXPECT_TRUE(foundUpper);
    EXPECT_TRUE(foundLower);
    EXPECT_TRUE(foundMixed);
    
    // Clean up: Remove the inserted data using the same values vector
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, values));
}

/**
 * @tc.name: SandboxManagerRdbTest_FindSubPathIgnoreCase_002
 * @tc.desc: Test FindSubPathIgnoreCase func with exact match and subpath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest_FindSubPathIgnoreCase_002, TestSize.Level0)
{
    // Add data with different case paths including exact match
    GenericValues valueExactUpper;
    valueExactUpper.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(1));
    valueExactUpper.Put(PolicyFiledConst::FIELD_PATH, "/USER_GRANT");  // Exact uppercase match
    valueExactUpper.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(0b01));
    valueExactUpper.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(1)); // 1 means '/' included in path
    valueExactUpper.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(0));

    GenericValues valueSubUpper;
    valueSubUpper.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(1));
    valueSubUpper.Put(PolicyFiledConst::FIELD_PATH, "/USER_GRANT/A");  // Subpath uppercase
    valueSubUpper.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(0b11));
    valueSubUpper.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(2)); // 2 means '/' included in path
    valueSubUpper.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(0));

    GenericValues valueExactLower;
    valueExactLower.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(1));
    valueExactLower.Put(PolicyFiledConst::FIELD_PATH, "/user_grant");  // Exact lowercase match
    valueExactLower.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(0b10));
    valueExactLower.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(1)); // 1 means '/' included in path
    valueExactLower.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(0));

    GenericValues valueDifferent;
    valueDifferent.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(1));
    valueDifferent.Put(PolicyFiledConst::FIELD_PATH, "/other_path");  // Different path
    valueDifferent.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(0b00));
    valueDifferent.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(1)); // 1 means '/' included in path
    valueDifferent.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(0));

    std::vector<GenericValues> values = {valueExactUpper, valueSubUpper, valueExactLower, valueDifferent};
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY,
        values));

    // Test FindSubPathIgnoreCase function with exact match, should return exact match and subpaths
    std::vector<GenericValues> dbResult;
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().FindSubPathIgnoreCase(SANDBOX_MANAGER_PERSISTED_POLICY,
        "/user_grant", dbResult));

    // Should return three values: exact matches and subpaths
    // 1. "/USER_GRANT" - exact match (different case)
    // 2. "/USER_GRANT/A" - subpath match
    // 3. "/user_grant" - exact match (same case)
    uint64_t sizeLimit = 3;
    EXPECT_EQ(sizeLimit, dbResult.size());

    // Verify the results contain the expected paths
    bool foundExactUpper = false, foundSubUpper = false, foundExactLower = false, foundOther = false;
    for (const auto &result : dbResult) {
        std::string path = result.GetString(PolicyFiledConst::FIELD_PATH);
        if (path == "/USER_GRANT") foundExactUpper = true;
        else if (path == "/USER_GRANT/A") foundSubUpper = true;
        else if (path == "/user_grant") foundExactLower = true;
        else if (path == "/other_path") foundOther = true;
    }

    // Check that exact matches and subpath were found, but not the unrelated path
    EXPECT_TRUE(foundExactUpper);
    EXPECT_TRUE(foundSubUpper);
    EXPECT_TRUE(foundExactLower);
    EXPECT_FALSE(foundOther);  // This should not be found since it doesn't match
    
    // Clean up: Remove the inserted data using the same values vector
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, values));
}

/**
 * @tc.name: SandboxManagerRdbTest001
 * @tc.desc: Test add func
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest001, TestSize.Level0)
{
    std::vector<GenericValues> values = {g_value1, g_value2, g_value3, g_value4, g_value5};
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY,
        values));

    GenericValues conditions;
    GenericValues symbols;
    std::vector<GenericValues> dbResult;
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Find(SANDBOX_MANAGER_PERSISTED_POLICY,
        conditions, symbols, dbResult));
    uint64_t sizeLimit = 5;
    EXPECT_EQ(sizeLimit, dbResult.size());
}

/**
 * @tc.name: SandboxManagerRdbTest002
 * @tc.desc: Test self-defined find func
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest002, TestSize.Level0)
{
    std::vector<GenericValues> values = {g_value1, g_value2, g_value3, g_value4, g_value5};
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY,
        values));

    // find token = 2, depth <= 1, g_value5
    GenericValues conditions;
    GenericValues symbols;
    conditions.Put(PolicyFiledConst::FIELD_TOKENID, 2);
    symbols.Put(PolicyFiledConst::FIELD_TOKENID, std::string("="));

    conditions.Put(PolicyFiledConst::FIELD_DEPTH, 1);
    symbols.Put(PolicyFiledConst::FIELD_DEPTH, std::string("<="));

    std::vector<GenericValues> dbResult;
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Find(SANDBOX_MANAGER_PERSISTED_POLICY,
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
 * @tc.name: SandboxManagerRdbTest001
 * @tc.desc: Test remove func
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest003, TestSize.Level0)
{
    std::vector<GenericValues> values = {g_value1, g_value2, g_value3, g_value4, g_value5};
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY,
        values));

    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY,
        g_value1));
    
    GenericValues conditions;
    GenericValues symbols;
    std::vector<GenericValues> dbResult;
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Find(SANDBOX_MANAGER_PERSISTED_POLICY,
        conditions, symbols, dbResult));
    uint64_t sizeLimit = 4;
    EXPECT_EQ(sizeLimit, dbResult.size());
}

/**
 * @tc.name: SandboxManagerRdbTest001
 * @tc.desc: Test remove func (not exist record)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest004, TestSize.Level0)
{
    std::vector<GenericValues> values = {g_value1, g_value2, g_value3, g_value4, g_value5};
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY,
        values));

    GenericValues tmpValue;
    tmpValue.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(3));
    tmpValue.Put(PolicyFiledConst::FIELD_PATH, "/t/a/b");
    tmpValue.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(0b11));
    tmpValue.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(3));
    tmpValue.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(3));
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY,
        tmpValue));
    
    GenericValues conditions;
    GenericValues symbols;
    std::vector<GenericValues> dbResult;
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Find(SANDBOX_MANAGER_PERSISTED_POLICY,
        conditions, symbols, dbResult));

    uint64_t sizeLimit = 5;
    EXPECT_EQ(sizeLimit, dbResult.size());
}

/**
 * @tc.name: SandboxManagerRdbTest001
 * @tc.desc: Test modify
 * @tc.type: FUNC
 * @tc.require: IMPORTANT: modify cannot change primary key (tokenid depth path)
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest005, TestSize.Level0)
{
    std::vector<GenericValues> values = {g_value1, g_value2, g_value3, g_value4, g_value5};
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY,
        values));

    GenericValues tmpValue;
    tmpValue.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(8));

    std::vector<GenericValues> tmpdbResult;
    GenericValues symbols;
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Find(SANDBOX_MANAGER_PERSISTED_POLICY,
        g_value5, symbols, tmpdbResult));
    uint64_t sizeLimit = 1;
    EXPECT_EQ(sizeLimit, tmpdbResult.size());
    GenericValues condition;
    condition.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(2));
    condition.Put(PolicyFiledConst::FIELD_PATH, "/user_grant");
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Modify(SANDBOX_MANAGER_PERSISTED_POLICY,
        tmpValue, condition));

    GenericValues conditions;


    std::vector<GenericValues> dbResult;
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Find(SANDBOX_MANAGER_PERSISTED_POLICY,
        tmpValue, symbols, dbResult));
    
    EXPECT_EQ(sizeLimit, dbResult.size());
    EXPECT_EQ(8, dbResult[0].GetInt(PolicyFiledConst::FIELD_DEPTH));
}

/**
 * @tc.name: SandboxManagerRdbTest006
 * @tc.desc: Test add func - db_ is null and retry
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest006, TestSize.Level0)
{
    SandboxManagerRdb &instance = SandboxManagerRdb::GetInstance();
    instance.db_ = nullptr;
    std::vector<GenericValues> values = {g_value1, g_value2, g_value3, g_value4, g_value5};
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY,
        values));

    GenericValues conditions;
    GenericValues symbols;
    std::vector<GenericValues> dbResult;
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Find(SANDBOX_MANAGER_PERSISTED_POLICY,
        conditions, symbols, dbResult));
    uint64_t sizeLimit = 5;
    EXPECT_EQ(sizeLimit, dbResult.size());
}

/**
 * @tc.name: SandboxManagerRdbTest_GetRecordCount_001
 * @tc.desc: Test GetRecordCount normal, empty, and invalid type branches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest_GetRecordCount_001, TestSize.Level0)
{
    int32_t count = -1;
    EXPECT_EQ(SandboxManagerRdb::SUCCESS,
        SandboxManagerRdb::GetInstance().GetRecordCount(SANDBOX_MANAGER_PERSISTED_POLICY, count));
    EXPECT_EQ(0, count);

    std::vector<GenericValues> values = {g_value1, g_value2, g_value3, g_value4, g_value5};
    EXPECT_EQ(SandboxManagerRdb::SUCCESS,
        SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY, values));
    EXPECT_EQ(SandboxManagerRdb::SUCCESS,
        SandboxManagerRdb::GetInstance().GetRecordCount(SANDBOX_MANAGER_PERSISTED_POLICY, count));
    EXPECT_EQ(5, count);

    count = -1;
    EXPECT_EQ(SandboxManagerRdb::FAILURE,
        SandboxManagerRdb::GetInstance().GetRecordCount(static_cast<DataType>(999), count));
    EXPECT_EQ(-1, count);
}

/**
 * @tc.name: SandboxManagerRdbTest_GetTokenIdWithMostRecords_001
 * @tc.desc: Test GetTokenIdWithMostRecords normal, empty, and invalid type branches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest_GetTokenIdWithMostRecords_001, TestSize.Level0)
{
    uint32_t tokenId = 1;
    uint32_t count = 1;
    EXPECT_EQ(SandboxManagerRdb::SUCCESS,
        SandboxManagerRdb::GetInstance().GetTokenIdWithMostRecords(SANDBOX_MANAGER_PERSISTED_POLICY, tokenId, count));
    EXPECT_EQ(static_cast<uint32_t>(0), tokenId);
    EXPECT_EQ(static_cast<uint32_t>(0), count);

    std::vector<GenericValues> values = {g_value1, g_value2, g_value3, g_value4, g_value5};
    EXPECT_EQ(SandboxManagerRdb::SUCCESS,
        SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY, values));
    EXPECT_EQ(SandboxManagerRdb::SUCCESS,
        SandboxManagerRdb::GetInstance().GetTokenIdWithMostRecords(SANDBOX_MANAGER_PERSISTED_POLICY, tokenId, count));
    EXPECT_EQ(static_cast<uint32_t>(1), tokenId);
    EXPECT_EQ(static_cast<uint32_t>(3), count);

    tokenId = 1;
    count = 1;
    EXPECT_EQ(SandboxManagerRdb::FAILURE,
        SandboxManagerRdb::GetInstance().GetTokenIdWithMostRecords(static_cast<DataType>(999), tokenId, count));
    EXPECT_EQ(static_cast<uint32_t>(1), tokenId);
    EXPECT_EQ(static_cast<uint32_t>(1), count);
}

/**
 * @tc.name: SandboxManagerRdbTest007
 * @tc.desc: Test BUNDLE_PERSISTENT_POLICY table - add and find
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest007, TestSize.Level0)
{
    // Clean up first
    GenericValues conditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY, conditions);

    // Add bundle persistent policy
    GenericValues bundlePolicy;
    bundlePolicy.Put(PolicyFiledConst::FIELD_BUNDLENAME, std::string("test.bundle"));
    bundlePolicy.Put(PolicyFiledConst::FIELD_USERID, static_cast<int32_t>(100));
    bundlePolicy.Put(PolicyFiledConst::FIELD_APPIDENTIFIER, std::string("test.bundle"));
    bundlePolicy.Put(PolicyFiledConst::FIELD_ORIGINAL_TOKENID, static_cast<int32_t>(12345));
    bundlePolicy.Put(PolicyFiledConst::FIELD_TIMESTAMP, static_cast<int64_t>(1234567890));

    std::vector<GenericValues> values = {bundlePolicy};
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY, values));

    // Find the record
    GenericValues findConditions;
    findConditions.Put(PolicyFiledConst::FIELD_APPIDENTIFIER, std::string("test.bundle"));
    findConditions.Put(PolicyFiledConst::FIELD_USERID, static_cast<int32_t>(100));

    GenericValues symbols;
    symbols.Put(PolicyFiledConst::FIELD_APPIDENTIFIER, std::string("="));
    symbols.Put(PolicyFiledConst::FIELD_USERID, std::string("="));

    std::vector<GenericValues> dbResult;
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Find(SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY,
        findConditions, symbols, dbResult));
    EXPECT_EQ(1, dbResult.size());

    // Verify the data
    EXPECT_EQ(std::string("test.bundle"), dbResult[0].GetString(PolicyFiledConst::FIELD_BUNDLENAME));
    EXPECT_EQ(100, dbResult[0].GetInt(PolicyFiledConst::FIELD_USERID));
    EXPECT_EQ(12345, dbResult[0].GetInt(PolicyFiledConst::FIELD_ORIGINAL_TOKENID));

    // Clean up
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY, conditions);
}

/**
 * @tc.name: SandboxManagerRdbTest008
 * @tc.desc: Test BUNDLE_PERSISTENT_POLICY table - remove
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest008, TestSize.Level0)
{
    // Clean up first
    GenericValues conditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY, conditions);

    // Add multiple bundle persistent policies
    GenericValues bundlePolicy1;
    bundlePolicy1.Put(PolicyFiledConst::FIELD_BUNDLENAME, std::string("test.bundle1"));
    bundlePolicy1.Put(PolicyFiledConst::FIELD_USERID, static_cast<int32_t>(100));
    bundlePolicy1.Put(PolicyFiledConst::FIELD_APPIDENTIFIER, std::string("test.bundle1"));
    bundlePolicy1.Put(PolicyFiledConst::FIELD_ORIGINAL_TOKENID, static_cast<int32_t>(12345));
    bundlePolicy1.Put(PolicyFiledConst::FIELD_TIMESTAMP, static_cast<int64_t>(1234567890));

    GenericValues bundlePolicy2;
    bundlePolicy2.Put(PolicyFiledConst::FIELD_BUNDLENAME, std::string("test.bundle2"));
    bundlePolicy2.Put(PolicyFiledConst::FIELD_USERID, static_cast<int32_t>(100));
    bundlePolicy2.Put(PolicyFiledConst::FIELD_APPIDENTIFIER, std::string("test.bundle2"));
    bundlePolicy2.Put(PolicyFiledConst::FIELD_ORIGINAL_TOKENID, static_cast<int32_t>(67890));
    bundlePolicy2.Put(PolicyFiledConst::FIELD_TIMESTAMP, static_cast<int64_t>(1234567891));

    std::vector<GenericValues> values = {bundlePolicy1, bundlePolicy2};
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY, values));

    // Remove one bundle
    GenericValues removeConditions;
    removeConditions.Put(PolicyFiledConst::FIELD_BUNDLENAME, std::string("test.bundle1"));
    removeConditions.Put(PolicyFiledConst::FIELD_USERID, static_cast<int32_t>(100));

    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY, removeConditions));

    // Verify only one remains
    GenericValues symbols;
    std::vector<GenericValues> dbResult;
    GenericValues findAllConditions;
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Find(SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY,
        findAllConditions, symbols, dbResult));
    EXPECT_EQ(1, dbResult.size());
    EXPECT_EQ(std::string("test.bundle2"), dbResult[0].GetString(PolicyFiledConst::FIELD_BUNDLENAME));

    // Clean up
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY, conditions);
}

/**
 * @tc.name: SandboxManagerRdbTest_ManualCleanupAndReopen
 * @tc.desc: Test CleanupDbInternal directly closes db connection, and auto-reopen on next operation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest_ManualCleanupAndReopen, TestSize.Level0)
{
    // Add data to ensure db_ is opened
    std::vector<GenericValues> values = {g_value1, g_value2};
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY, values));

    // Manually trigger internal cleanup
    SandboxManagerRdb::GetInstance().CleanupDbInternal();
    EXPECT_EQ(nullptr, SandboxManagerRdb::GetInstance().db_);

    // Next operation should auto-reopen db_ and still succeed
    GenericValues conditions;
    GenericValues symbols;
    std::vector<GenericValues> dbResult;
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Find(SANDBOX_MANAGER_PERSISTED_POLICY,
        conditions, symbols, dbResult));
    uint64_t sizeLimit = 2;
    EXPECT_EQ(sizeLimit, dbResult.size());
}

/**
 * @tc.name: SandboxManagerRdbTest_ScheduledDbCleanup
 * @tc.desc: Test dbCleanupDelay_ is configurable, short delay triggers cleanup quickly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest_ScheduledDbCleanup, TestSize.Level0)
{
    // Save original delay
    int64_t originalDelay = SandboxManagerRdb::GetInstance().dbCleanupDelay_;

    // Set a very short delay for testing
    SandboxManagerRdb::GetInstance().dbCleanupDelay_ = 2000; // 2s

    // Add data, which internally calls ScheduleDbCleanup with the short delay
    std::vector<GenericValues> values = {g_value1};
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY, values));

    // Poll for cleanup instead of a single long sleep:
    // - Returns as soon as db_ becomes null (fast in the normal case)
    // - Generous timeout tolerates slow CI scheduling
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (SandboxManagerRdb::GetInstance().db_ != nullptr &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    // Verify db_ has been cleaned up
    EXPECT_EQ(nullptr, SandboxManagerRdb::GetInstance().db_);

    // Restore original delay
    SandboxManagerRdb::GetInstance().dbCleanupDelay_ = originalDelay;
}

/**
 * @tc.name: SandboxManagerRdbTest_CleanupOnNullDb
 * @tc.desc: Test CleanupDbInternal on already-null db_ does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest_CleanupOnNullDb, TestSize.Level0)
{
    // Ensure db_ is null first
    SandboxManagerRdb::GetInstance().db_ = nullptr;

    // Calling cleanup on already-null db_ should be safe
    SandboxManagerRdb::GetInstance().CleanupDbInternal();
    EXPECT_EQ(nullptr, SandboxManagerRdb::GetInstance().db_);
}

/**
 * @tc.name: SandboxManagerRdbTest_ConcurrentAdd
 * @tc.desc: Test concurrent Add from multiple threads, verify no crash and data consistency
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest_ConcurrentAdd, TestSize.Level0)
{
    const int threadCount = 10;
    const int itemsPerThread = 5;
    std::vector<std::thread> threads;
    std::atomic<int> successCount{0};
    std::atomic<int> failCount{0};

    std::function<void(int, std::atomic<int>&, std::atomic<int>&)> addWorker =
        [itemsPerThread](int tid, std::atomic<int>& success, std::atomic<int>& fail) {
            for (int i = 0; i < itemsPerThread; ++i) {
                GenericValues value;
                value.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(tid));
                value.Put(PolicyFiledConst::FIELD_PATH, "/concurrent/" + std::to_string(tid) + "/" + std::to_string(i));
                value.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(1));
                value.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(2));
                value.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(0));

                int ret = SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY, {value});
                if (ret == SandboxManagerRdb::SUCCESS) {
                    success.fetch_add(1);
                }
                if (ret != SandboxManagerRdb::SUCCESS) {
                    fail.fetch_add(1);
                }
            }
        };

    for (int t = 0; t < threadCount; ++t) {
        threads.emplace_back(addWorker, t, std::ref(successCount), std::ref(failCount));
    }

    for (auto &th : threads) {
        th.join();
    }

    // All threads should succeed without crash
    EXPECT_EQ(threadCount * itemsPerThread, successCount.load());
    EXPECT_EQ(0, failCount.load());

    // Verify total record count
    int32_t count = -1;
    int32_t ret = SandboxManagerRdb::GetInstance().GetRecordCount(SANDBOX_MANAGER_PERSISTED_POLICY, count);
    EXPECT_EQ(SandboxManagerRdb::SUCCESS, ret);
    EXPECT_EQ(threadCount * itemsPerThread, count);

    // Clean up: remove all records
    GenericValues clearConditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, clearConditions);
}

/**
 * @tc.name: SandboxManagerRdbTest_ConcurrentFind
 * @tc.desc: Test concurrent Find from multiple threads, verify no crash and consistent results
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest_ConcurrentFind, TestSize.Level0)
{
    const int threadCount = 10;
    const int findCountPerThread = 20;

    // First, insert some data
    std::vector<GenericValues> values = {g_value1, g_value2, g_value3, g_value4, g_value5};
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY, values));

    std::vector<std::thread> threads;
    std::atomic<int> successCount{0};
    std::atomic<int> failCount{0};
    std::atomic<int> zeroResultCount{0};

    std::function<void(std::atomic<int>&, std::atomic<int>&, std::atomic<int>&)> findWorker =
        [findCountPerThread](std::atomic<int>& success, std::atomic<int>& fail, std::atomic<int>& zeroResult) {
            for (int i = 0; i < findCountPerThread; ++i) {
                GenericValues conditions;
                GenericValues symbols;
                std::vector<GenericValues> dbResult;

                int ret = SandboxManagerRdb::GetInstance().Find(SANDBOX_MANAGER_PERSISTED_POLICY,
                    conditions, symbols, dbResult);
                if (ret == SandboxManagerRdb::SUCCESS) {
                    success.fetch_add(1);
                }
                if (ret == SandboxManagerRdb::SUCCESS && dbResult.empty()) {
                    zeroResult.fetch_add(1);
                }
                if (ret != SandboxManagerRdb::SUCCESS) {
                    fail.fetch_add(1);
                }
            }
        };

    for (int t = 0; t < threadCount; ++t) {
        threads.emplace_back(findWorker, std::ref(successCount), std::ref(failCount), std::ref(zeroResultCount));
    }

    for (auto &th : threads) {
        th.join();
    }

    // All concurrent reads should succeed
    EXPECT_EQ(threadCount * findCountPerThread, successCount.load());
    EXPECT_EQ(0, failCount.load());

    // Clean up: remove all records
    GenericValues clearConditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, clearConditions);
}

/**
 * @tc.name: SandboxManagerRdbTest_ConcurrentAddAndFind
 * @tc.desc: Test concurrent mixed Add and Find operations, verify no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest_ConcurrentAddAndFind, TestSize.Level0)
{
    const int threadCount = 8;
    const int opsPerThread = 10;
    std::vector<std::thread> threads;
    std::atomic<int> addSuccess{0};
    std::atomic<int> findSuccess{0};

    std::function<void(int, std::atomic<int>&)> addWorker =
        [opsPerThread](int tid, std::atomic<int>& success) {
            for (int i = 0; i < opsPerThread; ++i) {
                GenericValues value;
                value.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(tid));
                value.Put(PolicyFiledConst::FIELD_PATH, "/mixed/" + std::to_string(tid) + "/" + std::to_string(i));
                value.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(1));
                value.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(2));
                value.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(0));

                int ret = SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY, {value});
                if (ret == SandboxManagerRdb::SUCCESS) {
                    success.fetch_add(1);
                }
            }
        };

    std::function<void(std::atomic<int>&)> findWorker =
        [opsPerThread](std::atomic<int>& success) {
            for (int i = 0; i < opsPerThread; ++i) {
                GenericValues conditions;
                GenericValues symbols;
                std::vector<GenericValues> dbResult;

                int ret = SandboxManagerRdb::GetInstance().Find(SANDBOX_MANAGER_PERSISTED_POLICY,
                    conditions, symbols, dbResult);
                if (ret == SandboxManagerRdb::SUCCESS) {
                    success.fetch_add(1);
                }
            }
        };

    // Half threads do Add, half do Find
    for (int t = 0; t < threadCount; ++t) {
        if (t % 2 == 0) {
            threads.emplace_back(addWorker, t, std::ref(addSuccess));
        } else {
            threads.emplace_back(findWorker, std::ref(findSuccess));
        }
    }

    for (auto &th : threads) {
        th.join();
    }

    // Expected: 4 writer threads and 4 reader threads
    EXPECT_EQ((threadCount / 2) * opsPerThread, addSuccess.load());
    EXPECT_EQ((threadCount / 2) * opsPerThread, findSuccess.load());

    // Clean up: remove all records
    GenericValues clearConditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, clearConditions);
}

/**
 * @tc.name: SandboxManagerRdbTest_ConcurrentAddAndCleanup
 * @tc.desc: Test concurrent Add and CleanupDbInternal, verify auto-reopen works correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest_ConcurrentAddAndCleanup, TestSize.Level0)
{
    const int addThreadCount = 4;
    const int opsPerThread = 20;
    const int cleanupThreadCount = 2;

    std::vector<std::thread> threads;
    std::atomic<int> addSuccess{0};
    std::atomic<int> cleanupCount{0};
    std::atomic<bool> stopCleanup{false};

    std::function<void(int, std::atomic<int>&)> addWorker =
        [opsPerThread](int tid, std::atomic<int>& success) {
            for (int i = 0; i < opsPerThread; ++i) {
                GenericValues value;
                value.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(100 + tid));
                value.Put(PolicyFiledConst::FIELD_PATH, "/stress/" + std::to_string(tid) + "/" + std::to_string(i));
                value.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(1));
                value.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(2));
                value.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(0));

                int ret = SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY, {value});
                if (ret == SandboxManagerRdb::SUCCESS) {
                    success.fetch_add(1);
                }
            }
        };

    std::function<void(std::atomic<int>&, std::atomic<bool>&)> cleanupWorker =
        [](std::atomic<int>& count, std::atomic<bool>& stop) {
            while (!stop.load()) {
                SandboxManagerRdb::GetInstance().CleanupDbInternal();
                count.fetch_add(1);
                usleep(10000); // 10ms between cleanups
            }
        };

    // Add threads: continuously write data
    for (int t = 0; t < addThreadCount; ++t) {
        threads.emplace_back(addWorker, t, std::ref(addSuccess));
    }

    // Cleanup threads: repeatedly close db_ while writers are working
    for (int t = 0; t < cleanupThreadCount; ++t) {
        threads.emplace_back(cleanupWorker, std::ref(cleanupCount), std::ref(stopCleanup));
    }

    // Wait for add threads to finish
    for (int t = 0; t < addThreadCount; ++t) {
        threads[t].join();
    }

    // Stop cleanup threads
    stopCleanup.store(true);
    for (size_t t = addThreadCount; t < threads.size(); ++t) {
        threads[t].join();
    }

    // Writers should still succeed despite concurrent cleanup
    EXPECT_GT(addSuccess.load(), 0);
    SANDBOXMANAGER_LOG_INFO(LABEL, "Add success: %d, Cleanup count: %d",
        addSuccess.load(), cleanupCount.load());

    // Clean up: remove all records
    GenericValues clearConditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, clearConditions);
}

/**
 * @tc.name: SandboxManagerRdbTest_ConcurrentRemoveAndFind
 * @tc.desc: Test concurrent Remove and Find operations, verify no crash and data consistency
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest_ConcurrentRemoveAndFind, TestSize.Level0)
{
    const int threadCount = 8;
    const int opsPerThread = 20;
    std::vector<std::thread> threads;
    std::atomic<int> removeSuccess{0};
    std::atomic<int> findSuccess{0};

    std::vector<GenericValues> values = {g_value1, g_value2, g_value3, g_value4, g_value5};
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY, values));

    std::function<void(std::atomic<int>&)> removeWorker = [](std::atomic<int>& success) {
        for (int i = 0; i < opsPerThread; ++i) {
            GenericValues condition;
            condition.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(i));
            int ret = SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, condition);
            if (ret == SandboxManagerRdb::SUCCESS) {
                success.fetch_add(1);
            }
        }
    };

    std::function<void(std::atomic<int>&)> findWorker = [](std::atomic<int>& success) {
        for (int i = 0; i < opsPerThread; ++i) {
            GenericValues conditions;
            GenericValues symbols;
            std::vector<GenericValues> dbResult;
            int ret = SandboxManagerRdb::GetInstance().Find(SANDBOX_MANAGER_PERSISTED_POLICY,
                conditions, symbols, dbResult);
            if (ret == SandboxManagerRdb::SUCCESS) {
                success.fetch_add(1);
            }
        }
    };

    for (int t = 0; t < threadCount; ++t) {
        if (t % 2 == 0) {
            threads.emplace_back(removeWorker, std::ref(removeSuccess));
        } else {
            threads.emplace_back(findWorker, std::ref(findSuccess));
        }
    }

    for (auto &th : threads) {
        th.join();
    }

    EXPECT_EQ((threadCount / 2) * opsPerThread, removeSuccess.load());
    EXPECT_EQ((threadCount / 2) * opsPerThread, findSuccess.load());

    GenericValues clearConditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, clearConditions);
}

/**
 * @tc.name: SandboxManagerRdbTest_ConcurrentModify
 * @tc.desc: Test concurrent Modify on the same table, verify no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest_ConcurrentModify, TestSize.Level0)
{
    const int threadCount = 6;
    const int opsPerThread = 20;
    std::vector<std::thread> threads;
    std::atomic<int> modifySuccess{0};

    // Insert a single record that all threads will try to modify
    GenericValues baseValue;
    baseValue.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(999));
    baseValue.Put(PolicyFiledConst::FIELD_PATH, "/modify_target");
    baseValue.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(1));
    baseValue.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(2));
    baseValue.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(0));
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY, {baseValue}));

    std::function<void(int, std::atomic<int>&)> modifyWorker =
        [opsPerThread](int tid, std::atomic<int>& success) {
            for (int i = 0; i < opsPerThread; ++i) {
                GenericValues modifyValue;
                modifyValue.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(tid));

                GenericValues condition;
                condition.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(999));
                condition.Put(PolicyFiledConst::FIELD_PATH, "/modify_target");

                int ret = SandboxManagerRdb::GetInstance().Modify(SANDBOX_MANAGER_PERSISTED_POLICY,
                    modifyValue, condition);
                if (ret == SandboxManagerRdb::SUCCESS) {
                    success.fetch_add(1);
                }
            }
        };

    for (int t = 0; t < threadCount; ++t) {
        threads.emplace_back(modifyWorker, t, std::ref(modifySuccess));
    }

    for (auto &th : threads) {
        th.join();
    }

    EXPECT_EQ(threadCount * opsPerThread, modifySuccess.load());

    // Verify final state: record should still exist and be consistent
    GenericValues queryCondition;
    queryCondition.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(999));
    queryCondition.Put(PolicyFiledConst::FIELD_PATH, "/modify_target");
    GenericValues querySymbols;
    std::vector<GenericValues> results;
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Find(
        SANDBOX_MANAGER_PERSISTED_POLICY, queryCondition, querySymbols, results));
    ASSERT_EQ(1u, results.size());

    // Other fields should remain intact
    EXPECT_EQ(999, results[0].GetInt(PolicyFiledConst::FIELD_TOKENID));
    EXPECT_EQ(1, results[0].GetInt(PolicyFiledConst::FIELD_MODE));
    EXPECT_EQ(2, results[0].GetInt(PolicyFiledConst::FIELD_DEPTH));

    // Clean up: remove all records
    GenericValues clearConditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, clearConditions);
}

/**
 * @tc.name: SandboxManagerRdbTest_DbLifecycle_ReopenAndClose
 * @tc.desc: Test repeated db open, cleanup, and reopen cycles
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest_DbLifecycle_ReopenAndClose, TestSize.Level0)
{
    const int cycleCount = 5;

    for (int i = 0; i < cycleCount; ++i) {
        // Ensure db_ is closed
        SandboxManagerRdb::GetInstance().CleanupDbInternal();
        EXPECT_EQ(nullptr, SandboxManagerRdb::GetInstance().db_);

        // Operation should auto-reopen db_
        std::vector<GenericValues> values;
        GenericValues value;
        value.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(i));
        value.Put(PolicyFiledConst::FIELD_PATH, "/lifecycle/" + std::to_string(i));
        value.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(1));
        value.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(1));
        value.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(0));
        values.push_back(value);

        EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY, values));
        EXPECT_NE(nullptr, SandboxManagerRdb::GetInstance().db_);

        // Verify the record was inserted
        int32_t count = -1;
        int32_t ret = SandboxManagerRdb::GetInstance().GetRecordCount(SANDBOX_MANAGER_PERSISTED_POLICY, count);
        EXPECT_EQ(SandboxManagerRdb::SUCCESS, ret);
        EXPECT_EQ(i + 1, count);
    }

    // Clean up: remove all records
    GenericValues clearConditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, clearConditions);
}

/**
 * @tc.name: SandboxManagerRdbTest_ConcurrentFindAndCleanup
 * @tc.desc: Test concurrent Find and CleanupDbInternal, verify readers survive db_ being closed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerRdbTest, SandboxManagerRdbTest_ConcurrentFindAndCleanup, TestSize.Level0)
{
    const int findThreadCount = 4;
    const int opsPerThread = 30;
    const int cleanupThreadCount = 2;

    // Insert baseline data
    std::vector<GenericValues> values = {g_value1, g_value2, g_value3, g_value4, g_value5};
    EXPECT_EQ(0, SandboxManagerRdb::GetInstance().Add(SANDBOX_MANAGER_PERSISTED_POLICY, values));

    std::vector<std::thread> threads;
    std::atomic<int> findSuccess{0};
    std::atomic<int> cleanupCount{0};
    std::atomic<bool> stopCleanup{false};

    std::function<void(std::atomic<int>&)> findWorker = [opsPerThread](std::atomic<int>& success) {
        for (int i = 0; i < opsPerThread; ++i) {
            GenericValues conditions;
            GenericValues symbols;
            std::vector<GenericValues> dbResult;
            int ret = SandboxManagerRdb::GetInstance().Find(SANDBOX_MANAGER_PERSISTED_POLICY,
                conditions, symbols, dbResult);
            if (ret == SandboxManagerRdb::SUCCESS) {
                success.fetch_add(1);
            }
        }
    };

    std::function<void(std::atomic<int>&, std::atomic<bool>&)> cleanupWorker =
        [](std::atomic<int>& count, std::atomic<bool>& stop) {
            while (!stop.load()) {
                SandboxManagerRdb::GetInstance().CleanupDbInternal();
                count.fetch_add(1);
                usleep(10000);
            }
        };

    // Find threads: continuously read data
    for (int t = 0; t < findThreadCount; ++t) {
        threads.emplace_back(findWorker, std::ref(findSuccess));
    }

    // Cleanup threads: repeatedly close db_
    for (int t = 0; t < cleanupThreadCount; ++t) {
        threads.emplace_back(cleanupWorker, std::ref(cleanupCount), std::ref(stopCleanup));
    }

    // Wait for find threads to finish
    for (int t = 0; t < findThreadCount; ++t) {
        threads[t].join();
    }

    // Stop cleanup threads
    stopCleanup.store(true);
    for (size_t t = findThreadCount; t < threads.size(); ++t) {
        threads[t].join();
    }

    // All reads should succeed
    EXPECT_EQ(findThreadCount * opsPerThread, findSuccess.load());

    // Clean up: remove all records
    GenericValues clearConditions;
    SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, clearConditions);
}
} // SandboxManager
} // AccessControl
} // OHOS
