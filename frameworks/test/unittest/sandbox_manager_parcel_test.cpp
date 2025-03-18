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

#include <gtest/gtest.h>
#include "parcel.h"
#include "parcel_utils.h"
#include "policy_info.h"
#include "policy_info_parcel.h"
#include "policy_info_vector_parcel.h"
#include <string>
#include <vector>

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class SandboxManagerParcelTest : public testing::Test  {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

PolicyInfo g_info1 = {
    .path = "path1",
    .mode = 0b01,
};

PolicyInfo g_info2 = {
    .path = "path2",
    .mode = 0b10,
};

PolicyInfo g_info3 = {
    .path = "path3",
    .mode = 0b11,
};

void SandboxManagerParcelTest::SetUpTestCase(void)
{}

void SandboxManagerParcelTest::TearDownTestCase(void)
{}

void SandboxManagerParcelTest::SetUp(void)
{}

void SandboxManagerParcelTest::TearDown(void)
{}


/**
 * @tc.name: PolicyInfoParcel001
 * @tc.desc: Test PolicyInfo Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerParcelTest, PolicyInfoParcel001, TestSize.Level1)
{
    PolicyInfoParcel policyInfoParcel;
    policyInfoParcel.policyInfo = g_info1;

    Parcel parcel;
    EXPECT_EQ(true, policyInfoParcel.Marshalling(parcel));

    std::shared_ptr<PolicyInfoParcel> readedData(PolicyInfoParcel::Unmarshalling(parcel));
    ASSERT_NE(nullptr, readedData);

    EXPECT_EQ(g_info1.path, readedData->policyInfo.path);
    EXPECT_EQ(g_info1.mode, readedData->policyInfo.mode);
}

/**
 * @tc.name: PolicyInfoParcel002
 * @tc.desc: Test PolicyInfoVector Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerParcelTest, PolicyInfoParcel002, TestSize.Level1)
{
    PolicyInfoVectorParcel policyInfoVectorParcel;
    std::vector<PolicyInfo> policyVector;
    policyVector.emplace_back(g_info1);
    policyVector.emplace_back(g_info2);
    policyVector.emplace_back(g_info3);

    policyInfoVectorParcel.policyVector = policyVector;

    Parcel parcel;
    EXPECT_EQ(true, policyInfoVectorParcel.Marshalling(parcel));

    std::shared_ptr<PolicyInfoVectorParcel> readedData(PolicyInfoVectorParcel::Unmarshalling(parcel));
    ASSERT_NE(nullptr, readedData);

    EXPECT_EQ(g_info1.path, readedData->policyVector[0].path);
    EXPECT_EQ(g_info1.mode, readedData->policyVector[0].mode);
    EXPECT_EQ(g_info2.path, readedData->policyVector[1].path);
    EXPECT_EQ(g_info2.mode, readedData->policyVector[1].mode);
    EXPECT_EQ(g_info3.path, readedData->policyVector[2].path);
    EXPECT_EQ(g_info3.mode, readedData->policyVector[2].mode);
}

/**
 * @tc.name: PolicyInfoParcel003
 * @tc.desc: Test PolicyInfoVector Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerParcelTest, PolicyInfoParcel003, TestSize.Level1)
{
    PolicyInfoVectorParcel policyInfoVectorParcel;
    std::vector<PolicyInfo> policyVector;
    for (int i = 0; i < 550; i++) {
        policyVector.emplace_back(g_info1);
    }
    policyInfoVectorParcel.policyVector = policyVector;
    Parcel parcel;
    EXPECT_EQ(true, policyInfoVectorParcel.Marshalling(parcel));

    std::shared_ptr<PolicyInfoVectorParcel> readedData(PolicyInfoVectorParcel::Unmarshalling(parcel));
    ASSERT_NE(nullptr, readedData);
    for (int i = 0; i < 550; i++) {
        EXPECT_EQ(g_info1.path, readedData->policyVector[i].path);
    }
}

/**
 * @tc.name: PolicyInfoParcel004
 * @tc.desc: Test PolicyInfoVector Marshalling/Unmarshalling, no actual policyinfo messages
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerParcelTest, PolicyInfoParcel004, TestSize.Level1)
{
    Parcel parcel;
    uint32_t maxSize = 5000;
    EXPECT_EQ(true, parcel.WriteUint32(maxSize + 1));

    std::shared_ptr<PolicyInfoVectorParcel> readedData(PolicyInfoVectorParcel::Unmarshalling(parcel));
    ASSERT_EQ(nullptr, readedData);
}
} // SandboxManager
} // AccessControl
} // OHOS