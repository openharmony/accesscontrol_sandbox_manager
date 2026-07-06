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
#include "shared_directory_info_vec_raw_data.h"
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

SharedDirectoryInfo CreateTestInfo(const std::string &bundleName, const std::string &path, uint32_t permissionMode)
{
    SharedDirectoryInfo info;
    info.bundleName = bundleName;
    info.path = path;
    info.permissionMode = static_cast<OperateMode>(permissionMode);
    return info;
}

/**
 * @tc.name: PolicyInfoParcel001
 * @tc.desc: Test PolicyInfo Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerParcelTest, PolicyInfoParcel001, TestSize.Level0)
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
 * @tc.desc: Test Unmarshalling truncates path at embedded '\0'
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerParcelTest, PolicyInfoParcel002, TestSize.Level0)
{
    // Construct a path with embedded '\0': "/data/files\0garbage"
    std::string rawPath = "/data/files";
    rawPath.push_back('\0');
    rawPath.append("garbage");

    Parcel parcel;
    parcel.WriteString(rawPath);
    parcel.WriteUint64(0b01);

    parcel.RewindRead(0);
    std::shared_ptr<PolicyInfoParcel> readedData(PolicyInfoParcel::Unmarshalling(parcel));
    ASSERT_NE(nullptr, readedData);

    // path should be truncated at '\0', resulting in "/data/files" (11 chars)
    EXPECT_EQ(std::string("/data/files"), readedData->policyInfo.path);
    EXPECT_EQ(11u, readedData->policyInfo.path.length());
    EXPECT_EQ(0b01u, readedData->policyInfo.mode);
}

/**
 * @tc.name: SharedDirectoryInfoVecRawData_001
 * @tc.desc: Test normal Marshalling/Unmarshalling with single element
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerParcelTest, SharedDirectoryInfoVecRawData_001, TestSize.Level0)
{
    SharedDirectoryInfoVecRawData rawData;
    std::vector<SharedDirectoryInfo> input;
    input.push_back(CreateTestInfo("com.example.app", "/base/files", 0b11));

    int32_t ret = rawData.Marshalling(input);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    EXPECT_NE(nullptr, rawData.data);
    EXPECT_GT(rawData.size, 0);

    std::vector<SharedDirectoryInfo> output;
    ret = rawData.Unmarshalling(output);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ASSERT_EQ(1u, output.size());
    EXPECT_EQ("com.example.app", output[0].bundleName);
    EXPECT_EQ("/base/files", output[0].path);
    EXPECT_EQ(0b11u, output[0].permissionMode);
}

/**
 * @tc.name: SharedDirectoryInfoVecRawData_002
 * @tc.desc: Test Marshalling/Unmarshalling with empty vector
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerParcelTest, SharedDirectoryInfoVecRawData_002, TestSize.Level0)
{
    SharedDirectoryInfoVecRawData rawData;
    std::vector<SharedDirectoryInfo> input;

    int32_t ret = rawData.Marshalling(input);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    std::vector<SharedDirectoryInfo> output;
    ret = rawData.Unmarshalling(output);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    EXPECT_TRUE(output.empty());
}

/**
 * @tc.name: SharedDirectoryInfoVecRawData_003
 * @tc.desc: Test Marshalling/Unmarshalling with multiple elements
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerParcelTest, SharedDirectoryInfoVecRawData_003, TestSize.Level0)
{
    SharedDirectoryInfoVecRawData rawData;
    std::vector<SharedDirectoryInfo> input;
 
    for (int i = 0; i < 100; i++) {
        input.push_back(CreateTestInfo("com.example.app" + std::to_string(i),
                                       "/base/files/" + std::to_string(i),
                                       0b01));
    }

    int32_t ret = rawData.Marshalling(input);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);

    std::vector<SharedDirectoryInfo> output;
    ret = rawData.Unmarshalling(output);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    EXPECT_EQ(100u, output.size());

    EXPECT_EQ("com.example.app0", output[0].bundleName);
    EXPECT_EQ("com.example.app99", output[99].bundleName);
}

/**
 * @tc.name: SharedDirectoryInfoVecRawData_004
 * @tc.desc: Test Unmarshalling with corrupted data (truncated)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerParcelTest, SharedDirectoryInfoVecRawData_004, TestSize.Level0)
{
    SharedDirectoryInfoVecRawData rawData;
    std::vector<SharedDirectoryInfo> input;
    input.push_back(CreateTestInfo("com.example.app", "/base/files", 0b11));
    (void)rawData.Marshalling(input);

    rawData.size = 2;  // corrupted data

    std::vector<SharedDirectoryInfo> output;
    int32_t ret = rawData.Unmarshalling(output);
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_PARCEL_ERR, ret);
    EXPECT_TRUE(output.empty());
}
} // SandboxManager
} // AccessControl
} // OHOS