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
#include "mac_adapter.h"
#include "policy_field_const.h"
#include "policy_info.h"
#define private public
#include "policy_info_manager.h"
#undef private
#include "sandbox_manager_const.h"
#include "sandbox_manager_log.h"
#include "sandbox_manager_err_code.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class MediaPathMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    uint32_t selfTokenId_;
};

#ifdef DEC_ENABLED
constexpr const char* MEDIA_PATH_1 = "/data/storage/el2/media/Photo/1/1/1.jpg";
constexpr const char* MEDIA_PATH_2 = "/data/storage/el2/media/Photo/2/2/2.jpg";
// For coverage, when input this path , will return no policy
constexpr const char* MEDIA_PATH_3 = "/data/storage/el2/media/Photo/3/3/3.jpg";
// For coverage, when input this path , will return failed
constexpr const char* MEDIA_PATH_4 = "/data/storage/el2/media/Photo/4/4/4.jpg";
#endif

void MediaPathMockTest::SetUpTestCase(void)
{}

void MediaPathMockTest::TearDownTestCase(void)
{}

void MediaPathMockTest::SetUp(void)
{
    selfTokenId_ = 0;
    PolicyInfoManager::GetInstance().Init();
}

void MediaPathMockTest::TearDown(void)
{}

#ifdef DEC_ENABLED
/**
 * @tc.name: MediaPathMockTest001
 * @tc.desc: Test AddPolicy - normal cases
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MediaPathMockTest, MediaPathMockTest001, TestSize.Level0)
{
    PolicyInfo info;
    uint64_t sizeLimit = 1;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = MEDIA_PATH_1;
    info.mode = OperateMode::READ_MODE;
    policy[0] = info;
    std::vector<uint32_t> result11;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, result11));
    EXPECT_EQ(sizeLimit, result11.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, result11[0]);
    std::vector<uint32_t> result21;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().StartAccessingPolicy(selfTokenId_, policy, result21));
    ASSERT_EQ(sizeLimit, result21.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, result21[0]);

    info.path = MEDIA_PATH_1;
    info.mode = OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> result12;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, result12));
    EXPECT_EQ(sizeLimit, result12.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, result12[0]);

    std::vector<uint32_t> result22;
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        PolicyInfoManager::GetInstance().StopAccessingPolicy(selfTokenId_, policy, result22));
    ASSERT_EQ(sizeLimit, result22.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, result22[0]);

    info.path = MEDIA_PATH_2;
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> result13;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, result13));
    EXPECT_EQ(sizeLimit, result13.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, result13[0]);

    std::vector<uint32_t> result33;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().RemovePolicy(selfTokenId_, policy, result33));
    ASSERT_EQ(sizeLimit, result33.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, result33[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: MediaPathMockTest002
 * @tc.desc: Test AddPolicy - normal cases 2
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MediaPathMockTest, MediaPathMockTest002, TestSize.Level0)
{
    PolicyInfo info;
    uint64_t sizeLimit = 1;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = MEDIA_PATH_1;
    info.mode = OperateMode::READ_MODE;
    policy[0] = info;
    std::vector<uint32_t> result11;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, result11));
    EXPECT_EQ(sizeLimit, result11.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, result11[0]);

    std::vector<uint32_t> result21;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().MatchPolicy(selfTokenId_, policy, result21));
    ASSERT_EQ(sizeLimit, result21.size());
    EXPECT_EQ(SandboxRetType::OPERATE_SUCCESSFULLY, result21[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: MediaPathMockTest002
 * @tc.desc: Test AddPolicy - normal cases 2
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MediaPathMockTest, MediaPathMockTest003, TestSize.Level0)
{
    PolicyInfo info;
    uint64_t sizeLimit = 1;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = MEDIA_PATH_3;
    info.mode = OperateMode::READ_MODE;
    policy[0] = info;
    std::vector<uint32_t> result11;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, result11));
    EXPECT_EQ(sizeLimit, result11.size());
    EXPECT_EQ(SandboxRetType::FORBIDDEN_TO_BE_PERSISTED, result11[0]);

    std::vector<uint32_t> result21;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().MatchPolicy(selfTokenId_, policy, result21));
    ASSERT_EQ(sizeLimit, result21.size());
    EXPECT_EQ(SandboxRetType::POLICY_HAS_NOT_BEEN_PERSISTED, result21[0]);

    std::vector<uint32_t> result33;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().RemovePolicy(selfTokenId_, policy, result33));
    ASSERT_EQ(sizeLimit, result33.size());
    EXPECT_EQ(SandboxRetType::POLICY_HAS_NOT_BEEN_PERSISTED, result33[0]);
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: MediaPathMockTest004
 * @tc.desc: Test AddPolicy - Abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MediaPathMockTest, MediaPathMockTest004, TestSize.Level0)
{
    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = MEDIA_PATH_4;
    info.mode = OperateMode::READ_MODE;
    policy[0] = info;
    std::vector<uint32_t> result11;
    EXPECT_EQ(SANDBOX_MANAGER_MEDIA_CALL_ERR,
        PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, result11));
    std::vector<uint32_t> result21;
    EXPECT_EQ(SANDBOX_MANAGER_MEDIA_CALL_ERR,
        PolicyInfoManager::GetInstance().MatchPolicy(selfTokenId_, policy, result21));
    std::vector<uint32_t> result31;
    EXPECT_EQ(SANDBOX_MANAGER_MEDIA_CALL_ERR,
        PolicyInfoManager::GetInstance().RemovePolicy(selfTokenId_, policy, result31));
}
#endif

#ifdef DEC_ENABLED
/**
 * @tc.name: MediaPathMockTest005
 * @tc.desc: Test AddPolicy - Abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MediaPathMockTest, MediaPathMockTest005, TestSize.Level0)
{
    PolicyInfo info;
    uint64_t sizeLimit = 1;
    std::vector<PolicyInfo> policy;
    policy.emplace_back(info);

    info.path = MEDIA_PATH_1;
    info.mode = OperateMode::READ_MODE + OperateMode::WRITE_MODE + OperateMode::READ_MODE + OperateMode::WRITE_MODE;
    policy[0] = info;
    std::vector<uint32_t> result11;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, result11));
    EXPECT_EQ(sizeLimit, result11.size());
    EXPECT_EQ(SandboxRetType::INVALID_MODE, result11[0]);

    std::vector<uint32_t> result21;
    EXPECT_EQ(INVALID_PARAMTER, PolicyInfoManager::GetInstance().MatchPolicy(selfTokenId_, policy, result21));

    std::vector<uint32_t> result31;
    EXPECT_EQ(SANDBOX_MANAGER_OK, PolicyInfoManager::GetInstance().RemovePolicy(selfTokenId_, policy, result31));
    EXPECT_EQ(sizeLimit, result11.size());
    EXPECT_EQ(SandboxRetType::INVALID_MODE, result31[0]);
}
#endif
} // SandboxManager
} // AccessControl
} // OHOS