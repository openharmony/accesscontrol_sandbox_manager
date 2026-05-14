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
#include <thread>
#include <atomic>
#include <vector>
#include <string>
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
#include "sandbox_manager_log.h"
#include "sandbox_manager_err_code.h"
#include "media_path_support.h"

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
{
    if (PolicyInfoManager::GetInstance().macAdapter_.fd_ > 0) {
        close(PolicyInfoManager::GetInstance().macAdapter_.fd_);
        PolicyInfoManager::GetInstance().macAdapter_.fd_ = -1;
        PolicyInfoManager::GetInstance().macAdapter_.isMacSupport_ = false;
    }
}

/**
 * @tc.name: MediaModeTest001
 * @tc.desc: Test CalculateOperateMode function with PERSIST_READ_IMAGEVIDEO
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MediaPathMockTest, MediaModeTest001, TestSize.Level0)
{
    std::vector<Media::PhotoPermissionType> photoPermissionList;
    photoPermissionList.push_back(Media::PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO);
    photoPermissionList.push_back(Media::PhotoPermissionType::PERSIST_READ_IMAGEVIDEO);

    int32_t result = SandboxManagerMedia::GetInstance().CalculateOperateMode(photoPermissionList);

    // Expect READ_MODE to be set due to PERSIST_READ_IMAGEVIDEO
    EXPECT_EQ(OperateMode::READ_MODE, result);
    // Verify that the photoPermissionList has been modified as expected
    // Since the mock implementation doesn't change the list, we just verify it's still valid
    EXPECT_EQ(2, photoPermissionList.size());
}

/**
 * @tc.name: MediaModeTest002
 * @tc.desc: Test CalculateOperateMode function with empty vector
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MediaPathMockTest, MediaModeTest002, TestSize.Level0)
{
    std::vector<Media::PhotoPermissionType> photoPermissionList;

    int32_t result = SandboxManagerMedia::GetInstance().CalculateOperateMode(photoPermissionList);

    EXPECT_EQ(0, result); // Empty list should return 0
    EXPECT_EQ(0, photoPermissionList.size());
}

/**
 * @tc.name: MediaModeTest003
 * @tc.desc: Test CalculateOperateMode function with all possible permission types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MediaPathMockTest, MediaModeTest003, TestSize.Level0)
{
    std::vector<Media::PhotoPermissionType> photoPermissionList;
    photoPermissionList.push_back(Media::PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO);
    photoPermissionList.push_back(Media::PhotoPermissionType::PERSIST_READ_IMAGEVIDEO);
    photoPermissionList.push_back(Media::PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO);
    photoPermissionList.push_back(Media::PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO);
    photoPermissionList.push_back(Media::PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO);
    photoPermissionList.push_back(Media::PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO);
    photoPermissionList.push_back(Media::PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO);

    int32_t result = SandboxManagerMedia::GetInstance().CalculateOperateMode(photoPermissionList);

    // Should return combined modes: READ_MODE | WRITE_MODE | (WRITE_MODE | READ_MODE) = READ_MODE | WRITE_MODE
    EXPECT_EQ(OperateMode::READ_MODE | OperateMode::WRITE_MODE, result);
    EXPECT_EQ(7, photoPermissionList.size());
}

/**
 * @tc.name: MediaPathMockTest_CancelPhotoUriPersistPermission
 * @tc.desc: Test CancelPhotoUriPersistPermission clears all permissions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MediaPathMockTest, MediaPathMockTest_CancelPhotoUriPersistPermission, TestSize.Level0)
{
    uint32_t testTokenId = 1001;
    
    // Directly use the MediaPermissionHelper to grant permissions to testTokenId
    std::vector<std::string> uris = {"/data/storage/el2/media/test1.jpg", "/data/storage/el2/media/test2.jpg"};
    std::vector<Media::PhotoPermissionType> photoPermissionTypes = {
        Media::PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        Media::PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO
    };
    
    // Access the MediaPermissionHelper instance through SandboxManagerMedia
    SandboxManagerMedia &mediaInstance = SandboxManagerMedia::GetInstance();
    int32_t initResult = mediaInstance.InitMedia();
    EXPECT_EQ(0, initResult);

    Media::MediaPermissionHelper *helper = Media::MediaPermissionHelper::GetMediaPermissionHelper();
    EXPECT_NE(nullptr, helper);

    // Step 1: Grant permissions to the test token ID
    int32_t grantResult = helper->GrantPhotoUriPermission(1000, testTokenId, uris, photoPermissionTypes,
        Media::HideSensitiveType::ALL_DESENSITIZE);
    EXPECT_EQ(0, grantResult);

    // Step 2: Verify permissions were granted
    std::vector<Media::PhotoPermissionType> retrievedPermissions;
    int32_t getResult = mediaInstance.GetPhotoUriPersistPermission(testTokenId, retrievedPermissions);
    EXPECT_EQ(0, getResult);
    EXPECT_EQ(2, retrievedPermissions.size());
    
    // Check that both expected permission types are present (order not guaranteed)
    bool hasReadPermission = false;
    bool hasWritePermission = false;
    for (const auto& perm : retrievedPermissions) {
        if (perm == Media::PhotoPermissionType::PERSIST_READ_IMAGEVIDEO) {
            hasReadPermission = true;
        } else if (perm == Media::PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO) {
            hasWritePermission = true;
        }
    }
    EXPECT_TRUE(hasReadPermission);
    EXPECT_TRUE(hasWritePermission);

    // Step 3: Cancel the persist permissions
    int32_t cancelResult = mediaInstance.CancelPhotoUriPersistPermission(testTokenId);
    EXPECT_EQ(0, cancelResult);

    // Step 4: Try to get permissions again - should be empty now after cancellation
    std::vector<Media::PhotoPermissionType> permissionsAfterCancel;
    int32_t getResultAfterCancel = mediaInstance.GetPhotoUriPersistPermission(testTokenId, permissionsAfterCancel);
    EXPECT_EQ(0, getResultAfterCancel);
    EXPECT_TRUE(permissionsAfterCancel.empty()); // Mock clears all entries
}


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
        PolicyInfoManager::GetInstance().StartAccessingPolicy(selfTokenId_, policy, result21, 0));
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

#ifdef DEC_ENABLED
/**
 * @tc.name: MediaPathMockTest006
 * @tc.desc: Test concurrent AddMediaPolicy calls - verify thread safety
 * @tc.type: FUNC
 * @tc.require: AR000GTUAB
 */
HWTEST_F(MediaPathMockTest, MediaPathMockTest006, TestSize.Level0)
{
    PolicyInfo info;
    info.path = MEDIA_PATH_1;
    info.mode = OperateMode::READ_MODE;

    constexpr int THREAD_COUNT = 5;
    std::vector<std::thread> threads;
    std::atomic<int> successCount(0);
    std::atomic<int> readyCount(0);
    std::atomic<bool> start(false);

    for (int i = 0; i < THREAD_COUNT; ++i) {
        threads.emplace_back([this, &info, &readyCount, &start, &successCount]() {
            readyCount.fetch_add(1);
            while (!start.load()) {
                std::this_thread::yield();
            }

            std::vector<PolicyInfo> policy = {info};
            std::vector<size_t> policyIndex = {0};
            std::vector<uint32_t> results;
            int32_t ret = PolicyInfoManager::GetInstance().AddPolicy(selfTokenId_, policy, results);

            if (ret == SANDBOX_MANAGER_OK && !results.empty() &&
                results[0] == SandboxRetType::OPERATE_SUCCESSFULLY) {
                successCount.fetch_add(1);
            }
        });
    }

    while (readyCount.load() < THREAD_COUNT) {
        std::this_thread::yield();
    }

    start.store(true);
    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    EXPECT_EQ(THREAD_COUNT, successCount.load());
}
#endif
} // SandboxManager
} // AccessControl
} // OHOS