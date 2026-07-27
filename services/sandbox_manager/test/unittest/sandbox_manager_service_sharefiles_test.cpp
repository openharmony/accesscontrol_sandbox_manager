/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <string>
#define private public  // NOLINT
#include "share_files.h"
#undef private
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_service.h"
#include "sandbox_test_common.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
const size_t MAX_JSON_SIZE = 5 * 1024 * 1024;
} // namespace

class SandboxManagerServiceSharefilesTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void SandboxManagerServiceSharefilesTest::SetUpTestCase()
{}

void SandboxManagerServiceSharefilesTest::TearDownTestCase()
{}

void SandboxManagerServiceSharefilesTest::SetUp()
{
    auto service = DelayedSingleton<SandboxManagerService>::GetInstance();
    ASSERT_NE(nullptr, service);
}

void SandboxManagerServiceSharefilesTest::TearDown()
{}

/**
 * @tc.name: SetShareFileInfoTest001
 * @tc.desc: SetShareFileInfo with invalid tokenId (0).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, SetShareFileInfoTest001, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 0;

    int32_t ret = SandboxManagerShare::GetInstance().SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: SetShareFileInfoTest002
 * @tc.desc: SetShareFileInfo with empty bundleName.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, SetShareFileInfoTest002, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: SetShareFileInfoTest003
 * @tc.desc: SetShareFileInfo with empty cfginfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, SetShareFileInfoTest003, TestSize.Level0)
{
    std::string cfginfo = "";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: SetShareFileInfoTest004
 * @tc.desc: SetShareFileInfo with oversized cfginfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, SetShareFileInfoTest004, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r+w"
        }
    })";
    cfginfo.append(MAX_JSON_SIZE, 'x');
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: SetShareFileInfoTest005
 * @tc.desc: SetShareFileInfo without share_files.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, SetShareFileInfoTest005, TestSize.Level0)
{
    std::string cfginfo = R"({})";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: SetShareFileInfoTest006
 * @tc.desc: SetShareFileInfo with share_files missing sharingOSPath/Subpath/mode.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, SetShareFileInfoTest006, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ]
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: SetShareFileInfoTest007
 * @tc.desc: SetShareFileInfo with sharingOSPath but no scopes array.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, SetShareFileInfoTest007, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: SetShareFileInfoTest008
 * @tc.desc: SetShareFileInfo with empty sharingOSPath.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, SetShareFileInfoTest008, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: SetShareFileInfoTest009
 * @tc.desc: SetShareFileInfo with sharingOSPath not in scopes.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, SetShareFileInfoTest009, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/haps",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: SetShareFileInfoTest010
 * @tc.desc: SetShareFileInfo with valid path, scopes mode=r, permission=r.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, SetShareFileInfoTest010, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ret = SandboxManagerShare::GetInstance().UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: SetShareFileInfoTest011
 * @tc.desc: SetShareFileInfo with valid path, scopes mode=r+w, permission=r+w.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, SetShareFileInfoTest011, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ret = SandboxManagerShare::GetInstance().UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: SetShareFileInfoTest012
 * @tc.desc: SetShareFileInfo with valid path, scopes mode=r+w, permission=r.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, SetShareFileInfoTest012, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ret = SandboxManagerShare::GetInstance().UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: SetShareFileInfoTest013
 * @tc.desc: SetShareFileInfo with valid path, scopes mode=r, permission=r+w.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, SetShareFileInfoTest013, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: SetShareFileInfoTest014
 * @tc.desc: SetShareFileInfo with valid path and mode but no subpath.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, SetShareFileInfoTest014, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: SetShareFileInfoTest015
 * @tc.desc: SetShareFileInfo with valid path and mode but empty subpath.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, SetShareFileInfoTest015, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ret = SandboxManagerShare::GetInstance().UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: SetShareFileInfoTest016
 * @tc.desc: SetShareFileInfo with subpath length exceeding 32.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, SetShareFileInfoTest016, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/testfiletestfiletestfiletestfile",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: SetShareFileInfoTest017
 * @tc.desc: SetShareFileInfo with subpath containing /./.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, SetShareFileInfoTest017, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/./test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: SetShareFileInfoTest018
 * @tc.desc: SetShareFileInfo with subpath containing /../.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, SetShareFileInfoTest018, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/../test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: SetShareFileInfoTest019
 * @tc.desc: SetShareFileInfo with subpath containing null character.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, SetShareFileInfoTest019, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/t\0est",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest001
 * @tc.desc: UpdateShareFileInfo with invalid tokenId (0).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest001, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 0;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest002
 * @tc.desc: UpdateShareFileInfo with empty bundleName.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest002, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest003
 * @tc.desc: UpdateShareFileInfo with empty cfginfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest003, TestSize.Level0)
{
    std::string cfginfo = "";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest004
 * @tc.desc: UpdateShareFileInfo with oversized cfginfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest004, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r+w"
        }
    })";
    cfginfo.append(MAX_JSON_SIZE, 'x');
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest005
 * @tc.desc: UpdateShareFileInfo without share_files.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest005, TestSize.Level0)
{
    std::string cfginfo = R"({})";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest006
 * @tc.desc: UpdateShareFileInfo with share_files missing sharingOSPath/Subpath/mode.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest006, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ]
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest007
 * @tc.desc: UpdateShareFileInfo with sharingOSPath but no scopes array.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest007, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest008
 * @tc.desc: UpdateShareFileInfo with empty sharingOSPath.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest008, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest009
 * @tc.desc: UpdateShareFileInfo with sharingOSPath not in scopes.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest009, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/haps",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest010
 * @tc.desc: UpdateShareFileInfo with valid path, scopes mode=r, permission=r.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest010, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ret = SandboxManagerShare::GetInstance().UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest011
 * @tc.desc: UpdateShareFileInfo with valid path, scopes mode=r+w, permission=r+w.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest011, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ret = SandboxManagerShare::GetInstance().UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest012
 * @tc.desc: UpdateShareFileInfo with valid path, scopes mode=r+w, permission=r.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest012, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ret = SandboxManagerShare::GetInstance().UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest013
 * @tc.desc: UpdateShareFileInfo with valid path, scopes mode=r, permission=r+w.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest013, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest014
 * @tc.desc: UpdateShareFileInfo with valid path and mode but no subpath.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest014, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest015
 * @tc.desc: UpdateShareFileInfo with valid path and mode but empty subpath.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest015, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ret = SandboxManagerShare::GetInstance().UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest016
 * @tc.desc: UpdateShareFileInfo with subpath length exceeding 32.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest016, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/testfiletestfiletestfiletestfile",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest017
 * @tc.desc: UpdateShareFileInfo with subpath containing /./.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest017, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/./test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest018
 * @tc.desc: UpdateShareFileInfo with subpath containing /../.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest018, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/../test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest019
 * @tc.desc: UpdateShareFileInfo with subpath containing null character.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest019, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/t\0est",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest020
 * @tc.desc: UpdateShareFileInfo with /el2 path, scopes mode=r+w, permission=r+w.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest020, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/el2/base/files",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ret = SandboxManagerShare::GetInstance().UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest021
 * @tc.desc: UpdateShareFileInfo with /el2 path, scopes mode=r+w, permission=r+w.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest021, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/el2/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/base/files",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ret = SandboxManagerShare::GetInstance().UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest022
 * @tc.desc: UpdateShareFileInfo with /el2 path, scopes mode=r+w, permission=r+w.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UpdateShareFileInfoTest022, TestSize.Level0)
{
    std::string cfginfo = R"({
        "share_files": {
            "scopes": [
                {
                    "path": "/el2/base/files",
                    "permission": "r+w"
                }
            ],
            "sharingOSPath": "/el2/base/files",
            "sharingOSSubpath": "/test",
            "sharingOSPermission": "r+w"
        }
    })";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ret = SandboxManagerShare::GetInstance().UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: UnsetShareFileInfoTest001
 * @tc.desc: UnsetShareFileInfo with normal input.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UnsetShareFileInfoTest001, TestSize.Level0)
{
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
}

/**
 * @tc.name: UnsetShareFileInfoTest002
 * @tc.desc: UnsetShareFileInfo with invalid tokenId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UnsetShareFileInfoTest002, TestSize.Level0)
{
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 0;

    int32_t ret = SandboxManagerShare::GetInstance().UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: UnsetShareFileInfoTest003
 * @tc.desc: UnsetShareFileInfo with empty bundleName.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, UnsetShareFileInfoTest003, TestSize.Level0)
{
    std::string bundleName = "";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerShare::GetInstance().UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
}

/**
 * @tc.name: IsPathSecureTest_Normal
 * @tc.desc: IsPathSecure returns true for normal valid paths.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, IsPathSecureTest_Normal, TestSize.Level0)
{
    EXPECT_TRUE(SandboxManagerShare::IsPathSecure("/data/storage/el2/base/files/test.txt"));
}

/**
 * @tc.name: IsPathSecureTest_EmbeddedNull
 * @tc.desc: IsPathSecure returns false for paths with embedded null bytes.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, IsPathSecureTest_EmbeddedNull, TestSize.Level0)
{
    std::string pathWithNull = std::string("/data/storage/") + '\0' + "el2/base";
    EXPECT_FALSE(SandboxManagerShare::IsPathSecure(pathWithNull));

    std::string pathWithNull2 = std::string("/data/storage/el2") + '\0' + "/base/files/test.txt";
    EXPECT_FALSE(SandboxManagerShare::IsPathSecure(pathWithNull2));
}

/**
 * @tc.name: IsPathSecureTest_EmptyPath
 * @tc.desc: IsPathSecure returns false for empty path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, IsPathSecureTest_EmptyPath, TestSize.Level0)
{
    EXPECT_FALSE(SandboxManagerShare::IsPathSecure(""));
}

/**
 * @tc.name: IsPathSecureTest_InvalidFormat
 * @tc.desc: IsPathSecure returns false for no leading /, trailing /, double leading //.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, IsPathSecureTest_InvalidFormat, TestSize.Level0)
{
    EXPECT_FALSE(SandboxManagerShare::IsPathSecure("data/storage/el2"));
    EXPECT_FALSE(SandboxManagerShare::IsPathSecure("/data/storage/"));
    EXPECT_FALSE(SandboxManagerShare::IsPathSecure("//data/storage/el2"));
}

/**
 * @tc.name: IsPathSecureTest_PathTraversal
 * @tc.desc: IsPathSecure returns false for paths with traversal components.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, IsPathSecureTest_PathTraversal, TestSize.Level0)
{
    EXPECT_FALSE(SandboxManagerShare::IsPathSecure("/data/storage/el2/../base"));
    EXPECT_FALSE(SandboxManagerShare::IsPathSecure("/data/storage/el2/./base"));
}

/**
 * @tc.name: PathComposeTest_ElFormat
 * @tc.desc: PathCompose with EL format path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, PathComposeTest_ElFormat, TestSize.Level0)
{
    std::string result = SandboxManagerShare::PathCompose("/el2/base", "com.example.app");
    EXPECT_EQ("/storage/Users/currentUser/appdata/el2/base/com.example.app", result);
}

/**
 * @tc.name: PathComposeTest_BaseFormat
 * @tc.desc: PathCompose with base format path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, PathComposeTest_BaseFormat, TestSize.Level0)
{
    std::string result = SandboxManagerShare::PathCompose("/base/haps", "com.example.app");
    EXPECT_EQ("/storage/Users/currentUser/appdata/el2/base/com.example.app/haps", result);
}

/**
 * @tc.name: PathComposeTest_ExtraComponents
 * @tc.desc: PathCompose with extra components.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, PathComposeTest_ExtraComponents, TestSize.Level0)
{
    std::string result = SandboxManagerShare::PathCompose("/el2/base/haps/files", "com.example.app");
    EXPECT_EQ("/storage/Users/currentUser/appdata/el2/base/com.example.app/haps/files", result);
}

/**
 * @tc.name: PathComposeTest_EmptyPath
 * @tc.desc: PathCompose with empty path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, PathComposeTest_EmptyPath, TestSize.Level0)
{
    EXPECT_EQ("", SandboxManagerShare::PathCompose("", "com.example.app"));
}

/**
 * @tc.name: PathComposeTest_EmptyName
 * @tc.desc: PathCompose with empty name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, PathComposeTest_EmptyName, TestSize.Level0)
{
    EXPECT_EQ("", SandboxManagerShare::PathCompose("/el2/base", ""));
}

/**
 * @tc.name: PathComposeTest_InsecurePath
 * @tc.desc: PathCompose with insecure path (traversal).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, PathComposeTest_InsecurePath, TestSize.Level0)
{
    EXPECT_EQ("", SandboxManagerShare::PathCompose("/el2/../base", "com.example.app"));
}

/**
 * @tc.name: PathComposeTest_InvalidFirstComponent
 * @tc.desc: PathCompose with invalid first component.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, PathComposeTest_InvalidFirstComponent, TestSize.Level0)
{
    EXPECT_EQ("", SandboxManagerShare::PathCompose("/invalid/xxx", "com.example.app"));
}

/**
 * @tc.name: PathComposeTest_SingleComponent
 * @tc.desc: PathCompose with single component (below MIN_PARTS_FORMAT).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, PathComposeTest_SingleComponent, TestSize.Level0)
{
    EXPECT_EQ("", SandboxManagerShare::PathCompose("/el2", "com.example.app"));
}

/**
 * @tc.name: PathComposeTest_DifferentElNumbers
 * @tc.desc: PathCompose with different EL numbers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, PathComposeTest_DifferentElNumbers, TestSize.Level0)
{
    EXPECT_EQ("/storage/Users/currentUser/appdata/el1/base/com.example.app",
        SandboxManagerShare::PathCompose("/el1/base", "com.example.app"));
    EXPECT_EQ("/storage/Users/currentUser/appdata/el3/base/com.example.app",
        SandboxManagerShare::PathCompose("/el3/base", "com.example.app"));
    EXPECT_EQ("/storage/Users/currentUser/appdata/el5/base/com.example.app",
        SandboxManagerShare::PathCompose("/el5/base", "com.example.app"));
}

/**
 * @tc.name: IsValidElNumberTest_Valid
 * @tc.desc: IsValidElNumber returns true for valid EL numbers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, IsValidElNumberTest_Valid, TestSize.Level0)
{
    EXPECT_TRUE(SandboxManagerShare::IsValidElNumber("el1"));
    EXPECT_TRUE(SandboxManagerShare::IsValidElNumber("el2"));
    EXPECT_TRUE(SandboxManagerShare::IsValidElNumber("el3"));
    EXPECT_TRUE(SandboxManagerShare::IsValidElNumber("el4"));
    EXPECT_TRUE(SandboxManagerShare::IsValidElNumber("el5"));
}

/**
 * @tc.name: IsValidElNumberTest_Invalid
 * @tc.desc: IsValidElNumber returns false for invalid EL numbers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, IsValidElNumberTest_Invalid, TestSize.Level0)
{
    EXPECT_FALSE(SandboxManagerShare::IsValidElNumber("el0"));
    EXPECT_FALSE(SandboxManagerShare::IsValidElNumber("el6"));
    EXPECT_FALSE(SandboxManagerShare::IsValidElNumber("EL2"));
    EXPECT_FALSE(SandboxManagerShare::IsValidElNumber("base"));
    EXPECT_FALSE(SandboxManagerShare::IsValidElNumber(""));
    EXPECT_FALSE(SandboxManagerShare::IsValidElNumber("el"));
}

/**
 * @tc.name: PermissionToModeTest_ReadMode
 * @tc.desc: PermissionToMode returns correct mode for "r".
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, PermissionToModeTest_ReadMode, TestSize.Level0)
{
    EXPECT_EQ(OperateMode::READ_MODE, SandboxManagerShare::PermissionToMode("r"));
}

/**
 * @tc.name: PermissionToModeTest_ReadWriteMode
 * @tc.desc: PermissionToMode returns correct mode for "r+w".
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, PermissionToModeTest_ReadWriteMode, TestSize.Level0)
{
    EXPECT_EQ(OperateMode::READ_MODE | OperateMode::WRITE_MODE,
        SandboxManagerShare::PermissionToMode("r+w"));
}

/**
 * @tc.name: PermissionToModeTest_Unknown
 * @tc.desc: PermissionToMode returns 0 for unknown permission string.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, PermissionToModeTest_Unknown, TestSize.Level0)
{
    EXPECT_EQ(0, SandboxManagerShare::PermissionToMode("w"));
    EXPECT_EQ(0, SandboxManagerShare::PermissionToMode("rw"));
    EXPECT_EQ(0, SandboxManagerShare::PermissionToMode(""));
    EXPECT_EQ(0, SandboxManagerShare::PermissionToMode("r+w+x"));
}

/**
 * @tc.name: NormalizeBasePathTest_BasePath
 * @tc.desc: NormalizeBasePath prepends /el2 for /base/ paths.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, NormalizeBasePathTest_BasePath, TestSize.Level0)
{
    EXPECT_EQ("/el2/base/haps", SandboxManagerShare::NormalizeBasePath("/base/haps"));
}

/**
 * @tc.name: NormalizeBasePathTest_NonBasePath
 * @tc.desc: NormalizeBasePath returns path unchanged for non-/base/ paths.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceSharefilesTest, NormalizeBasePathTest_NonBasePath, TestSize.Level0)
{
    EXPECT_EQ("/el2/base", SandboxManagerShare::NormalizeBasePath("/el2/base"));
    EXPECT_EQ("/el2/base/haps", SandboxManagerShare::NormalizeBasePath("/el2/base/haps"));
    EXPECT_EQ("/data/test", SandboxManagerShare::NormalizeBasePath("/data/test"));
    EXPECT_EQ("", SandboxManagerShare::NormalizeBasePath(""));
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
