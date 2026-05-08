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
#include "share_files.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_service.h"
#include "sandbox_test_common.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
#ifdef DEC_ENABLED
const size_t MAX_JSON_SIZE = 5 * 1024 * 1024;
#endif
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

#ifdef DEC_ENABLED
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
#endif
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
