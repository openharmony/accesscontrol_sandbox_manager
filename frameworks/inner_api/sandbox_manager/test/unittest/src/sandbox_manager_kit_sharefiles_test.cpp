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

#include "sandbox_manager_kit_sharefiles_test.h"

#include <cstdint>
#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <vector>
#include "accesstoken_kit.h"
#include "policy_info.h"
#include "securec.h"
#include "sandbox_manager_client.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"
#include "sandbox_manager_kit.h"
#include "sandbox_test_common.h"
#include "token_setproc.h"
#include "os_account_manager.h"
#include "shared_directory_info_vec_raw_data.h"

#define HM_DEC_IOCTL_BASE 's'
#define HM_DENY_POLICY_ID 6
#define DENY_DEC_POLICY_CMD _IOW(HM_DEC_IOCTL_BASE, HM_DENY_POLICY_ID, struct SandboxPolicyInfo)

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
const std::string SET_POLICY_PERMISSION = "ohos.permission.SET_SANDBOX_POLICY";
const std::string CHECK_POLICY_PERMISSION = "ohos.permission.CHECK_SANDBOX_POLICY";
const std::string ACCESS_PERSIST_PERMISSION = "ohos.permission.FILE_ACCESS_PERSIST";
const std::string FILE_ACCESS_PERMISSION = "ohos.permission.FILE_ACCESS_MANAGER";
const size_t MAX_POLICY_NUM = 8;
const int DEC_POLICY_HEADER_RESERVED = 64;
uint32_t g_selfTokenId;
uint32_t g_mockToken;
#ifdef DEC_ENABLED
const int32_t FOUNDATION_UID = 5523;
const size_t MAX_JSON_SIZE = 5 * 1024 * 1024;
#endif
Security::AccessToken::PermissionStateFull g_testState1 = {
    .permissionName = SET_POLICY_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_testState2 = {
    .permissionName = ACCESS_PERSIST_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_testState3 = {
    .permissionName = CHECK_POLICY_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_testState4 = {
    .permissionName = FILE_ACCESS_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::HapInfoParams g_testInfoParms = {
    .userID = 100,
    .bundleName = "sandbox_manager_test",
    .instIndex = 0,
    .appIDDesc = "test"
};

Security::AccessToken::HapPolicyParams g_testPolicyPrams = {
    .apl = Security::AccessToken::APL_NORMAL,
    .domain = "test.domain",
    .permList = {},
    .permStateList = {g_testState1, g_testState2, g_testState3, g_testState4}
};
};

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

static int SetDeny(const std::string& path)
{
    struct PathInfo info;
    string infoPath = path;
    info.path = const_cast<char *>(infoPath.c_str());
    info.pathLen = infoPath.length();
    struct SandboxPolicyInfo policyInfo;
    policyInfo.tokenId = g_mockToken;
    policyInfo.pathInfos[0] = info;
    policyInfo.pathNum = 1;
    policyInfo.persist = true;

    auto fd = open("/dev/dec", O_RDWR);
    if (fd < 0) {
        std::cout << "fd open err" << std::endl;
        return fd;
    }
    auto ret = ioctl(fd, DENY_DEC_POLICY_CMD, &policyInfo);
    std::cout << "set deny ret: " << ret << std::endl;
    close(fd);
    return ret;
}
void SandboxManagerKitSharefilesTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    SetDeny("/A");
    SetDeny("/C/D");
    SetDeny("/data/temp");
}

void SandboxManagerKitSharefilesTest::TearDownTestCase()
{
    Security::AccessToken::AccessTokenKit::DeleteToken(g_mockToken);
}

void SandboxManagerKitSharefilesTest::SetUp()
{
    EXPECT_TRUE(MockTokenId("foundation"));
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
    EXPECT_NE(0, tokenIdEx.tokenIdExStruct.tokenID);
    g_mockToken = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_EQ(0, SetSelfTokenID(g_mockToken));
}

void SandboxManagerKitSharefilesTest::TearDown()
{
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
}

#ifdef DEC_ENABLED
/**
 * @tc.name: SetShareFileInfoTest001
 * @tc.desc: SetShareFileInfo with non-BMS process.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, SetShareFileInfoTest001, TestSize.Level0)
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

    int32_t ret = SandboxManagerKit::SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(PERMISSION_DENIED, ret);
}

/**
 * @tc.name: SetShareFileInfoTest002
 * @tc.desc: SetShareFileInfo with invalid tokenId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, SetShareFileInfoTest002, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: SetShareFileInfoTest003
 * @tc.desc: SetShareFileInfo with empty bundleName.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, SetShareFileInfoTest003, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: SetShareFileInfoTest004
 * @tc.desc: SetShareFileInfo with empty cfginfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, SetShareFileInfoTest004, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
    std::string cfginfo = "";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerKit::SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    setuid(uid);
}

/**
 * @tc.name: SetShareFileInfoTest005
 * @tc.desc: SetShareFileInfo with oversized cfginfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, SetShareFileInfoTest005, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_REMOTE_ERR, ret);
    setuid(uid);
}

/**
 * @tc.name: SetShareFileInfoTest006
 * @tc.desc: SetShareFileInfo without share_files.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, SetShareFileInfoTest006, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
    std::string cfginfo = R"({})";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerKit::SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    setuid(uid);
}

/**
 * @tc.name: SetShareFileInfoTest007
 * @tc.desc: SetShareFileInfo with share_files missing sharingOSPath/Subpath/mode.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, SetShareFileInfoTest007, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    setuid(uid);
}

/**
 * @tc.name: SetShareFileInfoTest008
 * @tc.desc: SetShareFileInfo with sharingOSPath but no scopes array.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, SetShareFileInfoTest008, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: SetShareFileInfoTest009
 * @tc.desc: SetShareFileInfo with empty sharingOSPath.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, SetShareFileInfoTest009, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: SetShareFileInfoTest010
 * @tc.desc: SetShareFileInfo with sharingOSPath not in scopes.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, SetShareFileInfoTest010, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: SetShareFileInfoTest011
 * @tc.desc: SetShareFileInfo with valid path, scopes mode=r, permission=r.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, SetShareFileInfoTest011, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ret = SandboxManagerKit::UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    setuid(uid);
}

/**
 * @tc.name: SetShareFileInfoTest012
 * @tc.desc: SetShareFileInfo with valid path, scopes mode=r+w, permission=r+w.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, SetShareFileInfoTest012, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ret = SandboxManagerKit::UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    setuid(uid);
}

/**
 * @tc.name: SetShareFileInfoTest013
 * @tc.desc: SetShareFileInfo with valid path, scopes mode=r+w, permission=r.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, SetShareFileInfoTest013, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ret = SandboxManagerKit::UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    setuid(uid);
}

/**
 * @tc.name: SetShareFileInfoTest014
 * @tc.desc: SetShareFileInfo with valid path, scopes mode=r, permission=r+w.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, SetShareFileInfoTest014, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: SetShareFileInfoTest015
 * @tc.desc: SetShareFileInfo with valid path and mode but no subpath.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, SetShareFileInfoTest015, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: SetShareFileInfoTest016
 * @tc.desc: SetShareFileInfo with valid path and mode but empty subpath.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, SetShareFileInfoTest016, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ret = SandboxManagerKit::UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    setuid(uid);
}

/**
 * @tc.name: SetShareFileInfoTest017
 * @tc.desc: SetShareFileInfo with subpath length exceeding 32.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, SetShareFileInfoTest017, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: SetShareFileInfoTest018
 * @tc.desc: SetShareFileInfo with subpath containing /./.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, SetShareFileInfoTest018, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: SetShareFileInfoTest019
 * @tc.desc: SetShareFileInfo with subpath containing /../.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, SetShareFileInfoTest019, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: SetShareFileInfoTest020
 * @tc.desc: SetShareFileInfo with subpath containing null character.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, SetShareFileInfoTest020, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::SetShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: UpdateShareFileInfoTest001
 * @tc.desc: UpdateShareFileInfo with non-BMS process.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UpdateShareFileInfoTest001, TestSize.Level0)
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

    int32_t ret = SandboxManagerKit::UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(PERMISSION_DENIED, ret);
}

/**
 * @tc.name: UpdateShareFileInfoTest002
 * @tc.desc: UpdateShareFileInfo with invalid tokenId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UpdateShareFileInfoTest002, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: UpdateShareFileInfoTest003
 * @tc.desc: UpdateShareFileInfo with empty bundleName.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UpdateShareFileInfoTest003, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: UpdateShareFileInfoTest004
 * @tc.desc: UpdateShareFileInfo with empty cfginfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UpdateShareFileInfoTest004, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
    std::string cfginfo = "";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerKit::UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    setuid(uid);
}

/**
 * @tc.name: UpdateShareFileInfoTest005
 * @tc.desc: UpdateShareFileInfo with oversized cfginfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UpdateShareFileInfoTest005, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_SERVICE_REMOTE_ERR, ret);
    setuid(uid);
}

/**
 * @tc.name: UpdateShareFileInfoTest006
 * @tc.desc: UpdateShareFileInfo without share_files.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UpdateShareFileInfoTest006, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
    std::string cfginfo = R"({})";
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerKit::UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    setuid(uid);
}

/**
 * @tc.name: UpdateShareFileInfoTest007
 * @tc.desc: UpdateShareFileInfo with share_files missing sharingOSPath/Subpath/mode.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UpdateShareFileInfoTest007, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    setuid(uid);
}

/**
 * @tc.name: UpdateShareFileInfoTest008
 * @tc.desc: UpdateShareFileInfo with sharingOSPath but no scopes array.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UpdateShareFileInfoTest008, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: UpdateShareFileInfoTest009
 * @tc.desc: UpdateShareFileInfo with empty sharingOSPath.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UpdateShareFileInfoTest009, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: UpdateShareFileInfoTest010
 * @tc.desc: UpdateShareFileInfo with sharingOSPath not in scopes.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UpdateShareFileInfoTest010, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: UpdateShareFileInfoTest011
 * @tc.desc: UpdateShareFileInfo with valid path, scopes mode=r, permission=r.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UpdateShareFileInfoTest011, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ret = SandboxManagerKit::UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    setuid(uid);
}

/**
 * @tc.name: UpdateShareFileInfoTest012
 * @tc.desc: UpdateShareFileInfo with valid path, scopes mode=r+w, permission=r+w.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UpdateShareFileInfoTest012, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ret = SandboxManagerKit::UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    setuid(uid);
}

/**
 * @tc.name: UpdateShareFileInfoTest013
 * @tc.desc: UpdateShareFileInfo with valid path, scopes mode=r+w, permission=r.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UpdateShareFileInfoTest013, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ret = SandboxManagerKit::UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    setuid(uid);
}

/**
 * @tc.name: UpdateShareFileInfoTest014
 * @tc.desc: UpdateShareFileInfo with valid path, scopes mode=r, permission=r+w.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UpdateShareFileInfoTest014, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: UpdateShareFileInfoTest015
 * @tc.desc: UpdateShareFileInfo with valid path and mode but no subpath.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UpdateShareFileInfoTest015, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: UpdateShareFileInfoTest016
 * @tc.desc: UpdateShareFileInfo with valid path and mode but empty subpath.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UpdateShareFileInfoTest016, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    ret = SandboxManagerKit::UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    setuid(uid);
}

/**
 * @tc.name: UpdateShareFileInfoTest017
 * @tc.desc: UpdateShareFileInfo with subpath length exceeding 32.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UpdateShareFileInfoTest017, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: UpdateShareFileInfoTest018
 * @tc.desc: UpdateShareFileInfo with subpath containing /./.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UpdateShareFileInfoTest018, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: UpdateShareFileInfoTest019
 * @tc.desc: UpdateShareFileInfo with subpath containing /../.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UpdateShareFileInfoTest019, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: UpdateShareFileInfoTest020
 * @tc.desc: UpdateShareFileInfo with subpath containing null character.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UpdateShareFileInfoTest020, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
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

    int32_t ret = SandboxManagerKit::UpdateShareFileInfo(cfginfo, bundleName, userId, tokenId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: UnsetShareFileInfoTest001
 * @tc.desc: UnsetShareFileInfo with normal input.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UnsetShareFileInfoTest001, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerKit::UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(SANDBOX_MANAGER_OK, ret);
    setuid(uid);
}

/**
 * @tc.name: UnsetShareFileInfoTest002
 * @tc.desc: UnsetShareFileInfo with invalid tokenId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UnsetShareFileInfoTest002, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 0;

    int32_t ret = SandboxManagerKit::UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: UnsetShareFileInfoTest003
 * @tc.desc: UnsetShareFileInfo with empty bundleName.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UnsetShareFileInfoTest003, TestSize.Level0)
{
    int32_t uid = getuid();
    setuid(FOUNDATION_UID);
    std::string bundleName = "";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerKit::UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(INVALID_PARAMTER, ret);
    setuid(uid);
}

/**
 * @tc.name: UnsetShareFileInfoTest004
 * @tc.desc: UnsetShareFileInfo with non-BMS process.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitSharefilesTest, UnsetShareFileInfoTest004, TestSize.Level0)
{
    std::string bundleName = "com.example.test";
    uint32_t userId = 100;
    uint32_t tokenId = 12345;

    int32_t ret = SandboxManagerKit::UnsetShareFileInfo(tokenId, bundleName, userId);
    EXPECT_EQ(PERMISSION_DENIED, ret);
}
#endif
} // SandboxManager
} // AccessControl
} // OHOS
