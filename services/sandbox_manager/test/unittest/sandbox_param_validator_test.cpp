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

#include <cstdint>
#include <string>
#include <vector>
#include <gtest/gtest.h>
#include "sandbox_param_validator.h"
#include "sandbox_manager_const.h"
#include "sandbox_manager_err_code.h"
#include "policy_info.h"
#include "policy_info_manager.h"
#include "share_files.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

class SandboxParamValidatorTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/* ---- ValidateGenericPath: normal paths ---- */

/**
 * @tc.name: ValidateGenericPath_Normal_001
 * @tc.desc: Normal absolute path passes validation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateGenericPath_Normal_001, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateGenericPath(
        "/storage/Users/currentUser/Desktop/1.txt");
    EXPECT_EQ(SANDBOX_MANAGER_OK, result);
}

/**
 * @tc.name: ValidateGenericPath_Normal_002
 * @tc.desc: Normal data storage path passes validation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateGenericPath_Normal_002, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateGenericPath(
        "/data/storage/el2/base/files/1.txt");
    EXPECT_EQ(SANDBOX_MANAGER_OK, result);
}

/**
 * @tc.name: ValidateGenericPath_Normal_003
 * @tc.desc: Path with emoji filename passes validation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateGenericPath_Normal_003, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateGenericPath(
        "/storage/Users/currentUser/Desktop/\xF0\x9F\x98\x80.txt");
    EXPECT_EQ(SANDBOX_MANAGER_OK, result);
}

/**
 * @tc.name: ValidateGenericPath_Normal_004
 * @tc.desc: Path with CJK filename passes validation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateGenericPath_Normal_004, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateGenericPath(
        "/storage/Users/currentUser/Desktop/\xE4\xB8\xAD\xE6\x96\x87.txt");
    EXPECT_EQ(SANDBOX_MANAGER_OK, result);
}

/**
 * @tc.name: ValidateGenericPath_Normal_005
 * @tc.desc: Path with special characters in filename passes validation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateGenericPath_Normal_005, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateGenericPath(
        "/storage/Users/currentUser/Desktop/file@#$%^&.txt");
    EXPECT_EQ(SANDBOX_MANAGER_OK, result);
}

/* ---- ValidateGenericPath: path normalization ---- */

/**
 * @tc.name: ValidateGenericPath_Normalize_001
 * @tc.desc: Path with trailing .. is rejected (strict mode: not already normalized)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateGenericPath_Normalize_001, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateGenericPath(
        "/storage/Users/currentUser/..");
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/**
 * @tc.name: ValidateGenericPath_Normalize_002
 * @tc.desc: Path with trailing . is rejected (strict mode: not already normalized)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateGenericPath_Normalize_002, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateGenericPath(
        "/storage/Users/currentUser/.");
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/**
 * @tc.name: ValidateGenericPath_Normalize_003
 * @tc.desc: Path with embedded ./ is rejected (strict mode: not already normalized)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateGenericPath_Normalize_003, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateGenericPath(
        "/storage/Users/currentUser/./appdata");
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/**
 * @tc.name: ValidateGenericPath_Normalize_004
 * @tc.desc: Path with embedded ../ is rejected (strict mode: not already normalized)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateGenericPath_Normalize_004, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateGenericPath(
        "/storage/Users/currentUser/../appdata");
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/**
 * @tc.name: ValidateGenericPath_Normalize_005
 * @tc.desc: Path with trailing slash is rejected (strict mode: not already normalized)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateGenericPath_Normalize_005, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateGenericPath(
        "/storage/Users/currentUser/Desktop/");
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/* ---- ValidateGenericPath: backslash paths (legal on Linux) ---- */

/**
 * @tc.name: ValidateGenericPath_Backslash_001
 * @tc.desc: Path with backslash in filename passes (backslash is legal on Linux)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateGenericPath_Backslash_001, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateGenericPath(
        "/storage/Users/currentUser\\appdata");
    EXPECT_EQ(SANDBOX_MANAGER_OK, result);
}

/**
 * @tc.name: ValidateGenericPath_Backslash_002
 * @tc.desc: Path with double backslash at end passes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateGenericPath_Backslash_002, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateGenericPath(
        "/storage/Users/currentUser/appdata\\\\");
    EXPECT_EQ(SANDBOX_MANAGER_OK, result);
}

/* ---- ValidateGenericPath: illegal paths rejected ---- */

/**
 * @tc.name: ValidateGenericPath_Empty_001
 * @tc.desc: Empty path is rejected with INVALID_PATH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateGenericPath_Empty_001, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateGenericPath("");
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/**
 * @tc.name: ValidateGenericPath_TooLong_001
 * @tc.desc: Path exceeding POLICY_PATH_LIMIT (4095) is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateGenericPath_TooLong_001, TestSize.Level1)
{
    std::string longPath = "/" + std::string(POLICY_PATH_LIMIT, 'a');
    int32_t result = SandboxParamValidator::ValidateGenericPath(longPath);
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/**
 * @tc.name: ValidateGenericPath_Relative_001
 * @tc.desc: Relative path (no leading /) is rejected with INVALID_PATH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateGenericPath_Relative_001, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateGenericPath(
        "storage/Users/currentUser");
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/**
 * @tc.name: ValidateGenericPath_Relative_002
 * @tc.desc: Relative path with dot is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateGenericPath_Relative_002, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateGenericPath(
        "./data/test");
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/* ---- ValidateGenericPath: null byte detection (before lexically_normal) ---- */

/**
 * @tc.name: ValidateGenericPath_NullByte_001
 * @tc.desc: Path with embedded null byte is rejected (checked before lexically_normal)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateGenericPath_NullByte_001, TestSize.Level1)
{
    std::string pathWithNull = "/storage/Users/currentUser";
    pathWithNull += '\0';
    pathWithNull += "/secret";
    int32_t result = SandboxParamValidator::ValidateGenericPath(pathWithNull);
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/**
 * @tc.name: ValidateGenericPath_NullByte_002
 * @tc.desc: Path with null byte at end is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateGenericPath_NullByte_002, TestSize.Level1)
{
    std::string pathWithNull = "/storage/Users/currentUser/Desktop";
    pathWithNull += '\0';
    int32_t result = SandboxParamValidator::ValidateGenericPath(pathWithNull);
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/* ---- NormalizePath helper tests ---- */

/**
 * @tc.name: NormalizePath_001
 * @tc.desc: NormalizePath resolves .. and . components
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, NormalizePath_001, TestSize.Level1)
{
    EXPECT_EQ("/storage/Users",
        SandboxParamValidator::NormalizePath("/storage/Users/currentUser/.."));
    EXPECT_EQ("/storage/Users/currentUser",
        SandboxParamValidator::NormalizePath("/storage/Users/currentUser/."));
    EXPECT_EQ("/storage/Users/currentUser/appdata",
        SandboxParamValidator::NormalizePath("/storage/Users/currentUser/./appdata"));
    EXPECT_EQ("/storage/Users/appdata",
        SandboxParamValidator::NormalizePath("/storage/Users/currentUser/../appdata"));
}

/**
 * @tc.name: NormalizePath_002
 * @tc.desc: NormalizePath removes trailing slash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, NormalizePath_002, TestSize.Level1)
{
    EXPECT_EQ("/storage/Users/currentUser/Desktop",
        SandboxParamValidator::NormalizePath("/storage/Users/currentUser/Desktop/"));
}

/**
 * @tc.name: NormalizePath_003
 * @tc.desc: NormalizePath preserves backslash (legal Linux char)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, NormalizePath_003, TestSize.Level1)
{
    std::string result = SandboxParamValidator::NormalizePath("/storage/Users/currentUser\\appdata");
    EXPECT_EQ("/storage/Users/currentUser\\appdata", result);
}

/* ---- CheckEmbeddedNull helper tests ---- */

/**
 * @tc.name: CheckEmbeddedNull_001
 * @tc.desc: CheckEmbeddedNull returns false for normal paths
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, CheckEmbeddedNull_001, TestSize.Level1)
{
    EXPECT_FALSE(SandboxParamValidator::CheckEmbeddedNull("/storage/Users/currentUser"));
    EXPECT_FALSE(SandboxParamValidator::CheckEmbeddedNull("/data/storage/el2/base/files/1.txt"));
    EXPECT_FALSE(SandboxParamValidator::CheckEmbeddedNull(""));
}

/**
 * @tc.name: CheckEmbeddedNull_002
 * @tc.desc: CheckEmbeddedNull returns true for paths with embedded null bytes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, CheckEmbeddedNull_002, TestSize.Level1)
{
    std::string pathWithNull1 = "/storage/Users/currentUser";
    pathWithNull1 += '\0';
    pathWithNull1 += "/secret";
    EXPECT_TRUE(SandboxParamValidator::CheckEmbeddedNull(pathWithNull1));

    std::string pathWithNull2 = "/data/test";
    pathWithNull2 += '\0';
    EXPECT_TRUE(SandboxParamValidator::CheckEmbeddedNull(pathWithNull2));
}

/* ---- SplitPath helper tests ---- */

/**
 * @tc.name: SplitPath_001
 * @tc.desc: SplitPath splits path into components by /
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, SplitPath_001, TestSize.Level1)
{
    std::vector<std::string> components = SandboxParamValidator::SplitPath(
        "/storage/Users/currentUser/appdata/el1/base/com.test/files");
    ASSERT_EQ(8, components.size());
    EXPECT_EQ("storage", components[0]);
    EXPECT_EQ("Users", components[1]);
    EXPECT_EQ("currentUser", components[2]);
    EXPECT_EQ("appdata", components[3]);
    EXPECT_EQ("el1", components[4]);
    EXPECT_EQ("base", components[5]);
    EXPECT_EQ("com.test", components[6]);
    EXPECT_EQ("files", components[7]);
}

/**
 * @tc.name: SplitPath_002
 * @tc.desc: SplitPath with short path returns all components
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, SplitPath_002, TestSize.Level1)
{
    std::vector<std::string> components = SandboxParamValidator::SplitPath("/a/b/c");
    ASSERT_EQ(3, components.size());
    EXPECT_EQ("a", components[0]);
    EXPECT_EQ("b", components[1]);
    EXPECT_EQ("c", components[2]);
}

/**
 * @tc.name: SplitPath_003
 * @tc.desc: SplitPath handles trailing slash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, SplitPath_003, TestSize.Level1)
{
    std::vector<std::string> components = SandboxParamValidator::SplitPath("/a/b/");
    ASSERT_EQ(2, components.size());
    EXPECT_EQ("a", components[0]);
    EXPECT_EQ("b", components[1]);
}

/**
 * @tc.name: SplitPath_004
 * @tc.desc: SplitPath with deep path caps at MAX_CHECK_COM_NUM+1 segments
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, SplitPath_004, TestSize.Level1)
{
    std::vector<std::string> components = SandboxParamValidator::SplitPath(
        "/a/b/c/d/e/f/g/h/i/j/k");
    ASSERT_EQ(8, components.size());
    EXPECT_EQ("a", components[0]);
    EXPECT_EQ("h/i/j/k", components[7]);
}

/* ---- ValidateTempMode: mode validation for temporary policies ---- */

/**
 * @tc.name: ValidateTempMode_001
 * @tc.desc: READ mode (1) passes validation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateTempMode_001, TestSize.Level1)
{
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxParamValidator::ValidateTempMode(OperateMode::READ_MODE));
}

/**
 * @tc.name: ValidateTempMode_002
 * @tc.desc: READ+WRITE mode (3) passes validation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateTempMode_002, TestSize.Level1)
{
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        SandboxParamValidator::ValidateTempMode(OperateMode::READ_MODE | OperateMode::WRITE_MODE));
}

/**
 * @tc.name: ValidateTempMode_003
 * @tc.desc: All normal bits 0-4 (31) passes validation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateTempMode_003, TestSize.Level1)
{
    uint64_t allNormal = OperateMode::READ_MODE | OperateMode::WRITE_MODE | OperateMode::CREATE_MODE |
        OperateMode::DELETE_MODE | OperateMode::RENAME_MODE;
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxParamValidator::ValidateTempMode(allNormal));
}

/**
 * @tc.name: ValidateTempMode_004
 * @tc.desc: Mode 0 fails (no normal bits)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateTempMode_004, TestSize.Level1)
{
    EXPECT_EQ(SandboxRetType::INVALID_MODE, SandboxParamValidator::ValidateTempMode(0));
}

/**
 * @tc.name: ValidateTempMode_005
 * @tc.desc: DENY_READ mode (32) fails (deny bit set, no normal bits)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateTempMode_005, TestSize.Level1)
{
    EXPECT_EQ(SandboxRetType::INVALID_MODE, SandboxParamValidator::ValidateTempMode(OperateMode::DENY_READ_MODE));
}

/**
 * @tc.name: ValidateTempMode_006
 * @tc.desc: READ+DENY_READ mode (33) fails (mixed normal and deny bits)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateTempMode_006, TestSize.Level1)
{
    EXPECT_EQ(SandboxRetType::INVALID_MODE,
        SandboxParamValidator::ValidateTempMode(OperateMode::READ_MODE | OperateMode::DENY_READ_MODE));
}

/**
 * @tc.name: ValidateTempMode_007
 * @tc.desc: DENY_WRITE mode (64) fails (deny bit set, no normal bits)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateTempMode_007, TestSize.Level1)
{
    EXPECT_EQ(SandboxRetType::INVALID_MODE, SandboxParamValidator::ValidateTempMode(OperateMode::DENY_WRITE_MODE));
}

/**
 * @tc.name: ValidateTempMode_008
 * @tc.desc: DENY_READ+DENY_WRITE mode (96) fails (deny bits set, no normal bits)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateTempMode_008, TestSize.Level1)
{
    EXPECT_EQ(SandboxRetType::INVALID_MODE,
        SandboxParamValidator::ValidateTempMode(OperateMode::DENY_READ_MODE | OperateMode::DENY_WRITE_MODE));
}

/**
 * @tc.name: ValidateTempMode_009
 * @tc.desc: MAX_MODE (128) fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateTempMode_009, TestSize.Level1)
{
    EXPECT_EQ(SandboxRetType::INVALID_MODE, SandboxParamValidator::ValidateTempMode(OperateMode::MAX_MODE));
}

/* ---- ValidateDenyMode: mode validation for deny policies (GAP #3 fix) ---- */

/**
 * @tc.name: ValidateDenyMode_001
 * @tc.desc: DENY_READ mode (32) passes validation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateDenyMode_001, TestSize.Level1)
{
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxParamValidator::ValidateDenyMode(OperateMode::DENY_READ_MODE));
}

/**
 * @tc.name: ValidateDenyMode_002
 * @tc.desc: DENY_WRITE mode (64) passes validation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateDenyMode_002, TestSize.Level1)
{
    EXPECT_EQ(SANDBOX_MANAGER_OK, SandboxParamValidator::ValidateDenyMode(OperateMode::DENY_WRITE_MODE));
}

/**
 * @tc.name: ValidateDenyMode_003
 * @tc.desc: DENY_READ+DENY_WRITE mode (96) passes validation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateDenyMode_003, TestSize.Level1)
{
    EXPECT_EQ(SANDBOX_MANAGER_OK,
        SandboxParamValidator::ValidateDenyMode(OperateMode::DENY_READ_MODE | OperateMode::DENY_WRITE_MODE));
}

/**
 * @tc.name: ValidateDenyMode_004
 * @tc.desc: Mode 0 fails (no deny bits)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateDenyMode_004, TestSize.Level1)
{
    EXPECT_EQ(SandboxRetType::INVALID_MODE, SandboxParamValidator::ValidateDenyMode(0));
}

/**
 * @tc.name: ValidateDenyMode_005
 * @tc.desc: READ mode (1) fails (normal bit set, no deny bits)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateDenyMode_005, TestSize.Level1)
{
    EXPECT_EQ(SandboxRetType::INVALID_MODE, SandboxParamValidator::ValidateDenyMode(OperateMode::READ_MODE));
}

/**
 * @tc.name: ValidateDenyMode_006
 * @tc.desc: READ+DENY_READ mode (33) fails - GAP #3: mixed normal and deny bits rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateDenyMode_006, TestSize.Level1)
{
    EXPECT_EQ(SandboxRetType::INVALID_MODE,
        SandboxParamValidator::ValidateDenyMode(OperateMode::READ_MODE | OperateMode::DENY_READ_MODE));
}

/**
 * @tc.name: ValidateDenyMode_007
 * @tc.desc: MAX_MODE (128) fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateDenyMode_007, TestSize.Level1)
{
    EXPECT_EQ(SandboxRetType::INVALID_MODE, SandboxParamValidator::ValidateDenyMode(OperateMode::MAX_MODE));
}

/* ---- ValidateBasicPathRules: valid paths pass ---- */

/**
 * @tc.name: ValidateBasicPathRules_Valid_001
 * @tc.desc: Normal /storage/Users/currentUser path passes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateBasicPathRules_Valid_001, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateBasicPathRules(
        "/storage/Users/currentUser/Desktop/1.txt");
    EXPECT_EQ(SANDBOX_MANAGER_OK, result);
}

/**
 * @tc.name: ValidateBasicPathRules_Valid_002
 * @tc.desc: Non-/storage/ prefix path passes (whitelist)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateBasicPathRules_Valid_002, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateBasicPathRules(
        "/data/storage/el2/base/files/1.txt");
    EXPECT_EQ(SANDBOX_MANAGER_OK, result);
}

/* ---- ValidateBasicPathRules: illegal paths rejected ---- */

/**
 * @tc.name: ValidateBasicPathRules_Reject_001
 * @tc.desc: /storage is rejected (ROOT_PATH)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateBasicPathRules_Reject_001, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateBasicPathRules("/storage");
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/**
 * @tc.name: ValidateBasicPathRules_Reject_002
 * @tc.desc: /storage/Users/101 rejected (3rd segment != currentUser)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateBasicPathRules_Reject_002, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateBasicPathRules("/storage/Users/101");
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/**
 * @tc.name: ValidateBasicPathRules_Reject_003
 * @tc.desc: /storage/Users/currentUser/appdata rejected (exact appdata)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateBasicPathRules_Reject_003, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateBasicPathRules(
        "/storage/Users/currentUser/appdata");
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/**
 * @tc.name: ValidateBasicPathRules_Reject_004
 * @tc.desc: /storage/Users/currentUser/appdata/el2 rejected (appdata prefix <= 6 segments)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateBasicPathRules_Reject_004, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateBasicPathRules(
        "/storage/Users/currentUser/appdata/el2");
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/* ---- ValidateBasicPathRules: GAP #5 case-variant appdata rejected ---- */

/**
 * @tc.name: ValidateBasicPathRules_GAP5_001
 * @tc.desc: /storage/Users/currentUser/Appdata rejected (GAP #5: case mismatch)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateBasicPathRules_GAP5_001, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateBasicPathRules(
        "/storage/Users/currentUser/Appdata");
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/**
 * @tc.name: ValidateBasicPathRules_GAP5_002
 * @tc.desc: /storage/Users/currentUser/APPDATA rejected (GAP #5: case mismatch)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateBasicPathRules_GAP5_002, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateBasicPathRules(
        "/storage/Users/currentUser/APPDATA");
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/**
 * @tc.name: ValidateBasicPathRules_GAP5_003
 * @tc.desc: /storage/Users/currentUser/AppData rejected (GAP #5: case mismatch)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateBasicPathRules_GAP5_003, TestSize.Level1)
{
    int32_t result = SandboxParamValidator::ValidateBasicPathRules(
        "/storage/Users/currentUser/AppData");
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/* ---- ValidateBasicPathRules: abnormal extensions ---- */

/**
 * @tc.name: ValidateBasicPathRules_Abnormal_001
 * @tc.desc: /storage/./ normalizes to /storage (ROOT_PATH) and is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateBasicPathRules_Abnormal_001, TestSize.Level1)
{
    std::string normalized = SandboxParamValidator::NormalizePath("/storage/./");
    int32_t result = SandboxParamValidator::ValidateBasicPathRules(normalized);
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/**
 * @tc.name: ValidateBasicPathRules_Abnormal_002
 * @tc.desc: /storage/../ normalizes to / and passes (whitelist)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateBasicPathRules_Abnormal_002, TestSize.Level1)
{
    std::string normalized = SandboxParamValidator::NormalizePath("/storage/../");
    int32_t result = SandboxParamValidator::ValidateBasicPathRules(normalized);
    EXPECT_EQ(SANDBOX_MANAGER_OK, result);
}

/* ---- ValidateExtendedPathRules: SELF_PATH bundleName check ---- */

/**
 * @tc.name: ValidateExtendedPathRules_Valid_001
 * @tc.desc: SELF_PATH with matching bundleName passes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateExtendedPathRules_Valid_001, TestSize.Level1)
{
    PolicyInfo policy;
    policy.path = "/storage/Users/currentUser/appdata/el2/base/com.test/files/1.txt";
    policy.mode = OperateMode::READ_MODE;
    policy.type = PolicyType::SELF_PATH;
    int32_t result = SandboxParamValidator::ValidateExtendedPathRules(
        100, "/storage/Users/currentUser/appdata/el2/base/com.test/files/1.txt",
        policy, "com.test");
    EXPECT_EQ(SANDBOX_MANAGER_OK, result);
}

/**
 * @tc.name: ValidateExtendedPathRules_Valid_002
 * @tc.desc: SELF_PATH with empty bundleName passes (skips bundleName check)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateExtendedPathRules_Valid_002, TestSize.Level1)
{
    PolicyInfo policy;
    policy.path = "/storage/Users/currentUser/Desktop/1.txt";
    policy.mode = OperateMode::READ_MODE;
    policy.type = PolicyType::SELF_PATH;
    int32_t result = SandboxParamValidator::ValidateExtendedPathRules(
        100, "/storage/Users/currentUser/Desktop/1.txt", policy, "");
    EXPECT_EQ(SANDBOX_MANAGER_OK, result);
}

/**
 * @tc.name: ValidateExtendedPathRules_Valid_003
 * @tc.desc: Non-/storage/ prefix path passes (whitelist, no components > MAX_CHECK_COM_NUM)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateExtendedPathRules_Valid_003, TestSize.Level1)
{
    PolicyInfo policy;
    policy.path = "/data/storage/el2/base/files/1.txt";
    policy.mode = OperateMode::READ_MODE;
    policy.type = PolicyType::UNKNOWN;
    int32_t result = SandboxParamValidator::ValidateExtendedPathRules(
        100, "/data/storage/el2/base/files/1.txt", policy, "");
    EXPECT_EQ(SANDBOX_MANAGER_OK, result);
}

/**
 * @tc.name: ValidateExtendedPathRules_Reject_001
 * @tc.desc: SELF_PATH with mismatched bundleName rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateExtendedPathRules_Reject_001, TestSize.Level1)
{
    PolicyInfo policy;
    policy.path = "/storage/Users/currentUser/appdata/el2/base/com.test/files/1.txt";
    policy.mode = OperateMode::READ_MODE;
    policy.type = PolicyType::SELF_PATH;
    int32_t result = SandboxParamValidator::ValidateExtendedPathRules(
        100, "/storage/Users/currentUser/appdata/el2/base/com.test/files/1.txt",
        policy, "com.other");
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/* ---- CheckPathWithinBundleName tests ---- */

/**
 * @tc.name: CheckPathWithinBundleName_001
 * @tc.desc: Empty bundleName returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, CheckPathWithinBundleName_001, TestSize.Level1)
{
    std::vector<std::string> components = {"storage", "Users", "currentUser", "appdata",
        "el2", "base", "com.test", "files"};
    EXPECT_FALSE(SandboxParamValidator::CheckPathWithinBundleName(components, ""));
}

/**
 * @tc.name: CheckPathWithinBundleName_002
 * @tc.desc: Matching bundleName at position 6 returns true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, CheckPathWithinBundleName_002, TestSize.Level1)
{
    std::vector<std::string> components = {"storage", "Users", "currentUser", "appdata",
        "el2", "base", "com.test", "files"};
    EXPECT_TRUE(SandboxParamValidator::CheckPathWithinBundleName(components, "com.test"));
}

/**
 * @tc.name: CheckPathWithinBundleName_003
 * @tc.desc: Mismatched bundleName returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, CheckPathWithinBundleName_003, TestSize.Level1)
{
    std::vector<std::string> components = {"storage", "Users", "currentUser", "appdata",
        "el2", "base", "com.test", "files"};
    EXPECT_FALSE(SandboxParamValidator::CheckPathWithinBundleName(components, "com.other"));
}

/**
 * @tc.name: CheckPathWithinBundleName_004
 * @tc.desc: Too few components (<=6) returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, CheckPathWithinBundleName_004, TestSize.Level1)
{
    std::vector<std::string> components = {"storage", "Users", "currentUser", "appdata"};
    EXPECT_FALSE(SandboxParamValidator::CheckPathWithinBundleName(components, "com.test"));
}

/* ---- ValidateTempPolicy: scenario validator for temporary policies ---- */

/**
 * @tc.name: ValidateTempPolicy_Valid_001
 * @tc.desc: Temp policy mode=READ path=/storage/Users/currentUser/Desktop/1.txt passes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateTempPolicy_Valid_001, TestSize.Level1)
{
    PolicyInfo policy;
    policy.path = "/storage/Users/currentUser/Desktop/1.txt";
    policy.mode = OperateMode::READ_MODE;
    policy.type = PolicyType::SELF_PATH;
    SetInfo setInfo;
    setInfo.bundleName = "com.test.demo";
    setInfo.userId = 100;
    int32_t result = SandboxParamValidator::ValidateTempPolicy(policy, setInfo);
    EXPECT_EQ(SANDBOX_MANAGER_OK, result);
}

/**
 * @tc.name: ValidateTempPolicy_InvalidMode_001
 * @tc.desc: Temp policy mode=DENY_READ (32) fails ValidateTempMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateTempPolicy_InvalidMode_001, TestSize.Level1)
{
    PolicyInfo policy;
    policy.path = "/storage/Users/currentUser/Desktop/1.txt";
    policy.mode = OperateMode::DENY_READ_MODE;
    policy.type = PolicyType::SELF_PATH;
    SetInfo setInfo;
    setInfo.bundleName = "com.test.demo";
    setInfo.userId = 100;
    int32_t result = SandboxParamValidator::ValidateTempPolicy(policy, setInfo);
    EXPECT_EQ(SandboxRetType::INVALID_MODE, result);
}

/**
 * @tc.name: ValidateTempPolicy_InvalidPath_001
 * @tc.desc: Temp policy path=/storage fails ValidateBasicPathRules (ROOT_PATH)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateTempPolicy_InvalidPath_001, TestSize.Level1)
{
    PolicyInfo policy;
    policy.path = "/storage";
    policy.mode = OperateMode::READ_MODE;
    policy.type = PolicyType::UNKNOWN;
    SetInfo setInfo;
    setInfo.bundleName = "";
    setInfo.userId = 100;
    int32_t result = SandboxParamValidator::ValidateTempPolicy(policy, setInfo);
    EXPECT_EQ(SandboxRetType::INVALID_PATH, result);
}

/* ---- ValidateActivationPolicy: scenario validator for policy activation ---- */

/**
 * @tc.name: ValidateActivationPolicy_Valid_001
 * @tc.desc: Activation mode=READ path=/data/storage/el2/base/files/1.txt passes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateActivationPolicy_Valid_001, TestSize.Level1)
{
    PolicyInfo policy;
    policy.path = "/data/storage/el2/base/files/1.txt";
    policy.mode = OperateMode::READ_MODE;
    policy.type = PolicyType::UNKNOWN;
    bool isMediaPath = true;
    int32_t result = SandboxParamValidator::ValidateActivationPolicy(policy, isMediaPath);
    EXPECT_EQ(SANDBOX_MANAGER_OK, result);
    EXPECT_FALSE(isMediaPath);
}

/**
 * @tc.name: ValidateActivationPolicy_InvalidMode_001
 * @tc.desc: Activation mode=DENY_READ (32) fails - GAP #4: deny bits not allowed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateActivationPolicy_InvalidMode_001, TestSize.Level1)
{
    PolicyInfo policy;
    policy.path = "/data/storage/el2/base/files/1.txt";
    policy.mode = OperateMode::DENY_READ_MODE;
    policy.type = PolicyType::UNKNOWN;
    bool isMediaPath = false;
    int32_t result = SandboxParamValidator::ValidateActivationPolicy(policy, isMediaPath);
    EXPECT_EQ(SandboxRetType::INVALID_MODE, result);
}

/**
 * @tc.name: ValidateActivationPolicy_Valid_002
 * @tc.desc: Activation mode=CREATE (4) passes validation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, ValidateActivationPolicy_Valid_002, TestSize.Level1)
{
    PolicyInfo policy;
    policy.path = "/data/storage/el2/base/files/1.txt";
    policy.mode = OperateMode::CREATE_MODE;
    policy.type = PolicyType::UNKNOWN;
    bool isMediaPath = false;
    int32_t result = SandboxParamValidator::ValidateActivationPolicy(policy, isMediaPath);
    EXPECT_EQ(SANDBOX_MANAGER_OK, result);
    EXPECT_FALSE(isMediaPath);
}

/* ---- CheckPathWithinShareMap: share map path check ---- */

/**
 * @tc.name: CheckPathWithinShareMap_001
 * @tc.desc: Non-appdata path returns true (does not enter share map check)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, CheckPathWithinShareMap_001, TestSize.Level1)
{
    PolicyInfo policy;
    policy.path = "/data/storage/el2/base/files/1.txt";
    policy.mode = OperateMode::READ_MODE;
    EXPECT_TRUE(SandboxParamValidator::CheckPathWithinShareMap(100, policy.path, policy));
}

/**
 * @tc.name: CheckPathWithinShareMap_002
 * @tc.desc: Non-storage path returns true (does not enter share map check)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, CheckPathWithinShareMap_002, TestSize.Level1)
{
    PolicyInfo policy;
    policy.path = "/data/test/file.txt";
    policy.mode = OperateMode::WRITE_MODE;
    EXPECT_TRUE(SandboxParamValidator::CheckPathWithinShareMap(100, policy.path, policy));
}

/**
 * @tc.name: CheckPathWithinShareMap_003
 * @tc.desc: Appdata path with no share config returns true (SHARE_BUNDLE_UNSET -> allowed)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, CheckPathWithinShareMap_003, TestSize.Level1)
{
    PolicyInfo policy;
    policy.path = "/storage/Users/currentUser/appdata/el2/base/com.test/files/1.txt";
    policy.mode = OperateMode::READ_MODE;
    EXPECT_TRUE(SandboxParamValidator::CheckPathWithinShareMap(100, policy.path, policy));
}

/**
 * @tc.name: CheckPathWithinShareMap_004
 * @tc.desc: Appdata path with WRITE mode and no share config returns true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, CheckPathWithinShareMap_004, TestSize.Level1)
{
    PolicyInfo policy;
    policy.path = "/storage/Users/currentUser/appdata/el2/base/com.demo/haps/entry/files/2.txt";
    policy.mode = OperateMode::WRITE_MODE;
    EXPECT_TRUE(SandboxParamValidator::CheckPathWithinShareMap(100, policy.path, policy));
}

/**
 * @tc.name: CheckPathWithinShareMap_005
 * @tc.desc: Path with storage but not appdata returns true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, CheckPathWithinShareMap_005, TestSize.Level1)
{
    PolicyInfo policy;
    policy.path = "/storage/Users/currentUser/Desktop/1.txt";
    policy.mode = OperateMode::READ_MODE;
    EXPECT_TRUE(SandboxParamValidator::CheckPathWithinShareMap(100, policy.path, policy));
}

/* ---- CheckShareMode ---- */

/**
 * @tc.name: CheckShareMode_001
 * @tc.desc: SHARE_BUNDLE_UNSET returns true (bundle has no share config, allow access)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, CheckShareMode_001, TestSize.Level1)
{
    EXPECT_TRUE(SandboxParamValidator::CheckShareMode(SHARE_BUNDLE_UNSET,
        OperateMode::READ_MODE, "/test/path", "com.test"));
}

/**
 * @tc.name: CheckShareMode_002
 * @tc.desc: SHARE_PATH_UNSET returns false (path has no share config, deny access)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, CheckShareMode_002, TestSize.Level1)
{
    EXPECT_FALSE(SandboxParamValidator::CheckShareMode(SHARE_PATH_UNSET,
        OperateMode::READ_MODE, "/test/path", "com.test"));
}

/**
 * @tc.name: CheckShareMode_003
 * @tc.desc: Mode mismatch (permission & mode != mode) returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, CheckShareMode_003, TestSize.Level1)
{
    uint32_t permission = OperateMode::WRITE_MODE;
    EXPECT_FALSE(SandboxParamValidator::CheckShareMode(permission,
        OperateMode::READ_MODE, "/test/path", "com.test"));
}

/**
 * @tc.name: CheckShareMode_004
 * @tc.desc: Mode match (permission & mode == mode) returns true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, CheckShareMode_004, TestSize.Level1)
{
    uint32_t permission = OperateMode::READ_MODE | OperateMode::WRITE_MODE;
    EXPECT_TRUE(SandboxParamValidator::CheckShareMode(permission,
        OperateMode::READ_MODE, "/test/path", "com.test"));
}

/* ---- RemoveClonePrefix ---- */

/**
 * @tc.name: RemoveClonePrefix_001
 * @tc.desc: Bundle name without clone prefix is returned unchanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, RemoveClonePrefix_001, TestSize.Level1)
{
    EXPECT_EQ("com.test.demo", SandboxParamValidator::RemoveClonePrefix("com.test.demo"));
}

/**
 * @tc.name: RemoveClonePrefix_002
 * @tc.desc: Bundle name with "+clone-N+" prefix is stripped
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, RemoveClonePrefix_002, TestSize.Level1)
{
    EXPECT_EQ("com.test.demo", SandboxParamValidator::RemoveClonePrefix("+clone-1+com.test.demo"));
}

/**
 * @tc.name: RemoveClonePrefix_003
 * @tc.desc: Bundle name with clone prefix but no terminating '+' is returned unchanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, RemoveClonePrefix_003, TestSize.Level1)
{
    EXPECT_EQ("+clone-1com.test.demo", SandboxParamValidator::RemoveClonePrefix("+clone-1com.test.demo"));
}

/* ---- GenerateMaskedPath ---- */

/**
 * @tc.name: GenerateMaskedPath_001
 * @tc.desc: Components count too small (<= SUB_PATH_SEGMENT) returns "invalid_path"
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, GenerateMaskedPath_001, TestSize.Level1)
{
    std::vector<std::string> components = {"storage", "Users"};
    EXPECT_EQ("invalid_path", SandboxParamValidator::GenerateMaskedPath(components));
}

/**
 * @tc.name: GenerateMaskedPath_002
 * @tc.desc: Normal components produce a masked path containing "***"
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxParamValidatorTest, GenerateMaskedPath_002, TestSize.Level1)
{
    std::vector<std::string> components = {"storage", "Users", "currentUser", "appdata",
        "el2", "base", "com.test", "files"};
    std::string result = SandboxParamValidator::GenerateMaskedPath(components);
    EXPECT_FALSE(result.empty());
    EXPECT_NE("invalid_path", result);
    EXPECT_TRUE(result.find("***") != std::string::npos);
}

} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
