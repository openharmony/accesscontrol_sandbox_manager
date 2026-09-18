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

#include "claw_sandbox_cmd_parser_test.h"
#include "sandbox_cmd_parser.h"
#include "sandbox_error.h"
#include <sched.h>
#include <cstdint>
#include <cstdlib>
#include <unistd.h>
#include "scoped_pc_mode.h"

/*
 * NOTE: execvp() and execl() are mocked via linker interposition in
 * execvp_mock_stub.cpp. That file defines the actual execvp() and execl()
 * symbols, which the linker resolves in preference to the libc versions.
 * This approach is more reliable than preprocessor-based mocking because
 * it operates at the linker level.
 */

#define private public
#include "sandbox_manager.h"
#undef private

/*
 * Last on purpose. sandbox_log.h #undefs LOG_TAG and LOG_DOMAIN and redefines
 * them, and those are plain macros read where SANDBOX_LOGx is written, not
 * settings applied once. Any header included after this one that defines its own
 * LOG_TAG silently takes over, and the log lines go out under someone else's tag
 * and domain - which looks exactly like logging being broken.
 */
#include "sandbox_log.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

// The high half of an AccessTokenIDEx. It gates nothing - ValidateTokenType
// masks it off - so it is here only to keep the test tokens shaped like real ones.
static constexpr uint64_t TEST_TOKEN_ID_HIGH_BIT = (static_cast<uint64_t>(1) << 32);

// A callerTokenId with a non-zero low 32-bit token ID.
static constexpr uint64_t TEST_HAP_TOKEN_ID = TEST_TOKEN_ID_HIGH_BIT | 0x200D000D;

struct ConfigJsonField {
    const char *key;
    std::string value;
};

static const ConfigJsonField BASE_CONFIG_FIELDS[] = {
    {"callerTokenId", "1"},
    {"callerPid", "1"},
    {"uid", "20020026"},
    {"gid", "20020026"},
    {"challenge", R"("ch")"},
    {"appIdentifier", R"("20020026")"},
    {"bundleName", R"("bundle")"},
    {"cliName", R"("cli")"},
    {"subCliName", R"("sub")"},
};

static std::string BuildConfigJsonWithoutField(const std::string &missingKey)
{
    std::string json = "{";
    bool first = true;
    for (const auto &field : BASE_CONFIG_FIELDS) {
        if (missingKey == field.key) {
            continue;
        }
        json += first ? "" : ",";
        json += "\"";
        json += field.key;
        json += "\":";
        json += field.value;
        first = false;
    }
    json += "}";
    return json;
}

static std::string BuildConfigJsonWithValue(const std::string &overrideKey,
    const std::string &overrideValue)
{
    std::string json = "{";
    bool first = true;
    for (const auto &field : BASE_CONFIG_FIELDS) {
        json += first ? "" : ",";
        json += "\"";
        json += field.key;
        json += "\":";
        json += (overrideKey == field.key) ? overrideValue : field.value;
        first = false;
    }
    json += "}";
    return json;
}

static std::string AddConfigJsonField(std::string json, const std::string &key, const std::string &value)
{
    if (!json.empty() && json.back() == '}') {
        json.pop_back();
    }
    json += ",\"";
    json += key;
    json += "\":";
    json += value;
    json += "}";
    return json;
}

static std::string ToJsonString(const std::string &value)
{
    std::string json = "\"";
    for (char c : value) {
        if (c == '"' || c == '\\') {
            json += '\\';
            json += c;
        } else if (c == '\n') {
            json += "\\n";
        } else if (c == '\r') {
            json += "\\r";
        } else if (c == '\t') {
            json += "\\t";
        } else {
            json += c;
        }
    }
    json += "\"";
    return json;
}

void ClawSandboxCmdParserTest::SetUpTestCase() {}
void ClawSandboxCmdParserTest::TearDownTestCase() {}
void ClawSandboxCmdParserTest::SetUp() {}
void ClawSandboxCmdParserTest::TearDown() {}

// ==================== ParseConfig tests ====================

/**
 * @tc.name: ParseConfig001
 * @tc.desc: ParseConfig with valid JSON containing all required fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig001, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 123456789,
        "callerPid": 1000,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "test-challenge",
        "appIdentifier": "20020026",
        "bundleName": "com.example.bundle",
        "cliName": "testCli",
        "subCliName": "testSubCli"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(123456789ULL, config.callerTokenId);
    EXPECT_EQ(1000U, config.callerPid);
    EXPECT_EQ(20020026U, config.uid);
    EXPECT_EQ(20020026U, config.gid);
    EXPECT_EQ("test-challenge", config.challenge);
    EXPECT_EQ("20020026", config.appIdentifier);
    EXPECT_EQ("com.example.bundle", config.bundleName);
    EXPECT_EQ("testCli", config.cliName);
    EXPECT_EQ("testSubCli", config.subCliName);
    EXPECT_TRUE(config.name.empty());
    // When nsFlags is not specified in JSON, it defaults to CLONE_NEWNS
    EXPECT_EQ(CLONE_NEWNS, config.nsFlags);
}

/**
 * @tc.name: ParseConfigAppIdentifierU64
 * @tc.desc: A numeric appIdentifier is stored both as the string and as the
 *           parsed u64 in appIdentifierU64.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfigAppIdentifierU64, TestSize.Level0)
{
    const std::string json = BuildConfigJsonWithValue("appIdentifier", R"("20020026")");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ("20020026", config.appIdentifier);
    EXPECT_EQ(20020026ULL, config.appIdentifierU64);
}

/**
 * @tc.name: ParseConfigAppIdentifierHex
 * @tc.desc: A 0x-prefixed hex appIdentifier parses into appIdentifierU64.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfigAppIdentifierHex, TestSize.Level0)
{
    const std::string json = BuildConfigJsonWithValue("appIdentifier", R"("0xDEC00001")");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(0xDEC00001ULL, config.appIdentifierU64);
}

/**
 * @tc.name: ParseConfigAppIdentifierNonNumeric
 * @tc.desc: A non-integer appIdentifier (e.g. a dotted bundle id) rejects the
 *           whole config with SANDBOX_ERR_CONFIG_INVALID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfigAppIdentifierNonNumeric, TestSize.Level0)
{
    const std::string json = BuildConfigJsonWithValue("appIdentifier", R"("com.example.app")");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfigAppIdentifierOverflow
 * @tc.desc: An appIdentifier overflowing u64 rejects the config.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfigAppIdentifierOverflow, TestSize.Level0)
{
    const std::string json = BuildConfigJsonWithValue("appIdentifier", R"("99999999999999999999999999")");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfigAppIdentifierTrailingGarbage
 * @tc.desc: An appIdentifier with trailing non-numeric characters rejects.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfigAppIdentifierTrailingGarbage, TestSize.Level0)
{
    const std::string json = BuildConfigJsonWithValue("appIdentifier", R"("123abc")");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfigAppIdentifierMax
 * @tc.desc: Both forms survive at the top of the range: XPM consumes the string,
 *           AIDS and DEC the number.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfigAppIdentifierMax, TestSize.Level0)
{
    const std::string json = BuildConfigJsonWithValue("appIdentifier", R"("18446744073709551615")");
    SandboxConfig config;
    ASSERT_EQ(SANDBOX_SUCCESS, CmdParser::ParseConfig(json, config));
    EXPECT_EQ("18446744073709551615", config.appIdentifier);
    EXPECT_EQ(UINT64_MAX, config.appIdentifierU64);
}

/**
 * @tc.name: ParseConfigAppIdentifierEmpty
 * @tc.desc: A cli caller sends appIdentifier empty; the u64 conversion is skipped
 *           rather than failing the config.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfigAppIdentifierEmpty, TestSize.Level0)
{
    const std::string json = BuildConfigJsonWithValue("appIdentifier", R"("")");
    SandboxConfig config;
    // Not the struct's default: the step has to write the field, not skip it.
    config.appIdentifierU64 = UINT64_MAX;
    ASSERT_EQ(SANDBOX_SUCCESS, CmdParser::ParseConfig(json, config));
    EXPECT_TRUE(config.appIdentifier.empty());
    EXPECT_EQ(0ULL, config.appIdentifierU64);
}

/**
 * @tc.name: ParseConfig002
 * @tc.desc: ParseConfig with invalid JSON string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig002, TestSize.Level0)
{
    const std::string json = "not valid json";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig003
 * @tc.desc: ParseConfig with missing required field (callerTokenId)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig003, TestSize.Level0)
{
    const std::string json = R"({
        "callerPid": 1000,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig004
 * @tc.desc: ParseConfig with valid name (hex string)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig004, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "name": "abcdef0123456789"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ("abcdef0123456789", config.name);
}

/**
 * @tc.name: ParseConfig005
 * @tc.desc: ParseConfig with invalid name (non-hex characters)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig005, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "name": "hello-world!"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig006
 * @tc.desc: ParseConfig with name exceeding max length (64 chars)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig006, TestSize.Level0)
{
    std::string longName(65, 'a');
    std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "name": ")" + longName + R"("
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig007
 * @tc.desc: ParseConfig with valid nsFlags array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig007, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "nsFlags": ["net", "pid", "uts"]
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    uint32_t expectedFlags = CLONE_NEWNS;
    expectedFlags |= CLONE_NEWNET;
    expectedFlags |= CLONE_NEWPID;
    expectedFlags |= CLONE_NEWUTS;
    EXPECT_EQ(expectedFlags, config.nsFlags);
}

/**
 * @tc.name: ParseConfig008
 * @tc.desc: ParseConfig with nsFlags exceeding max count (10)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig008, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "nsFlags": ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"]
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig009
 * @tc.desc: ParseConfig with nsFlags containing non-string element
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig009, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "nsFlags": [123]
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig010
 * @tc.desc: ParseConfig with uint32 field out of range
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig010, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 1,
        "callerPid": -1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: ParseConfig011
 * @tc.desc: ParseConfig with large uint64 tokenId (close to 2^53 safe boundary)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig011, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 9007199254740990,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(9007199254740990ULL, config.callerTokenId);
}

/**
 * @tc.name: ParseConfig012
 * @tc.desc: ParseConfig with empty JSON object (all required fields missing)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig012, TestSize.Level0)
{
    const std::string json = "{}";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig013
 * @tc.desc: ParseConfig with string field exceeding max length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig013, TestSize.Level0)
{
    std::string longStr(257, 'x');
    std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": ")" + longStr + R"(",
        "subCliName": "sub"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig014
 * @tc.desc: ParseConfig with nsFlags string exceeding max length per flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig014, TestSize.Level0)
{
    std::string longFlag(25, 'x');
    std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "nsFlags": [")" + longFlag + R"("]
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig015
 * @tc.desc: ParseConfig rejects optional fields with wrong JSON types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig015, TestSize.Level0)
{
    const std::string invalidNameJson = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "name": 123
    })";
    SandboxConfig config;
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, CmdParser::ParseConfig(invalidNameJson, config));

    const std::string invalidNsFlagsJson = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "nsFlags": {"net": true}
    })";
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, CmdParser::ParseConfig(invalidNsFlagsJson, config));
}

/**
 * @tc.name: ParseConfig016
 * @tc.desc: ParseConfig rejects missing required numeric fields after callerTokenId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig016, TestSize.Level0)
{
    const char *missingFields[] = {"callerPid", "uid", "gid"};

    for (const char *field : missingFields) {
        SCOPED_TRACE(field);
        SandboxConfig config;
        EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
            CmdParser::ParseConfig(BuildConfigJsonWithoutField(field), config));
    }
}

/**
 * @tc.name: ParseConfig017
 * @tc.desc: ParseConfig rejects missing required string fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig017, TestSize.Level0)
{
    const char *missingFields[] = {"appIdentifier", "bundleName", "cliName", "subCliName"};

    for (const char *field : missingFields) {
        SCOPED_TRACE(field);
        SandboxConfig config;
        EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
            CmdParser::ParseConfig(BuildConfigJsonWithoutField(field), config));
    }
}

/**
 * @tc.name: ParseConfig018
 * @tc.desc: ParseConfig rejects required numeric fields with wrong JSON types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig018, TestSize.Level0)
{
    const ConfigJsonField invalidFields[] = {
        {"callerTokenId", R"("1")"},
        {"callerPid", R"("1")"},
        {"uid", "true"},
        {"gid", "null"},
    };

    for (const auto &field : invalidFields) {
        SCOPED_TRACE(field.key);
        SandboxConfig config;
        EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
            CmdParser::ParseConfig(BuildConfigJsonWithValue(field.key, field.value), config));
    }
}

/**
 * @tc.name: ParseConfig019
 * @tc.desc: ParseConfig rejects uint32 values above the supported range
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig019, TestSize.Level0)
{
    const ConfigJsonField invalidFields[] = {
        {"callerPid", "4294967296"},
        {"uid", "4294967296"},
        {"gid", "4294967296"},
    };

    for (const auto &field : invalidFields) {
        SCOPED_TRACE(field.key);
        SandboxConfig config;
        EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
            CmdParser::ParseConfig(BuildConfigJsonWithValue(field.key, field.value), config));
    }
}

/**
 * @tc.name: ParseConfig020
 * @tc.desc: ParseConfig rejects string fields with wrong JSON types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig020, TestSize.Level0)
{
    const ConfigJsonField invalidFields[] = {
        {"challenge", "123"},
        {"appIdentifier", "false"},
        {"bundleName", "{}"},
        {"cliName", "[]"},
        {"subCliName", "null"},
    };

    for (const auto &field : invalidFields) {
        SCOPED_TRACE(field.key);
        SandboxConfig config;
        EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
            CmdParser::ParseConfig(BuildConfigJsonWithValue(field.key, field.value), config));
    }
}

/**
 * @tc.name: ParseConfig021
 * @tc.desc: ParseConfig accepts callerTokenId values above the double safe boundary
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig021, TestSize.Level0)
{
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(
        BuildConfigJsonWithValue("callerTokenId", "9007199254740994"), config);

    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig022
 * @tc.desc: ParseConfig rejects each string field above its max length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig022, TestSize.Level0)
{
    const ConfigJsonField invalidFields[] = {
        {"challenge", "\"" + std::string(40961, 'c') + "\""},
        {"appIdentifier", "\"" + std::string(10241, 'a') + "\""},
        {"bundleName", "\"" + std::string(257, 'b') + "\""},
        {"subCliName", "\"" + std::string(257, 's') + "\""},
    };

    for (const auto &field : invalidFields) {
        SCOPED_TRACE(field.key);
        SandboxConfig config;
        EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
            CmdParser::ParseConfig(BuildConfigJsonWithValue(field.key, field.value), config));
    }
}

/**
 * @tc.name: ParseConfig023
 * @tc.desc: ParseConfig accepts empty optional name and empty nsFlags array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig023, TestSize.Level0)
{
    std::string json = "{";
    for (const auto &field : BASE_CONFIG_FIELDS) {
        json += "\"";
        json += field.key;
        json += "\":";
        json += field.value;
        json += ",";
    }
    json += R"("name":"","nsFlags":[]})";

    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_TRUE(config.name.empty());
    EXPECT_EQ(CLONE_NEWNS, config.nsFlags);
}

/**
 * @tc.name: ParseConfig024
 * @tc.desc: ParseConfig accepts missing optional challenge
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig024, TestSize.Level0)
{
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(BuildConfigJsonWithoutField("challenge"), config);

    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_TRUE(config.challenge.empty());
}

/**
 * @tc.name: ParseConfig025
 * @tc.desc: ParseConfig accepts env and policy as JSON object strings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig025, TestSize.Level0)
{
    std::string json = BuildConfigJsonWithValue("", "");
    json = AddConfigJsonField(json, "env", ToJsonString(R"({"PATH":"/bin","HOME":"/tmp"})"));
    json = AddConfigJsonField(json, "policy",
        ToJsonString(R"({"mounts":[{"source":"/data/test","mode":"rw"}]})"));

    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);

    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ("/bin", config.env["PATH"]);
    ASSERT_EQ(1U, config.policy.mounts.size());
    EXPECT_EQ("/data/test", config.policy.mounts[0].source);
    EXPECT_FALSE(config.policy.mounts[0].readOnly);
}

/**
 * @tc.name: ParseConfig026
 * @tc.desc: ParseConfig skips empty env and policy strings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig026, TestSize.Level0)
{
    std::string json = BuildConfigJsonWithValue("", "");
    json = AddConfigJsonField(json, "env", R"("")");
    json = AddConfigJsonField(json, "policy", R"("")");

    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);

    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_TRUE(config.env.empty());
    EXPECT_TRUE(config.policy.mounts.empty());
}

/**
 * @tc.name: ParseConfig027
 * @tc.desc: ParseConfig rejects env and policy strings above whole-field length limits
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig027, TestSize.Level0)
{
    const ConfigJsonField invalidFields[] = {
        {"env", ToJsonString(std::string(10241, 'e'))},
        {"policy", ToJsonString(std::string(102401, 'p'))},
    };

    for (const auto &field : invalidFields) {
        SCOPED_TRACE(field.key);
        SandboxConfig config;
        std::string json = AddConfigJsonField(BuildConfigJsonWithValue("", ""), field.key, field.value);
        EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, CmdParser::ParseConfig(json, config));
    }
}

/**
 * @tc.name: ParseConfig028
 * @tc.desc: ParseConfig accepts policy source longer than the old per-source limit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig028, TestSize.Level0)
{
    std::string longSource = "/" + std::string(1500, 'a');
    std::string policy = R"({"mounts":[{"source":")" + longSource + R"(","mode":"ro"}]})";
    std::string json = AddConfigJsonField(BuildConfigJsonWithValue("", ""), "policy", ToJsonString(policy));

    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);

    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(1U, config.policy.mounts.size());
    EXPECT_EQ(longSource, config.policy.mounts[0].source);
    EXPECT_TRUE(config.policy.mounts[0].readOnly);
}

/**
 * @tc.name: ParseConfig029
 * @tc.desc: ParseConfig rejects env and policy strings that do not parse to objects
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig029, TestSize.Level0)
{
    const ConfigJsonField invalidFields[] = {
        {"env", ToJsonString("[]")},
        {"policy", ToJsonString("[]")},
    };

    for (const auto &field : invalidFields) {
        SCOPED_TRACE(field.key);
        SandboxConfig config;
        std::string json = AddConfigJsonField(BuildConfigJsonWithValue("", ""), field.key, field.value);
        EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, CmdParser::ParseConfig(json, config));
    }
}

/**
 * @tc.name: ParseConfig030
 * @tc.desc: ParseConfig accepts env and policy as direct JSON objects
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig030, TestSize.Level0)
{
    std::string json = BuildConfigJsonWithValue("", "");
    json = AddConfigJsonField(json, "workdir", R"("/tmp/claw_sandbox_ut")");
    json = AddConfigJsonField(json, "env", R"({"PATH":"/usr/bin","TERM":"xterm"})");
    json = AddConfigJsonField(json, "policy",
        R"({"mounts":[{"source":"/data/ro","mode":"ro"},{"source":"/data/rw","mode":"rw"}]})");

    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);

    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ("/tmp/claw_sandbox_ut", config.workdir);
    EXPECT_EQ("/usr/bin", config.env["PATH"]);
    ASSERT_EQ(2U, config.policy.mounts.size());
    EXPECT_EQ("/data/ro", config.policy.mounts[0].source);
    EXPECT_TRUE(config.policy.mounts[0].readOnly);
    EXPECT_EQ("/data/rw", config.policy.mounts[1].source);
    EXPECT_FALSE(config.policy.mounts[1].readOnly);
}

/**
 * @tc.name: ParseConfig031
 * @tc.desc: ParseConfig rejects invalid env object contents
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig031, TestSize.Level0)
{
    const ConfigJsonField invalidEnvFields[] = {
        {"env", R"({"KEY":123})"},
        {"env", R"({"":"value"})"},
        {"env", R"({"BAD=KEY":"value"})"},
    };

    for (const auto &field : invalidEnvFields) {
        SCOPED_TRACE(field.value);
        SandboxConfig config;
        std::string json = AddConfigJsonField(BuildConfigJsonWithValue("", ""), field.key, field.value);
        EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, CmdParser::ParseConfig(json, config));
    }
}

/**
 * @tc.name: ParseConfig032
 * @tc.desc: ParseConfig rejects invalid policy mount contents
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig032, TestSize.Level0)
{
    const ConfigJsonField invalidPolicyFields[] = {
        {"policy", R"({"mounts":"bad"})"},
        {"policy", R"({"mounts":[100]})"},
        {"policy", R"({"mounts":[{"mode":"ro"}]})"},
        {"policy", R"({"mounts":[{"source":123,"mode":"ro"}]})"},
        {"policy", R"({"mounts":[{"source":"","mode":"ro"}]})"},
        {"policy", R"({"mounts":[{"source":"relative","mode":"ro"}]})"},
        {"policy", R"({"mounts":[{"source":"/data/test"}]})"},
        {"policy", R"({"mounts":[{"source":"/data/test","mode":"bad"}]})"},
    };

    for (const auto &field : invalidPolicyFields) {
        SCOPED_TRACE(field.value);
        SandboxConfig config;
        std::string json = AddConfigJsonField(BuildConfigJsonWithValue("", ""), field.key, field.value);
        EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, CmdParser::ParseConfig(json, config));
    }
}

/**
 * @tc.name: ParseConfig033
 * @tc.desc: ParseConfig rejects wrong direct types for env policy and workdir
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig033, TestSize.Level0)
{
    const ConfigJsonField invalidFields[] = {
        {"env", "123"},
        {"policy", "false"},
        {"workdir", "123"},
        {"workdir", "\"" + std::string(1025, 'w') + "\""},
    };

    for (const auto &field : invalidFields) {
        SCOPED_TRACE(field.key);
        SandboxConfig config;
        std::string json = AddConfigJsonField(BuildConfigJsonWithValue("", ""), field.key, field.value);
        EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, CmdParser::ParseConfig(json, config));
    }
}

/*
 * Shell sandboxes are PC only, so the same JSON has two correct answers. Both
 * are asserted rather than skipping one platform: "shell is refused off PC" is
 * behaviour that can regress, not an absence of behaviour.
 */
#ifdef CONFIG_SHELL_SANDBOX

/**
 * @tc.name: ParseConfig034
 * @tc.desc: ParseConfig with valid JSON containing all required fields when type is "shell"
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig034, TestSize.Level0)
{
    ScopedPcMode pcMode("true");
    const std::string json = R"({
        "callerTokenId": 123456789,
        "callerPid": 1000,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "test-challenge",
        "appIdentifier": "20020026",
        "bundleName": "com.example.bundle",
        "type": "shell"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
#ifndef CONFIG_SHELL_SANDBOX
    // Without the shell sandbox built in, the type is refused before PC mode is consulted.
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
    return;
#endif
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(123456789ULL, config.callerTokenId);
    EXPECT_EQ(1000U, config.callerPid);
    EXPECT_EQ(20020026U, config.uid);
    EXPECT_EQ(20020026U, config.gid);
    EXPECT_EQ("test-challenge", config.challenge);
    EXPECT_EQ("20020026", config.appIdentifier);
    EXPECT_EQ("com.example.bundle", config.bundleName);
    // cliName and subCliName to default to empty strings when type is "shell"
    EXPECT_EQ("", config.cliName);
    EXPECT_EQ("", config.subCliName);
    EXPECT_TRUE(config.name.empty());
    // When nsFlags is not specified in JSON, it defaults to CLONE_NEWNS
    EXPECT_EQ(CLONE_NEWNS, config.nsFlags);
}

/**
 * @tc.name: ParseConfig035
 * @tc.desc: Verify ParseConfig ignores cliName and subCliName when type is "shell".
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig035, TestSize.Level0)
{
    ScopedPcMode pcMode("true");
    const std::string json = R"({
        "callerTokenId": 9007199254740990,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "type": "shell",
        "cliName": "cli",
        "subCliName": "sub"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
#ifndef CONFIG_SHELL_SANDBOX
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
    return;
#endif
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(9007199254740990ULL, config.callerTokenId);
    // Even if provided in JSON, they should be parsed as empty strings when type is "shell"
    EXPECT_EQ("", config.cliName);
    EXPECT_EQ("", config.subCliName);
}

#else

/**
 * @tc.name: ParseConfig034
 * @tc.desc: Off PC the shell type is refused at the config parser, before any
 *           template lookup can turn it into a missing-file error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig034, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 123456789,
        "callerPid": 1000,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "test-challenge",
        "appIdentifier": "20020026",
        "bundleName": "com.example.bundle",
        "type": "shell"
    })";
    SandboxConfig config;
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, CmdParser::ParseConfig(json, config));
}

#endif // CONFIG_SHELL_SANDBOX

/**
 * @tc.name: ParseConfigPcModeOff001
 * @tc.desc: With PC mode off, the shell type is refused by the config parser.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfigPcModeOff001, TestSize.Level0)
{
    ScopedPcMode pcMode("false");
    const std::string json = R"({
        "callerTokenId": 123456789,
        "callerPid": 1000,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "test-challenge",
        "appIdentifier": "20020026",
        "bundleName": "com.example.bundle",
        "type": "shell"
    })";
    SandboxConfig config;
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, CmdParser::ParseConfig(json, config));
}

/**
 * @tc.name: ParseConfigPcModeOff002
 * @tc.desc: The gate is scoped to the shell type - cli still parses with PC mode off.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfigPcModeOff002, TestSize.Level0)
{
    ScopedPcMode pcMode("false");
    const std::string json = R"({
        "callerTokenId": 123456789,
        "callerPid": 1000,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "test-challenge",
        "appIdentifier": "20020026",
        "bundleName": "com.example.bundle",
        "type": "cli",
        "cliName": "cli",
        "subCliName": "sub"
    })";
    SandboxConfig config;
    EXPECT_EQ(SANDBOX_SUCCESS, CmdParser::ParseConfig(json, config));
    EXPECT_EQ("cli", config.cliName);
    EXPECT_EQ("sub", config.subCliName);
}

/**
 * @tc.name: ParseConfig036
 * @tc.desc: ParseConfig with valid JSON containing all required fields when type explicitly is "cli"
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig036, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 123456789,
        "callerPid": 1000,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "test-challenge",
        "appIdentifier": "20020026",
        "bundleName": "com.example.bundle",
        "type": "cli",
        "cliName": "testCli",
        "subCliName": "testSubCli"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(123456789ULL, config.callerTokenId);
    EXPECT_EQ(1000U, config.callerPid);
    EXPECT_EQ(20020026U, config.uid);
    EXPECT_EQ(20020026U, config.gid);
    EXPECT_EQ("test-challenge", config.challenge);
    EXPECT_EQ("20020026", config.appIdentifier);
    EXPECT_EQ("com.example.bundle", config.bundleName);
    EXPECT_EQ("testCli", config.cliName);
    EXPECT_EQ("testSubCli", config.subCliName);
    EXPECT_TRUE(config.name.empty());
    // When nsFlags is not specified in JSON, it defaults to CLONE_NEWNS
    EXPECT_EQ(CLONE_NEWNS, config.nsFlags);
}

/**
 * @tc.name: ParseConfig037
 * @tc.desc: Verify ParseConfig returns SANDBOX_ERR_CONFIG_INVALID
 * when an unsupported type (e.g., "others") is provided.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig037, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 9007199254740990,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "type": "others"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig038
 * @tc.desc: ParseConfig accepts valid policy with AddOperationControlRuleGroups and self_session scope
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig038, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "policy": "{
            \"AddOperationControlRuleGroups\": [
                {
                    \"Scope\": { \"Type\": \"self_session\", \"priority\": \"absolute\" },
                    \"Network\": { \"DefaultAction\": \"deny\" }
                }
            ]
        }"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: ParseConfig039
 * @tc.desc: A configured Network object must carry a DefaultAction: "Network": {} is
 *           rejected (DefaultAction is required whenever Network is present)
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef CONFIG_SHELL_SANDBOX
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig039, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "policy": "{
            \"AddOperationControlRuleGroups\": [
                {
                    \"Scope\": { \"Type\": \"self_session\", \"priority\": \"absolute\" },
                    \"Network\": {}
                }
            ]
        }"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}
#endif // CONFIG_SHELL_SANDBOX

/**
 * @tc.name: ParseConfig040
 * @tc.desc: ParseConfig accepts valid policy without Network field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig040, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "policy": "{
            \"AddOperationControlRuleGroups\": [
                {
                    \"Scope\": { \"Type\": \"self_session\", \"priority\": \"absolute\" }
                }
            ]
        }"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
}

// ParseConfig041-044 assert op-driven CONFIG_INVALID results. Their rejection comes from
// ParseOperationControlRuleGroups, which is only compiled under CONFIG_SHELL_SANDBOX (the
// AddOperationControlRuleGroups payload is skipped in non-shell builds and the otherwise
// valid config would parse SUCCESS). Gate them like ParseConfig039 above.
#ifdef CONFIG_SHELL_SANDBOX
/**
 * @tc.name: ParseConfig041
 * @tc.desc: ParseConfig accepts invalid policy without Scope field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig041, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "policy": "{
            \"AddOperationControlRuleGroups\": [
                {
                    \"Network\":{\"DefaultAction\": \"deny\"}
                }
            ]
        }"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig042
 * @tc.desc: ParseConfig accepts invalid policy with unsupported Scope type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig042, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "policy": "{
            \"AddOperationControlRuleGroups\": [
                {
                    \"Scope\": { \"Type\": \"global\" },
                    \"Network\": { \"DefaultAction\": \"deny\" }
                }
            ]
        }"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig043
 * @tc.desc: ParseConfig accepts invalid policy with unsupported network DefaultAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig043, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "policy": "{
            \"AddOperationControlRuleGroups\": [
                {
                    \"Scope\": { \"Type\": \"self_session\", \"priority\": \"absolute\" },
                    \"Network\": { \"DefaultAction\": \"ask\" }
                }
            ]
        }"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig044
 * @tc.desc: ParseConfig accepts invalid policy with no Scope type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig044, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "policy": "{
            \"AddOperationControlRuleGroups\": [
                {
                    \"Scope\": { \"Type\": \"\" },
                    \"Network\": { \"DefaultAction\": \"deny\" }
                }
            ]
        }"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}
#endif // CONFIG_SHELL_SANDBOX

/**
 * @tc.name: ParseConfig045
 * @tc.desc: ParseConfig rejects policy mounts with path traversal in source
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig045, TestSize.Level0)
{
    const ConfigJsonField traversalPolicyFields[] = {
        {"policy", R"({"mounts":[{"source":"/data/../etc","mode":"ro"}]})"},
        {"policy", R"({"mounts":[{"source":"/data/..","mode":"ro"}]})"},
        {"policy", R"({"mounts":[{"source":"/data/../../etc/passwd","mode":"ro"}]})"},
        {"policy", R"({"mounts":[{"source":"/data/foo/../../bar","mode":"ro"}]})"},
        {"policy", R"({"mounts":[{"source":"/..","mode":"ro"}]})"},
    };
    for (const auto &field : traversalPolicyFields) {
        SandboxConfig config;
        std::string json = AddConfigJsonField(
            BuildConfigJsonWithValue("", ""), field.key, field.value);
        int ret = CmdParser::ParseConfig(json, config);
        EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
    }
}

/**
 * @tc.name: ParseConfig046
 * @tc.desc: ParseConfig accepts policy mounts with safe source paths containing dots
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig046, TestSize.Level0)
{
    SandboxConfig config;
    std::string json = AddConfigJsonField(
        BuildConfigJsonWithValue("", ""), "policy",
        R"({"mounts":[{"source":"/data/.dotdir","mode":"ro"},)"
        R"({"source":"/data/test.dir/file","mode":"rw"}]})");
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(2U, config.policy.mounts.size());
    EXPECT_EQ("/data/.dotdir", config.policy.mounts[0].source);
    EXPECT_EQ("/data/test.dir/file", config.policy.mounts[1].source);
}

/**
 * @tc.name: ParseConfig047
 * @tc.desc: CheckJsonDepth (top-level config) — flat config with env object passes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig047, TestSize.Level0)
{
    std::string json = AddConfigJsonField(
        BuildConfigJsonWithValue("", ""), "env",
        R"({"flatKey":"flatValue"})");
    SandboxConfig config;
    EXPECT_EQ(SANDBOX_SUCCESS, CmdParser::ParseConfig(json, config));
    EXPECT_EQ("flatValue", config.env["flatKey"]);
}

/**
 * @tc.name: ParseConfig048
 * @tc.desc: CheckJsonDepth (top-level config) — nested array/object config passes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig048, TestSize.Level0)
{
    std::string json = AddConfigJsonField(
        BuildConfigJsonWithValue("", ""), "policy",
        R"({"mounts":[{"source":"/data/a","mode":"ro"},{"source":"/data/b","mode":"rw"}]})");
    SandboxConfig config;
    EXPECT_EQ(SANDBOX_SUCCESS, CmdParser::ParseConfig(json, config));
    ASSERT_EQ(2U, config.policy.mounts.size());
    EXPECT_EQ("/data/a", config.policy.mounts[0].source);
    EXPECT_TRUE(config.policy.mounts[0].readOnly);
    EXPECT_EQ("/data/b", config.policy.mounts[1].source);
    EXPECT_FALSE(config.policy.mounts[1].readOnly);
}

/**
 * @tc.name: ParseConfig049
 * @tc.desc: CheckJsonDepth (top-level config) — exceeds max depth (65 > 64), returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig049, TestSize.Level0)
{
    std::string deepJson = std::string(65, '[') + "1" + std::string(65, ']');
    SandboxConfig config;
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, CmdParser::ParseConfig(deepJson, config));
}

/**
 * @tc.name: ParseConfig050
 * @tc.desc: CheckJsonDepth (top-level config) — empty object passes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig050, TestSize.Level0)
{
    // 将 "{}" 修改为 "\"{}\""
    std::string json = AddConfigJsonField(
        BuildConfigJsonWithValue("", ""), "env", "{}");
    SandboxConfig config;
    EXPECT_EQ(SANDBOX_SUCCESS, CmdParser::ParseConfig(json, config));
    EXPECT_TRUE(config.env.empty());
}

// ==================== ParseCommandFromArgv tests ====================

/**
 * @tc.name: ParseCommandFromArgv001
 * @tc.desc: ParseCommandFromArgv copies a basic argv array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseCommandFromArgv001, TestSize.Level0)
{
    char arg0[] = "echo";
    char arg1[] = "hello";
    char arg2[] = "world";
    char *argv[] = {arg0, arg1, arg2};

    CmdInfo info = CmdParser::ParseCommandFromArgv(3, argv);
    ASSERT_EQ(3U, info.argv.size());
    EXPECT_EQ("echo", info.argv[0]);
    EXPECT_EQ("hello", info.argv[1]);
    EXPECT_EQ("world", info.argv[2]);
}

/**
 * @tc.name: ParseCommandFromArgv002
 * @tc.desc: ParseCommandFromArgv preserves each argv element as one argument
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseCommandFromArgv002, TestSize.Level0)
{
    char arg0[] = "cmd";
    char arg1[] = "arg with spaces";
    char arg2[] = "\"quoted value\"";
    char arg3[] = "";
    char *argv[] = {arg0, arg1, arg2, arg3};

    CmdInfo info = CmdParser::ParseCommandFromArgv(4, argv);
    ASSERT_EQ(4U, info.argv.size());
    EXPECT_EQ("cmd", info.argv[0]);
    EXPECT_EQ("arg with spaces", info.argv[1]);
    EXPECT_EQ("\"quoted value\"", info.argv[2]);
    EXPECT_EQ("", info.argv[3]);
}

/**
 * @tc.name: ParseCommandFromArgv003
 * @tc.desc: ParseCommandFromArgv returns empty argv for invalid inputs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseCommandFromArgv003, TestSize.Level0)
{
    char arg0[] = "ignored";
    char *argv[] = {arg0};

    CmdInfo zeroArgcInfo = CmdParser::ParseCommandFromArgv(0, argv);
    EXPECT_TRUE(zeroArgcInfo.argv.empty());

    CmdInfo negativeArgcInfo = CmdParser::ParseCommandFromArgv(-1, argv);
    EXPECT_TRUE(negativeArgcInfo.argv.empty());

    CmdInfo nullArgvInfo = CmdParser::ParseCommandFromArgv(1, nullptr);
    EXPECT_TRUE(nullArgvInfo.argv.empty());
}

/**
 * @tc.name: ParseCommandFromArgv004
 * @tc.desc: ParseCommandFromArgv skips null argv elements
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseCommandFromArgv004, TestSize.Level0)
{
    char arg0[] = "cmd";
    char arg2[] = "tail";
    char *argv[] = {arg0, nullptr, arg2};

    CmdInfo info = CmdParser::ParseCommandFromArgv(3, argv);
    ASSERT_EQ(2U, info.argv.size());
    EXPECT_EQ("cmd", info.argv[0]);
    EXPECT_EQ("tail", info.argv[1]);
}

/**
 * @tc.name: ParseCommandFromArgv005
 * @tc.desc: ParseCommandFromArgv stores string values instead of argv pointers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseCommandFromArgv005, TestSize.Level0)
{
    char arg0[] = "cmd";
    char arg1[] = "arg";
    char *argv[] = {arg0, arg1};

    CmdInfo info = CmdParser::ParseCommandFromArgv(2, argv);
    ASSERT_EQ(2U, info.argv.size());
    EXPECT_EQ("cmd", info.argv[0]);
    EXPECT_EQ("arg", info.argv[1]);

    arg1[0] = 'A';
    EXPECT_EQ("arg", info.argv[1]);
}

// ==================== ConvertNsFlags tests ====================

/**
 * @tc.name: ConvertNsFlags001
 * @tc.desc: ConvertNsFlags with empty vector returns CLONE_NEWNS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ConvertNsFlags001, TestSize.Level0)
{
    std::vector<std::string> flags;
    uint32_t result = 0;
    EXPECT_EQ(SANDBOX_SUCCESS, CmdParser::ConvertNsFlags(flags, result));
    EXPECT_EQ(CLONE_NEWNS, result);
}

/**
 * @tc.name: ConvertNsFlags002
 * @tc.desc: ConvertNsFlags with "pid" adds CLONE_NEWPID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ConvertNsFlags002, TestSize.Level0)
{
    std::vector<std::string> flags = {"pid"};
    uint32_t result = 0;
    EXPECT_EQ(SANDBOX_SUCCESS, CmdParser::ConvertNsFlags(flags, result));
    EXPECT_TRUE(result & CLONE_NEWPID);
    EXPECT_TRUE(result & CLONE_NEWNS);
}

/**
 * @tc.name: ConvertNsFlags003
 * @tc.desc: ConvertNsFlags with "uts" adds CLONE_NEWUTS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ConvertNsFlags003, TestSize.Level0)
{
    std::vector<std::string> flags = {"uts"};
    uint32_t result = 0;
    EXPECT_EQ(SANDBOX_SUCCESS, CmdParser::ConvertNsFlags(flags, result));
    EXPECT_TRUE(result & CLONE_NEWUTS);
}

/**
 * @tc.name: ConvertNsFlags004
 * @tc.desc: ConvertNsFlags with "ipc" adds CLONE_NEWIPC
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ConvertNsFlags004, TestSize.Level0)
{
    std::vector<std::string> flags = {"ipc"};
    uint32_t result = 0;
    EXPECT_EQ(SANDBOX_SUCCESS, CmdParser::ConvertNsFlags(flags, result));
    EXPECT_TRUE(result & CLONE_NEWIPC);
}

/**
 * @tc.name: ConvertNsFlags005
 * @tc.desc: ConvertNsFlags with "user" adds CLONE_NEWUSER
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ConvertNsFlags005, TestSize.Level0)
{
    std::vector<std::string> flags = {"user"};
    uint32_t result = 0;
    EXPECT_EQ(SANDBOX_SUCCESS, CmdParser::ConvertNsFlags(flags, result));
    EXPECT_TRUE(result & CLONE_NEWUSER);
}

/**
 * @tc.name: ConvertNsFlags006
 * @tc.desc: ConvertNsFlags with multiple flags combines all
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ConvertNsFlags006, TestSize.Level0)
{
    std::vector<std::string> flags = {"pid", "uts", "ipc", "user", "net"};
    uint32_t result = 0;
    EXPECT_EQ(SANDBOX_SUCCESS, CmdParser::ConvertNsFlags(flags, result));
    EXPECT_TRUE(result & CLONE_NEWPID);
    EXPECT_TRUE(result & CLONE_NEWUTS);
    EXPECT_TRUE(result & CLONE_NEWIPC);
    EXPECT_TRUE(result & CLONE_NEWUSER);
    EXPECT_TRUE(result & CLONE_NEWNET);
    EXPECT_TRUE(result & CLONE_NEWNS);
}

/**
 * @tc.name: ConvertNsFlags007
 * @tc.desc: An unknown namespace name is rejected, not skipped: it would leave a
 *           sandbox weaker than the config asked for
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ConvertNsFlags007, TestSize.Level0)
{
    std::vector<std::string> flags = {"unknown", "bogus"};
    uint32_t result = 0;
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, CmdParser::ConvertNsFlags(flags, result));
    EXPECT_EQ(0, result);  // left alone on failure
}

/**
 * @tc.name: ConvertNsFlags008
 * @tc.desc: ConvertNsFlags with "mnt" adds CLONE_NEWNS (duplicate, but valid)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ConvertNsFlags008, TestSize.Level0)
{
    std::vector<std::string> flags = {"mnt"};
    uint32_t result = 0;
    EXPECT_EQ(SANDBOX_SUCCESS, CmdParser::ConvertNsFlags(flags, result));
    // CLONE_NEWNS is already in the base flags
    EXPECT_TRUE(result & CLONE_NEWNS);
}

/**
 * @tc.name: ConvertNsFlags009
 * @tc.desc: One bad name among good ones fails the whole array; a partially
 *           applied set is exactly what must not reach the sandbox
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ConvertNsFlags009, TestSize.Level0)
{
    // "nte" is the typo this rejection exists for.
    std::vector<std::string> flags = {"pid", "nte", "ipc"};
    uint32_t result = 0;
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, CmdParser::ConvertNsFlags(flags, result));
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: ConvertNsFlags010
 * @tc.desc: The rejection reaches ParseConfig, so a misspelled nsFlags fails the
 *           launch instead of quietly starting a less isolated sandbox
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ConvertNsFlags010, TestSize.Level0)
{
    std::string json = BuildConfigJsonWithValue("", "");
    json = AddConfigJsonField(json, "nsFlags", R"(["net","nte"])");

    SandboxConfig config;
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, CmdParser::ParseConfig(json, config));
}

/**
 * @tc.name: ConvertNsFlags011
 * @tc.desc: The same config with the name spelled right still parses, so the
 *           rejection above is about the bad name and nothing else
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ConvertNsFlags011, TestSize.Level0)
{
    std::string json = BuildConfigJsonWithValue("", "");
    json = AddConfigJsonField(json, "nsFlags", R"(["net","pid"])");

    SandboxConfig config;
    ASSERT_EQ(SANDBOX_SUCCESS, CmdParser::ParseConfig(json, config));
    EXPECT_TRUE(config.nsFlags & CLONE_NEWNET);
    EXPECT_TRUE(config.nsFlags & CLONE_NEWPID);
    EXPECT_TRUE(config.nsFlags & CLONE_NEWNS);
}

// ==================== ExecuteCommand tests ====================

/**
 * @tc.name: ExecuteCommand001
 * @tc.desc: A bare command name is not resolved, because PATH is no longer searched
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ExecuteCommand001, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    cmdInfo.argv = {"echo", "hello"};
    manager.Initialize(std::move(config), cmdInfo);

    // The executable is opened by the exact name given, so that the file being
    // vetted is the file being run. "echo" therefore has to exist relative to
    // the working directory - it is not looked up in PATH.
    EXPECT_EQ(SANDBOX_ERR_CMD_INVALID, manager.ExecuteCommand());
}

/**
 * @tc.name: ExecuteCommand003
 * @tc.desc: A template that declares no exec types denies every executable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ExecuteCommand003, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    // An absolute path that exists, so the refusal can only come from the check.
    cmdInfo.argv = {"/proc/self/exe"};
    manager.Initialize(std::move(config), cmdInfo);

    ASSERT_TRUE(manager.templateConfig_.execSelinuxTypes.empty());
    // Empty means "nothing may exec", not "anything may exec": a template that
    // forgets exec-selinux-types must not silently disable the check.
    EXPECT_EQ(SANDBOX_ERR_CMD_INVALID, manager.ExecuteCommand());
}

/**
 * @tc.name: ExecuteCommand002
 * @tc.desc: ExecuteCommand with empty cmd falls back to execl which fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ExecuteCommand002, TestSize.Level0)
{
    SandboxManager manager;
    SandboxConfig config;
    config.uid = 20020026;
    config.gid = 20020026;
    config.callerPid = 1000;
    config.callerTokenId = TEST_HAP_TOKEN_ID;
    CmdInfo cmdInfo;
    manager.Initialize(std::move(config), cmdInfo);

    int ret = manager.ExecuteCommand();
    EXPECT_EQ(SANDBOX_ERR_CMD_INVALID, ret);
}

#ifdef CONFIG_SHELL_SANDBOX
// The op-control (AddOperationControlRuleGroups) parse tests below exercise the
// DEC/AgentLock model + parser TU, which only exist in shell-sandbox builds. The
// whole helper + case block is gated so non-shell builds still compile.

namespace {

// Build a ParseConfig JSON whose policy carries a single rule group described by
// groupBody (raw JSON without the outer braces). Reuses the base config fields.
static std::string BuildRuleGroupConfigJson(const std::string &groupBody)
{
    std::string policyJson = "{ \"AddOperationControlRuleGroups\": [ { " +
        groupBody + " } ] }";
    return AddConfigJsonField(BuildConfigJsonWithValue("", ""), "policy",
        ToJsonString(policyJson));
}

// Build a cJSON policy object whose AddOperationControlRuleGroups holds one group
// described by groupBody (raw JSON without the outer braces). Drives
// ParseOperationControlRuleGroups directly (with an explicit phase); the caller must
// cJSON_Delete() the result. cJSON is already visible via sandbox_manager.h above.
static cJSON *BuildRuleGroupPolicyCjson(const std::string &groupBody)
{
    const std::string json = "{ \"AddOperationControlRuleGroups\": [ { " +
        groupBody + " } ] }";
    return cJSON_Parse(json.c_str());
}
}  // namespace

// ==================== ParseConfig: DefaultAction rules ====================
// File/Process.DefaultAction are optional (default NONE); Network.DefaultAction is
// REQUIRED when a Network object is present and admits only "deny"/"allow".

/**
 * @tc.name: ParseConfig051
 * @tc.desc: File.DefaultAction is accepted (optional field)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig051, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"self_session\", \"priority\": \"absolute\" }, "
        "\"File\": { \"DefaultAction\": \"deny\", \"DenyDelete\": [\"/a\"] }");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(1u, config.policy.addOperationControlRuleGroups.size());
    EXPECT_EQ(DEC_POLICY_ACTION_DENY,
        config.policy.addOperationControlRuleGroups[0].fileRules.defaultAction);
}

/**
 * @tc.name: ParseConfig052
 * @tc.desc: File without DefaultAction defaults to NONE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig052, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"self_session\", \"priority\": \"absolute\" }, "
        "\"File\": { \"DenyDelete\": [\"/a\"] }");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(1u, config.policy.addOperationControlRuleGroups.size());
    EXPECT_EQ(DEC_POLICY_ACTION_NONE,
        config.policy.addOperationControlRuleGroups[0].fileRules.defaultAction);
}

/**
 * @tc.name: ParseConfig053
 * @tc.desc: File with an invalid DefaultAction value is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig053, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"self_session\", \"priority\": \"absolute\" }, "
        "\"File\": { \"DefaultAction\": \"forbid\" }");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig054
 * @tc.desc: Process without DefaultAction defaults to NONE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig054, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"self_session\", \"priority\": \"absolute\" }, "
        "\"Process\": { \"DenyExecCmd\": [\"sh\"] }");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(1u, config.policy.addOperationControlRuleGroups.size());
    const SandboxPolicyProcessConfig &processRules =
        config.policy.addOperationControlRuleGroups[0].processRules;
    EXPECT_EQ(DEC_POLICY_ACTION_NONE, processRules.defaultAction);
    ASSERT_EQ(1u, processRules.denyExecCmd.size());
    EXPECT_EQ("sh", processRules.denyExecCmd[0]);
}

/**
 * @tc.name: ParseConfig055
 * @tc.desc: Process accepts an explicit DefaultAction of "none"
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig055, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"self_session\", \"priority\": \"absolute\" }, "
        "\"Process\": { \"DefaultAction\": \"none\" }");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(1u, config.policy.addOperationControlRuleGroups.size());
    EXPECT_EQ(DEC_POLICY_ACTION_NONE,
        config.policy.addOperationControlRuleGroups[0].processRules.defaultAction);
}

/**
 * @tc.name: ParseConfig056
 * @tc.desc: Process with an invalid DefaultAction value is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig056, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"self_session\", \"priority\": \"absolute\" }, "
        "\"Process\": { \"DefaultAction\": \"maybe\" }");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig057
 * @tc.desc: Network DefaultAction admits only "deny"/"allow": an explicit "none"
 *           is rejected just like "ask"
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig057, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"self_session\", \"priority\": \"absolute\" }, "
        "\"Network\": { \"DefaultAction\": \"none\" }");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig058
 * @tc.desc: All three modules in one group with mixed DefaultAction values parse
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig058, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"self_session\", \"priority\": \"absolute\" }, "
        "\"Network\": { \"DefaultAction\": \"deny\" }, "
        "\"File\": { \"DefaultAction\": \"ask\" }, "
        "\"Process\": { \"DefaultAction\": \"allow\" }");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(1u, config.policy.addOperationControlRuleGroups.size());
    const SandboxPolicyRuleGroup &group = config.policy.addOperationControlRuleGroups[0];
    EXPECT_EQ(DEC_POLICY_ACTION_DENY, group.networkRules.defaultAction);
    EXPECT_EQ(DEC_POLICY_ACTION_ASK, group.fileRules.defaultAction);
    EXPECT_EQ(DEC_POLICY_ACTION_ALLOW, group.processRules.defaultAction);
}

/**
 * @tc.name: ParseConfig059
 * @tc.desc: Scope needs only Type ("self_session"); priority is not parsed this
 *           version, so its absence is accepted and the parsed type is filled in
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig059, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"self_session\" }, "
        "\"Network\": { \"DefaultAction\": \"deny\" }");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(1u, config.policy.addOperationControlRuleGroups.size());
    EXPECT_EQ(DEC_POLICY_SCOPE_TYPE_SELF_SESSION,
        config.policy.addOperationControlRuleGroups[0].scope.type);
}

/**
 * @tc.name: ParseConfig060
 * @tc.desc: Scope.Type other than "self_session" is rejected this version
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig060, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"global\" }, "
        "\"Network\": { \"DefaultAction\": \"deny\" }");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig061
 * @tc.desc: Process DenyExecCmd with a path ("/bin/ls") is rejected: exec cmds
 *           must be bare command names without '/'
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig061, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"self_session\", \"priority\": \"absolute\" }, "
        "\"Process\": { \"DenyExecCmd\": [\"/bin/ls\"] }");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig062
 * @tc.desc: Process AskExecCmd with a path is rejected too ("/bin/sh")
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig062, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"self_session\", \"priority\": \"absolute\" }, "
        "\"Process\": { \"AskExecCmd\": [\"/bin/sh\"] }");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig063
 * @tc.desc: ParseConfig rejects rule groups carrying duplicate Scope.Type (the array
 *           exists for several DISTINCT scope types; with only self_session allowed,
 *           a second group duplicates it)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig063, TestSize.Level0)
{
    const std::string json = R"({
        "callerTokenId": 1,
        "callerPid": 1,
        "uid": 20020026,
        "gid": 20020026,
        "challenge": "ch",
        "appIdentifier": "20020026",
        "bundleName": "bundle",
        "cliName": "cli",
        "subCliName": "sub",
        "policy": "{
            \"AddOperationControlRuleGroups\": [
                {
                    \"Scope\": { \"Type\": \"self_session\", \"priority\": \"absolute\" },
                    \"Network\": { \"DefaultAction\": \"deny\" }
                },
                {
                    \"Scope\": { \"Type\": \"self_session\", \"priority\": \"absolute\" },
                    \"Network\": { \"DefaultAction\": \"deny\" }
                }
            ]
        }"
    })";
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig064
 * @tc.desc: File allow/ask and Process allow/ask arrays parse into their vectors
 *           (bare exec cmds pass the validator)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig064, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"self_session\" }, "
        "\"File\": { \"AllowDelete\": [\"/data/allow\"], \"AskDelete\": [\"/data/ask\"] }, "
        "\"Process\": { \"AllowExecCmd\": [\"cat\"], \"AskExecCmd\": [\"top\"] }");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(1u, config.policy.addOperationControlRuleGroups.size());
    const SandboxPolicyRuleGroup &group = config.policy.addOperationControlRuleGroups[0];
    ASSERT_EQ(1u, group.fileRules.allowDelete.size());
    EXPECT_EQ("/data/allow", group.fileRules.allowDelete[0]);
    ASSERT_EQ(1u, group.fileRules.askDelete.size());
    EXPECT_EQ("/data/ask", group.fileRules.askDelete[0]);
    ASSERT_EQ(1u, group.processRules.allowExecCmd.size());
    EXPECT_EQ("cat", group.processRules.allowExecCmd[0]);
    ASSERT_EQ(1u, group.processRules.askExecCmd.size());
    EXPECT_EQ("top", group.processRules.askExecCmd[0]);
}

/**
 * @tc.name: ParseConfig065
 * @tc.desc: Network rejects an explicit DefaultAction of "ask"
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig065, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"self_session\" }, "
        "\"Network\": { \"DefaultAction\": \"ask\" }");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig066
 * @tc.desc: A module field that is not an object ("File": 7) is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig066, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"self_session\" }, \"File\": 7");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig067
 * @tc.desc: A File array field that is not an array (DenyDelete as a string) is
 *           rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig067, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"self_session\" }, "
        "\"File\": { \"DenyDelete\": \"/a\" }");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig068
 * @tc.desc: A File array field holding a non-string item (DenyDelete: ["/a", 7])
 *           is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig068, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"self_session\" }, "
        "\"File\": { \"DenyDelete\": [\"/a\", 7] }");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig069
 * @tc.desc: A rule group with no Scope object is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig069, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Network\": { \"DefaultAction\": \"deny\" }");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig070
 * @tc.desc: AddOperationControlRuleGroups that is not an array is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig070, TestSize.Level0)
{
    const std::string policyJson =
        "{ \"AddOperationControlRuleGroups\": { \"Scope\": { \"Type\": \"self_session\" } } }";
    const std::string json =
        AddConfigJsonField(BuildConfigJsonWithValue("", ""), "policy", ToJsonString(policyJson));
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig071
 * @tc.desc: AddOperationControlRuleGroups holding a non-object item is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig071, TestSize.Level0)
{
    const std::string policyJson =
        "{ \"AddOperationControlRuleGroups\": [ { \"Scope\": { \"Type\": \"self_session\" } }, 7 ] }";
    const std::string json =
        AddConfigJsonField(BuildConfigJsonWithValue("", ""), "policy", ToJsonString(policyJson));
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig072
 * @tc.desc: A Network field that is not an object ("Network": 7) is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig072, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"self_session\" }, \"Network\": 7");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig073
 * @tc.desc: A Process field that is not an object ("Process": 7) is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig073, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"self_session\" }, \"Process\": 7");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig074
 * @tc.desc: Scope.Type with an unrecognized word is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig074, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"no_such_scope\" }, "
        "\"Network\": { \"DefaultAction\": \"deny\" }");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig075
 * @tc.desc: A DefaultAction that is not a string ("DefaultAction": 5) is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig075, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"self_session\" }, "
        "\"File\": { \"DefaultAction\": 5 }");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ParseConfig076
 * @tc.desc: Network accepts a DefaultAction of "allow" (one of the two allowed
 *           values), which lands on the network rules' default action
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig076, TestSize.Level0)
{
    const std::string json = BuildRuleGroupConfigJson(
        "\"Scope\": { \"Type\": \"self_session\" }, "
        "\"Network\": { \"DefaultAction\": \"allow\" }");
    SandboxConfig config;
    int ret = CmdParser::ParseConfig(json, config);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(1u, config.policy.addOperationControlRuleGroups.size());
    EXPECT_EQ(DEC_POLICY_ACTION_ALLOW,
        config.policy.addOperationControlRuleGroups[0].networkRules.defaultAction);
}

// ==================== ParseConfig: parse phase (STARTUP vs DYNAMIC) ====================
// STARTUP and DYNAMIC share one schema; a DYNAMIC policy may not carry a Network module
// (the network default is fixed at sandbox boot). ParseOperationControlRuleGroups is
// called directly here with an explicit phase because ParseConfig is always STARTUP.

/**
 * @tc.name: ParseConfig077
 * @tc.desc: A DYNAMIC (post-start) policy must not carry a Network module -- a group that
 *           does is rejected even when the Network object itself is well-formed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig077, TestSize.Level0)
{
    cJSON *policy = BuildRuleGroupPolicyCjson(
        "\"Scope\": { \"Type\": \"self_session\" }, "
        "\"Network\": { \"DefaultAction\": \"allow\" }");
    ASSERT_NE(policy, nullptr);
    std::vector<SandboxPolicyRuleGroup> groups;
    int ret = CmdParser::ParseOperationControlRuleGroups(policy, groups,
        SANDBOX_POLICY_PARSE_DYNAMIC);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
    cJSON_Delete(policy);
}

/**
 * @tc.name: ParseConfig078
 * @tc.desc: A DYNAMIC policy without a Network module parses normally -- File groups are
 *           admitted and no Network flag is raised
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig078, TestSize.Level0)
{
    cJSON *policy = BuildRuleGroupPolicyCjson(
        "\"Scope\": { \"Type\": \"self_session\" }, "
        "\"File\": { \"DenyDelete\": [\"/a\"] }");
    ASSERT_NE(policy, nullptr);
    std::vector<SandboxPolicyRuleGroup> groups;
    int ret = CmdParser::ParseOperationControlRuleGroups(policy, groups,
        SANDBOX_POLICY_PARSE_DYNAMIC);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(1u, groups.size());
    EXPECT_TRUE(groups[0].hasFile);
    EXPECT_FALSE(groups[0].hasNetwork);
    ASSERT_EQ(1u, groups[0].fileRules.denyDelete.size());
    EXPECT_EQ("/a", groups[0].fileRules.denyDelete[0]);
    cJSON_Delete(policy);
}

/**
 * @tc.name: ParseConfig079
 * @tc.desc: The STARTUP phase still admits a Network module -- guards that the DYNAMIC
 *           Network ban did not leak into the boot-time profile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxCmdParserTest, ParseConfig079, TestSize.Level0)
{
    cJSON *policy = BuildRuleGroupPolicyCjson(
        "\"Scope\": { \"Type\": \"self_session\" }, "
        "\"Network\": { \"DefaultAction\": \"allow\" }");
    ASSERT_NE(policy, nullptr);
    std::vector<SandboxPolicyRuleGroup> groups;
    int ret = CmdParser::ParseOperationControlRuleGroups(policy, groups,
        SANDBOX_POLICY_PARSE_STARTUP);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(1u, groups.size());
    EXPECT_TRUE(groups[0].hasNetwork);
    EXPECT_EQ(DEC_POLICY_ACTION_ALLOW, groups[0].networkRules.defaultAction);
    cJSON_Delete(policy);
}

#endif // CONFIG_SHELL_SANDBOX

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
