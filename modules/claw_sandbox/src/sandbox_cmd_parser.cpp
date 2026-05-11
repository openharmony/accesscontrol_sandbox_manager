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

#include "sandbox_cmd_parser.h"
#include "sandbox_error.h"
#include "sandbox_log.h"
#include <cstring>
#include <sstream>
#include <algorithm>
#include <iostream>
#include "cJSON.h"
#include <sched.h>

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

// Maximum safe integer value representable by double's 53-bit mantissa (2^53)
constexpr double DOUBLE_SAFE_MAX = 9007199254740992.0;

// Maximum value for uint32 (2^32 - 1)
constexpr double UINT32_MAX_VALUE = 4294967295.0;

// Maximum length for hex sandbox name
constexpr size_t MAX_NAME_LENGTH = 64;

// Maximum length constraints for config string fields
constexpr size_t MAX_CLI_NAME_LENGTH = 256;
constexpr size_t MAX_SUB_CLI_NAME_LENGTH = 256;
constexpr size_t MAX_CHALLENGE_LENGTH = 40960;
constexpr size_t MAX_APPID_LENGTH = 10240;
constexpr size_t MAX_BUNDLE_NAME_LENGTH = 256;

// Maximum constraints for nsFlags array
constexpr size_t MAX_NS_FLAGS_COUNT = 10;
constexpr size_t MAX_NS_FLAG_STRING_LENGTH = 24;

// Maximum command line length (2MB)
constexpr size_t MAX_CMD_LINE_LENGTH = 0x200000;

// Helper: clean up cJSON root and return error code
static inline int CleanupAndReturn(cJSON *root, int ret)
{
    cJSON_Delete(root);
    return ret;
}

// Helper: parse a required uint64 field
// Uses cJSON_GetNumberValue() for better precision; falls back to string parsing
// for values that may exceed double's 53-bit mantissa precision.
static int ParseUint64Field(cJSON *root, const char *key, uint64_t &out)
{
    cJSON *item = cJSON_GetObjectItem(root, key);
    if (!cJSON_IsNumber(item)) {
        std::cerr << "Error: Config field '" << key << "' missing or not a number" << std::endl;
        SANDBOX_LOGE("Config field '%{public}s' missing or not a number (expected uint64)", key);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    double d = cJSON_GetNumberValue(item);
    // If the value fits safely in double's 53-bit mantissa, use direct cast
    if (d >= 0 && d <= DOUBLE_SAFE_MAX) {
        out = static_cast<uint64_t>(d);
    } else {
        // For values exceeding 2^53, parse from the raw JSON string to avoid precision loss
        out = static_cast<uint64_t>(item->valuedouble);
    }
    return SANDBOX_SUCCESS;
}

// Helper: parse a required uint32 field
// Uses valuedouble and range check to avoid cJSON valueint truncation for
// values exceeding INT_MAX.
static int ParseUint32Field(cJSON *root, const char *key, uint32_t &out)
{
    cJSON *item = cJSON_GetObjectItem(root, key);
    if (!cJSON_IsNumber(item)) {
        std::cerr << "Error: Config field '" << key << "' missing or not a number" << std::endl;
        SANDBOX_LOGE("Config field '%{public}s' missing or not a number (expected uint32)", key);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    double d = cJSON_GetNumberValue(item);
    if (d < 0 || d > UINT32_MAX_VALUE) {
        std::cerr << "Error: Config field '" << key << "' value out of range for uint32: " << d << std::endl;
        SANDBOX_LOGE("Config field '%{public}s' value out of range for uint32: %{public}f", key, d);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    out = static_cast<uint32_t>(d);
    return SANDBOX_SUCCESS;
}

// Helper: parse a required string field with maximum length check
static int ParseStringFieldWithMaxLen(cJSON *root, const char *key,
    std::string &out, size_t maxLen)
{
    cJSON *item = cJSON_GetObjectItem(root, key);
    if (!cJSON_IsString(item) || item->valuestring == nullptr) {
        std::cerr << "Error: Config field '" << key << "' missing or not a string" << std::endl;
        SANDBOX_LOGE("Config field '%{public}s' missing or not a string", key);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    std::string val = item->valuestring;
    if (val.length() > maxLen) {
        std::cerr << "Error: Config field '" << key << "' exceeds max length (" <<
                  maxLen << ")" << std::endl;
        SANDBOX_LOGE("Config field '%{public}s' exceeds max length (%{public}zu)",
            key, maxLen);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    out = val;
    return SANDBOX_SUCCESS;
}

// Helper: parse optional hex name field (max 64 chars)
static int ParseNameField(cJSON *root, std::string &out)
{
    cJSON *item = cJSON_GetObjectItem(root, "name");
    if (item == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsString(item) || item->valuestring == nullptr) {
        std::cerr << "Error: Config field 'name' must be a string" << std::endl;
        SANDBOX_LOGE("Config field 'name' must be a string");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    std::string nameVal = item->valuestring;
    if (nameVal.length() > MAX_NAME_LENGTH) {
        std::cerr << "Error: Config field 'name' exceeds max length (" << MAX_NAME_LENGTH << ")" << std::endl;
        SANDBOX_LOGE("Config field 'name' exceeds max length (%{public}zu)", MAX_NAME_LENGTH);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    for (char c : nameVal) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            std::cerr << "Error: Config field 'name' must be a hex string" << std::endl;
            SANDBOX_LOGE("Config field 'name' must be a hex string");
            return SANDBOX_ERR_CONFIG_INVALID;
        }
    }
    out = nameVal;
    return SANDBOX_SUCCESS;
}

// Helper: parse optional nsFlags string array
static int ParseNsFlagsField(cJSON *root, std::vector<std::string> &out)
{
    out.clear();
    cJSON *item = cJSON_GetObjectItem(root, "nsFlags");
    if (item == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsArray(item)) {
        std::cerr << "Error: Config field 'nsFlags' type mismatch: expected array" << std::endl;
        SANDBOX_LOGE("Config field 'nsFlags' type mismatch: expected array");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    int size = cJSON_GetArraySize(item);
    if (static_cast<size_t>(size) > MAX_NS_FLAGS_COUNT) {
        std::cerr << "Error: nsFlags array size (" << size << ") exceeds max (" <<
                  MAX_NS_FLAGS_COUNT << ")" << std::endl;
        SANDBOX_LOGE("nsFlags array size (%{public}d) exceeds max (%{public}zu)",
            size, MAX_NS_FLAGS_COUNT);
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    for (int i = 0; i < size; i++) {
        cJSON *flagItem = cJSON_GetArrayItem(item, i);
        if (!cJSON_IsString(flagItem) || flagItem->valuestring == nullptr) {
            std::cerr << "Error: nsFlags[" << i << "] should be string" << std::endl;
            SANDBOX_LOGE("nsFlags[%{public}d] should be string", i);
            return SANDBOX_ERR_CONFIG_INVALID;
        }
        std::string flagVal = flagItem->valuestring;
        if (flagVal.length() > MAX_NS_FLAG_STRING_LENGTH) {
            std::cerr << "Error: nsFlags[" << i << "] exceeds max length (" <<
                      MAX_NS_FLAG_STRING_LENGTH << ")" << std::endl;
            SANDBOX_LOGE("nsFlags[%{public}d] exceeds max length (%{public}zu)",
                i, MAX_NS_FLAG_STRING_LENGTH);
            return SANDBOX_ERR_CONFIG_INVALID;
        }
        out.push_back(flagVal);
    }
    return SANDBOX_SUCCESS;
}

int CmdParser::ParseConfig(const std::string &jsonStr, SandboxConfig &config)
{
    config = SandboxConfig();

    cJSON *root = cJSON_Parse(jsonStr.c_str());
    if (root == nullptr) {
        const char *p = cJSON_GetErrorPtr();
        std::cerr << "Error: Failed to parse config JSON: " <<
                  (p != nullptr ? p : "unknown") << std::endl;
        SANDBOX_LOGE("Failed to parse config JSON: %{public}s",
            p != nullptr ? p : "unknown");
        return SANDBOX_ERR_CONFIG_INVALID;
    }

    int ret = ParseUint64Field(root, "callerTokenId", config.callerTokenId);
    if (ret != SANDBOX_SUCCESS) {
        return CleanupAndReturn(root, ret);
    }
    ret = ParseUint32Field(root, "callerPid", config.callerPid);
    if (ret != SANDBOX_SUCCESS) {
        return CleanupAndReturn(root, ret);
    }
    ret = ParseUint32Field(root, "uid", config.uid);
    if (ret != SANDBOX_SUCCESS) {
        return CleanupAndReturn(root, ret);
    }
    ret = ParseUint32Field(root, "gid", config.gid);
    if (ret != SANDBOX_SUCCESS) {
        return CleanupAndReturn(root, ret);
    }
    ret = ParseStringFieldWithMaxLen(root, "challenge", config.challenge, MAX_CHALLENGE_LENGTH);
    if (ret != SANDBOX_SUCCESS) {
        return CleanupAndReturn(root, ret);
    }
    ret = ParseStringFieldWithMaxLen(root, "appid", config.appid, MAX_APPID_LENGTH);
    if (ret != SANDBOX_SUCCESS) {
        return CleanupAndReturn(root, ret);
    }
    ret = ParseStringFieldWithMaxLen(root, "bundleName", config.bundleName, MAX_BUNDLE_NAME_LENGTH);
    if (ret != SANDBOX_SUCCESS) {
        return CleanupAndReturn(root, ret);
    }
    ret = ParseStringFieldWithMaxLen(root, "cliName", config.cliName, MAX_CLI_NAME_LENGTH);
    if (ret != SANDBOX_SUCCESS) {
        return CleanupAndReturn(root, ret);
    }
    ret = ParseStringFieldWithMaxLen(root, "subCliName", config.subCliName, MAX_SUB_CLI_NAME_LENGTH);
    if (ret != SANDBOX_SUCCESS) {
        return CleanupAndReturn(root, ret);
    }
    ret = ParseNameField(root, config.name);
    if (ret != SANDBOX_SUCCESS) {
        return CleanupAndReturn(root, ret);
    }
    ret = ParseNsFlagsField(root, config.nsFlags);
    if (ret != SANDBOX_SUCCESS) {
        return CleanupAndReturn(root, ret);
    }

    cJSON_Delete(root);
    return SANDBOX_SUCCESS;
}

CmdInfo CmdParser::ParseCommand(const std::string &cmdline)
{
    CmdInfo info;
    info.raw = cmdline;

    if (cmdline.length() > MAX_CMD_LINE_LENGTH) {
        std::cerr << "Error: Command line exceeds max length (" <<
                  MAX_CMD_LINE_LENGTH << ")" << std::endl;
        SANDBOX_LOGE("Command line exceeds max length (%{public}zu)", MAX_CMD_LINE_LENGTH);
        return info;
    }

    std::string trimmed = Trim(cmdline);
    if (trimmed.empty()) {
        return info;
    }

    if (NeedShellFallback(trimmed)) {
        SANDBOX_LOGD("CmdParser: %{public}s - falling back to sh -c", trimmed.c_str());
        info.isMultiCommand = true;
        info.argv = {"sh", "-c", trimmed};
        return info;
    }

    info.argv = Parse(trimmed);
    return info;
}

std::string CmdParser::Trim(const std::string &str)
{
    size_t first = str.find_first_not_of(" \t\n\r\f\v");
    if (first == std::string::npos) {
        return "";
    }
    size_t last = str.find_last_not_of(" \t\n\r\f\v");
    return str.substr(first, last - first + 1);
}

bool CmdParser::NeedShellFallback(const std::string &cmd)
{
    size_t pos = 0;
    bool inQuote = false;
    char quoteChar = '\0';

    while (pos < cmd.length()) {
        char c = cmd[pos];

        if (!inQuote && (c == '"' || c == '\'')) {
            inQuote = true;
            quoteChar = c;
            pos++;
            continue;
        } else if (inQuote && c == quoteChar) {
            inQuote = false;
            quoteChar = '\0';
            pos++;
            continue;
        }

        if (!inQuote) {
            char next = (pos + 1 < cmd.length()) ? cmd[pos + 1] : '\0';
            if (c == '&' && next == '&') {
                return true;
            }
            if (c == '|' && next == '|') {
                return true;
            }
            if (c == ';') {
                return true;
            }
            if (c == '|') {
                return true;
            }
            if (c == '>' || c == '<') {
                return true;
            }
            if (c == '$') {
                return true;
            }
            if (c == '*' || c == '?') {
                return true;
            }
            if (c == '`') {
                return true;
            }
            if (c == '#') {
                return true;
            }
        }

        pos++;
    }
    return false;
}

std::vector<std::string> CmdParser::Parse(const std::string &commandLine)
{
    std::vector<std::string> args;
    std::string current;
    char quoteChar = '\0';
    bool inQuote = false;

    for (size_t i = 0; i < commandLine.length(); i++) {
        char c = commandLine[i];

        if (!inQuote && (c == '"' || c == '\'')) {
            inQuote = true;
            quoteChar = c;
            current += c;
        } else if (inQuote && c == quoteChar) {
            inQuote = false;
            current += c;
            if (!current.empty()) {
                args.push_back(current);
                current.clear();
            }
        } else if (!inQuote && (c == ' ' || c == '\t')) {
            if (!current.empty()) {
                args.push_back(current);
                current.clear();
            }
        } else {
            current += c;
        }
    }

    if (!current.empty()) {
        args.push_back(current);
    }

    SANDBOX_LOGD("CmdParser: %{public}s - parsed to %{public}zu args",
        commandLine.c_str(), args.size());
    return args;
}

int CmdParser::ConvertNsFlags(const std::vector<std::string> &nsFlags)
{
    // CLONE_NEWNS | CLONE_NEWNET (mount namespace) is always enabled for sandbox isolation
    int flags = CLONE_NEWNS | CLONE_NEWNET;

    for (const auto &flag : nsFlags) {
        if (flag == "mnt") {
            flags |= CLONE_NEWNS;
        } else if (flag == "net") {
            flags |= CLONE_NEWNET;
        } else if (flag == "uts") {
            flags |= CLONE_NEWUTS;
        } else if (flag == "ipc") {
            flags |= CLONE_NEWIPC;
        } else if (flag == "pid") {
            flags |= CLONE_NEWPID;
        } else if (flag == "user") {
            flags |= CLONE_NEWUSER;
        }
    }

    return flags;
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
