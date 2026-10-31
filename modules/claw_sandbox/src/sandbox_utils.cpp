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

#include "sandbox_utils.h"

#include <charconv>
#include <climits>
#include <cstdlib>

#include "parameters.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

namespace {
constexpr const char *PC_MODE_PARAM = "persist.sceneboard.ispcmode";

// An octal escape is a backslash followed by three octal digits carrying one
// byte, e.g. "\040" for a space. Only the four characters mountinfo escapes
// need this today, but any such sequence decodes the same way.
constexpr char ESCAPE_PREFIX = '\\';
constexpr size_t OCTAL_DIGITS_PER_ESCAPE = 3;
constexpr char OCTAL_DIGIT_FIRST = '0';
constexpr char OCTAL_DIGIT_LAST = '7';
constexpr unsigned int OCTAL_BASE = 8;
constexpr unsigned int ESCAPED_BYTE_MAX = 0xFF;
} // namespace

bool IsPcMode(bool defaultValue)
{
    return OHOS::system::GetBoolParameter(PC_MODE_PARAM, defaultValue);
}

bool ParseDecimalU64(std::string_view text, uint64_t &value)
{
    const char *first = text.data();
    const char *last = first + text.size();
    // Unlike strtoull, this takes no sign, no leading space and no locale, so
    // there is nothing to screen out first - "-1" is rejected, not wrapped.
    const std::from_chars_result result = std::from_chars(first, last, value);
    return result.ec == std::errc() && result.ptr == last;
}

// Helper function to resolve the absolute path securely.
// Returns an empty string if resolution fails (e.g., file does not exist or access denied).
std::string GetRealPath(const std::string &path)
{
    if (path.empty()) {
        return "";
    }

    char resolvePath[PATH_MAX] = { 0 };
    if (realpath(path.c_str(), resolvePath) == nullptr) {
        return "";
    }

    return std::string(resolvePath);
}

bool IsCanonicalAbsolutePath(const std::string &path)
{
    if (path.empty() || path[0] != '/') {
        return false;
    }
    if (path == "/") {
        return true;
    }
    if (path.back() == '/') {
        return false;
    }

    size_t start = 1;
    while (start < path.size()) {
        size_t end = path.find('/', start);
        if (end == std::string::npos) {
            end = path.size();
        }
        if (end == start) {
            return false;
        }
        const std::string_view component(path.data() + start, end - start);
        if (component == "." || component == "..") {
            return false;
        }
        start = end + 1;
    }
    return true;
}

bool IsPathUnder(const std::string &path, const std::string &dir)
{
    std::string realPath = GetRealPath(path);
    std::string realDir = GetRealPath(dir);
    if (realPath.empty() || realDir.empty()) {
        return false;
    }
    if (realDir == "/") {
        return realPath[0] == '/';
    }
    if (realPath == realDir) {
        return true;
    }

    /*
     * The trailing '/' check is what makes this a containment test rather than a
     * string prefix test: with dir="/data", "/data/app" is inside but
     * "/data_app" is not.
     */
    return realPath.size() > realDir.size() &&
           realPath.compare(0, realDir.size(), realDir) == 0 &&
           realPath[realDir.size()] == '/';
}

std::string DecodeOctalEscapes(const std::string &raw)
{
    std::string result;
    result.reserve(raw.size());
    size_t pos = 0;
    while (pos < raw.size()) {
        if (raw[pos] != ESCAPE_PREFIX ||
            pos + OCTAL_DIGITS_PER_ESCAPE >= raw.size()) {
            result.push_back(raw[pos]);
            ++pos;
            continue;
        }
        unsigned int value = 0;
        bool octal = true;
        for (size_t j = 1; j <= OCTAL_DIGITS_PER_ESCAPE; ++j) {
            const char digit = raw[pos + j];
            if (digit < OCTAL_DIGIT_FIRST || digit > OCTAL_DIGIT_LAST) {
                octal = false;
                break;
            }
            value = value * OCTAL_BASE +
                static_cast<unsigned int>(digit - OCTAL_DIGIT_FIRST);
        }
        if (!octal || value > ESCAPED_BYTE_MAX) {
            result.push_back(raw[pos]);
            ++pos;
            continue;
        }
        result.push_back(static_cast<char>(value));
        pos += OCTAL_DIGITS_PER_ESCAPE + 1;
    }
    return result;
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
