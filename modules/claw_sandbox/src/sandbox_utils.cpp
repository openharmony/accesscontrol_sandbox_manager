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

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

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

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
