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
#include <cstdlib>

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

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

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
