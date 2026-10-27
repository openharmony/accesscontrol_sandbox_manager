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

#ifndef CLAW_SANDBOX_SANDBOX_GLOB_PATTERN_H
#define CLAW_SANDBOX_SANDBOX_GLOB_PATTERN_H

#include <string>

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

/**
 * @brief The two strings a file path pattern turns into.
 *
 * prefix is the fd path before '**'. suffix is the SUFFIX string after it:
 * empty, "/<tail>" for a literal tail, or "<tail>" for the star-led form.
 */
struct FilePattern {
    std::string prefix;
    std::string suffix;
};

/**
 * @brief Whether an entry claims to be a wildcard pattern.
 *
 * Any '*' marks it as one; a lone '*' is then refused by ParseFilePattern
 * rather than treated as a literal path.
 */
bool IsWildcardPattern(const std::string &path);

/**
 * @brief Parse the wildcard pattern grammar into an fd path plus a SUFFIX.
 *
 * Every check runs before out is touched. On failure the function returns
 * SANDBOX_ERR_CONFIG_INVALID and why describes the violated rule.
 */
int ParseFilePattern(const std::string &pattern, FilePattern &out, std::string &why);

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS

#endif // CLAW_SANDBOX_SANDBOX_GLOB_PATTERN_H
