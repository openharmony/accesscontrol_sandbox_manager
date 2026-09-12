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

#ifndef CLAW_SANDBOX_UTILS_H
#define CLAW_SANDBOX_UTILS_H

#include <cstdint>
#include <string>
#include <string_view>

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

std::string GetRealPath(const std::string &path);

// Strict decimal parse: the whole string or nothing, no sign and no leading
// space. A prefix reading would silently stand for a different number.
bool ParseDecimalU64(std::string_view text, uint64_t &value);

// Whether path resolves to dir itself or to something inside it. Both sides are
// canonicalised first, so ".." and symlinks cannot be used to step outside.
bool IsPathUnder(const std::string &path, const std::string &dir);

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
#endif // CLAW_SANDBOX_UTILS_H
