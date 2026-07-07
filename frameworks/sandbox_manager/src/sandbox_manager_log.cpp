/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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


#include <iostream>
#include <sstream>
#include <vector>
#include <cstring>
#include "sandbox_manager_log.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

#define MASK_INFO  "***"
const std::string CURRENT_DIR = ".";
const std::string PARENT_DIR = "..";
const std::string EMPTY_PATH = "empty path";
const std::string NULL_PATH = "null path";
constexpr size_t MAX_SANITIZE_KEEP = 6;

void SandboxManagerLog::SanitizeName(std::string &str, size_t offset, size_t length)
{
    size_t maskLength = (length >= MAX_SANITIZE_KEEP * 2)
                            ? (length - MAX_SANITIZE_KEEP)
                            : ((length + 1) / 2);
    size_t keepLength = length - maskLength;
    size_t maskStart = offset + (keepLength + 1) / 2;

    std::fill(str.begin() + maskStart,
              str.begin() + maskStart + maskLength, '*');
}

std::string SandboxManagerLog::MaskRealPath(const std::string &path)
{
    std::string result = path;
    size_t len = result.size();
    size_t nameStart = 0;

    for (size_t pos = 0; pos < len; pos++) {
        if (result[pos] != '/') {
            continue;
        }

        if (pos > nameStart) {
            SanitizeName(result, nameStart, pos - nameStart);
        }

        nameStart = pos + 1;
    }

    if (len > nameStart) {
        SanitizeName(result, nameStart, len - nameStart);
    }

    return result;
}

} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
