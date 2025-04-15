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

std::string SandboxManagerLog::MaskRealPath(const char *path)
{
    if (path == nullptr) {
        return NULL_PATH;
    }

    if (strlen(path) == 0) {
        return EMPTY_PATH;
    }

    std::istringstream stream(path);
    std::string part;
    std::string retStr;

    while (std::getline(stream, part, '/')) {
        if (!part.empty()) {
            if (part == CURRENT_DIR || part == PARENT_DIR) {
                retStr.append(part);
            } else {
                retStr.push_back(part[0]);
                retStr.append(MASK_INFO);
            }
            retStr.append("/");
        } else {
            /* means find "//" */
            retStr.append("/");
        }
    }

    if (path[strlen(path) - 1] != '/') {
        retStr.pop_back();
    }

    return retStr;
}

} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
