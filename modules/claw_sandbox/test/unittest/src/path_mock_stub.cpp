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

/*
 * path_mock_stub.cpp
 *
 * Mock implementation of realpath() for unit testing, following the same
 * approach as selinux_mock_stub.cpp: the test target compiles every source with
 * -Drealpath=WrapRealpath, so calls made from production code land here while
 * the production sources themselves stay untouched.
 *
 * The undef below has to come before any include, because the -D behaves like a
 * define at the top of the translation unit and this file needs to reach the
 * real realpath to forward to it.
 */
#undef realpath

#include <stdlib.h>

#include <string>

#include "sandbox_mock_state.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {
PathMockState g_pathMockState;
}  // namespace SANDBOX
}  // namespace AccessControl
}  // namespace OHOS

using namespace OHOS::AccessControl::SANDBOX;

extern "C" {

char *WrapRealpath(const char *path, char *resolved)
{
    if (!g_pathMockState.mockEnabled || path == nullptr ||
        g_pathMockState.redirectFrom.empty() || g_pathMockState.redirectTo.empty()) {
        return realpath(path, resolved);
    }

    const std::string &from = g_pathMockState.redirectFrom;
    const std::string request(path);

    /*
     * The prefix has to end on a component boundary, the same rule IsPathUnder
     * applies. Without it "/data/storage/el1/basement" would be redirected too
     * and the test would prove the opposite of what it claims.
     */
    if (request.compare(0, from.size(), from) != 0 ||
        (request.size() > from.size() && request[from.size()] != '/')) {
        return realpath(path, resolved);
    }

    const std::string rewritten = g_pathMockState.redirectTo + request.substr(from.size());
    return realpath(rewritten.c_str(), resolved);
}

}  // extern "C"
