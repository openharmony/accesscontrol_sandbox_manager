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

#include "sandbox_mock_state.h"

#ifdef CONFIG_SHELL_SANDBOX
#include "saf_credential.h"
#include "saf_result_code.h"

#include <string>
#include <utility>
#include <vector>

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {
ToolCredentialMockState g_toolCredentialMockState;
} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS

namespace OHOS {
namespace Security {
namespace SAF {

// Link-time replacement for the real SAF client. Tests drive it through
// g_toolCredentialMockState so FetchToolCredentials sees deterministic data.
int32_t SafCredential::GetToolCredential(const ToolInfo &toolInfo,
    std::vector<ToolCredentialInfo> &credentialInfos)
{
    auto &state = OHOS::AccessControl::SANDBOX::g_toolCredentialMockState;

    credentialInfos.clear();
    if (!state.mockEnabled) {
        return SAF_SUCCESS;
    }

    if (state.getToolCredentialRet != SAF_SUCCESS) {
        return state.getToolCredentialRet;
    }

    for (const auto &credential : state.credentials) {
        ToolCredentialInfo info;
        info.envName = credential.first;
        info.credentialValue = credential.second;
        credentialInfos.emplace_back(std::move(info));
    }
    return SAF_SUCCESS;
}

} // namespace SAF
} // namespace Security
} // namespace OHOS

#endif // CONFIG_SHELL_SANDBOX
