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

#include "sandbox_manager.h"
#include "sandbox_error.h"
#include "sandbox_log.h"

#ifdef CONFIG_SHELL_SANDBOX
#include <cerrno>
#include <cstdlib>
#include <cstring>

#include "saf_credential.h"
#include "saf_result_code.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

static bool IsValidCredentialEnvName(const std::string &envName)
{
    return !envName.empty() &&
           envName.find('=') == std::string::npos;
}

int SandboxManager::FetchToolCredentials()
{
    if (config_.type != "shell") {
        SANDBOX_LOGD("FetchToolCredentials: skip non-shell sandbox");
        return SANDBOX_SUCCESS;
    }

    toolCredentials_.clear();

    if (config_.subjectId.empty()) {
        SANDBOX_LOGD("FetchToolCredentials: subjectId is empty, skip credential fetch");
        return SANDBOX_SUCCESS;
    }

    OHOS::Security::SAF::ToolInfo toolInfo;
    toolInfo.agentTokenId = config_.callerTokenId & TOKEN_ID_LOWMASK;
    toolInfo.subjectId = config_.subjectId;

    std::vector<OHOS::Security::SAF::ToolCredentialInfo> credentialInfos;
    OHOS::Security::SAF::SafCredential credential;
    int32_t ret = credential.GetToolCredential(toolInfo, credentialInfos);
    if (ret != SAF_SUCCESS) {
        SANDBOX_LOGD("FetchToolCredentials: GetToolCredential failed, ret=%{public}d, "
            "continue without tool credentials", ret);
        return SANDBOX_SUCCESS;
    }

    for (const auto &info : credentialInfos) {
        if (!IsValidCredentialEnvName(info.envName)) {
            SANDBOX_LOGD("FetchToolCredentials: skip invalid env name, valueLen=%{public}zu",
                info.credentialValue.size());
            continue;
        }
        toolCredentials_.emplace_back(info.envName, info.credentialValue);
    }

    SANDBOX_LOGD("FetchToolCredentials: fetched %{public}zu credential(s)",
        toolCredentials_.size());
    return SANDBOX_SUCCESS;
}

int SandboxManager::SetToolCredentials()
{
    if (config_.type != "shell") {
        SANDBOX_LOGD("SetToolCredentials: skip non-shell sandbox");
        return SANDBOX_SUCCESS;
    }

    size_t injected = 0;
    for (const auto &credential : toolCredentials_) {
        if (!IsValidCredentialEnvName(credential.first)) {
            SANDBOX_LOGD("SetToolCredentials: skip invalid env name");
            continue;
        }
        if (setenv(credential.first.c_str(), credential.second.c_str(), 1) != 0) {
            int error = errno;
            SANDBOX_LOGD("SetToolCredentials: setenv %{public}s failed: %{public}s, "
                "continue without this credential", credential.first.c_str(), strerror(error));
            continue;
        }
        injected++;
    }

    SANDBOX_LOGD("SetToolCredentials: injected %{public}zu credential(s)", injected);
    return SANDBOX_SUCCESS;
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
#endif // CONFIG_SHELL_SANDBOX
