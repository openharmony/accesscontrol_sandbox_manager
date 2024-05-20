/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "sandbox_manager_kit.h"

#include <cinttypes>
#include <cstdint>
#include "sandbox_manager_client.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerKit"};
}
const uint64_t POLICY_VECTOR_SIZE_LIMIT = 500;

int32_t SandboxManagerKit::PersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "called");
    size_t policySize = policy.size();
    if (policySize == 0 || policySize > POLICY_VECTOR_SIZE_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "policySize = %{public}u", static_cast<uint32_t>(policySize));
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    result.clear();
    return SandboxManagerClient::GetInstance().PersistPolicy(policy, result);
}

int32_t SandboxManagerKit::UnPersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "called");
    size_t policySize = policy.size();
    if (policySize == 0 || policySize > POLICY_VECTOR_SIZE_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "policySize = %{public}u", static_cast<uint32_t>(policySize));
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    result.clear();
    return SandboxManagerClient::GetInstance().UnPersistPolicy(policy, result);
}

int32_t SandboxManagerKit::PersistPolicy(
    uint64_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "called");
    size_t policySize = policy.size();
    if ((policySize == 0) || (policySize > POLICY_VECTOR_SIZE_LIMIT) || (tokenId == 0)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "policySize = %{public}u, tokenId = %{public}" PRIu64,
            static_cast<uint32_t>(policySize), tokenId);
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    result.clear();
    return SandboxManagerClient::GetInstance().PersistPolicyByTokenId(tokenId, policy, result);
}

int32_t SandboxManagerKit::UnPersistPolicy(
    uint64_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "called");
    size_t policySize = policy.size();
    if ((policySize == 0) || (policySize > POLICY_VECTOR_SIZE_LIMIT) || (tokenId == 0)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "policySize = %{public}u, tokenId = %{public}" PRIu64,
            static_cast<uint32_t>(policySize), tokenId);
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    result.clear();
    return SandboxManagerClient::GetInstance().UnPersistPolicyByTokenId(tokenId, policy, result);
}

int32_t SandboxManagerKit::SetPolicy(uint64_t tokenId, const std::vector<PolicyInfo> &policy, uint64_t policyFlag)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "called");
    size_t policySize = policy.size();
    if ((policySize == 0) || (policySize > POLICY_VECTOR_SIZE_LIMIT) || (tokenId == 0)) {
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    return SandboxManagerClient::GetInstance().SetPolicy(tokenId, policy, policyFlag);
}

int32_t SandboxManagerKit::StartAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "called");
    size_t policySize = policy.size();
    if (policySize == 0 || policySize > POLICY_VECTOR_SIZE_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "policySize = %{public}u", static_cast<uint32_t>(policySize));
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    result.clear();
    return SandboxManagerClient::GetInstance().StartAccessingPolicy(policy, result);
}

int32_t SandboxManagerKit::StopAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "called");
    size_t policySize = policy.size();
    if (policySize == 0 || policySize > POLICY_VECTOR_SIZE_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "policySize = %{public}u", static_cast<uint32_t>(policySize));
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    result.clear();
    return SandboxManagerClient::GetInstance().StopAccessingPolicy(policy, result);
}

int32_t SandboxManagerKit::CheckPersistPolicy(
    uint64_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "called");
    size_t policySize = policy.size();
    if (policySize == 0 || policySize > POLICY_VECTOR_SIZE_LIMIT || tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "policySize = %{public}u", static_cast<uint32_t>(policySize));
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    result.clear();
    return SandboxManagerClient::GetInstance().CheckPersistPolicy(tokenId, policy, result);
}
} // SandboxManager
} // AccessControl
} // OHOS