/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
const uint32_t POLICY_PATH_LIMIT = 256;

int32_t SandboxManagerKit::PersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "called");
    size_t policySize = policy.size();
    if (policySize == 0 || policySize > POLICY_VECTOR_SIZE_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "PolicySize = %{public}u", static_cast<uint32_t>(policySize));
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
        SANDBOXMANAGER_LOG_ERROR(LABEL, "PolicySize = %{public}u", static_cast<uint32_t>(policySize));
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    result.clear();
    return SandboxManagerClient::GetInstance().UnPersistPolicy(policy, result);
}

int32_t SandboxManagerKit::PersistPolicy(
    uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "called");
    size_t policySize = policy.size();
    if ((policySize == 0) || (policySize > POLICY_VECTOR_SIZE_LIMIT) || (tokenId == 0)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "PolicySize = %{public}u, tokenId = %{public}d.",
            static_cast<uint32_t>(policySize), tokenId);
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    result.clear();
    return SandboxManagerClient::GetInstance().PersistPolicyByTokenId(tokenId, policy, result);
}

int32_t SandboxManagerKit::UnPersistPolicy(
    uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "called");
    size_t policySize = policy.size();
    if ((policySize == 0) || (policySize > POLICY_VECTOR_SIZE_LIMIT) || (tokenId == 0)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "PolicySize = %{public}u, tokenId = %{public}d.",
            static_cast<uint32_t>(policySize), tokenId);
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    result.clear();
    return SandboxManagerClient::GetInstance().UnPersistPolicyByTokenId(tokenId, policy, result);
}

int32_t SandboxManagerKit::SetPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                     uint64_t policyFlag, std::vector<uint32_t> &result)
{
    size_t policySize = policy.size();
    if (policySize == 0 || policySize > POLICY_VECTOR_SIZE_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check policy size failed, size = %{public}zu.", policySize);
        return INVALID_PARAMTER;
    }
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check tokenId failed.");
        return INVALID_PARAMTER;
    }
    if ((policyFlag != 0) && (policyFlag != 1)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check policyFlag failed, policyFlag = %{public}" PRIu64 ".", policyFlag);
        return INVALID_PARAMTER;
    }
    return SandboxManagerClient::GetInstance().SetPolicy(tokenId, policy, policyFlag, result);
}

int32_t SandboxManagerKit::UnSetPolicy(uint32_t tokenId, const PolicyInfo &policy)
{
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check tokenId failed.");
        return INVALID_PARAMTER;
    }
    uint32_t length = policy.path.length();
    if (length == 0 || length > POLICY_PATH_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Policy path size check failed, path=%{public}s", policy.path.c_str());
        return INVALID_PARAMTER;
    }
    return SandboxManagerClient::GetInstance().UnSetPolicy(tokenId, policy);
}

int32_t SandboxManagerKit::SetPolicyAsync(uint32_t tokenId, const std::vector<PolicyInfo> &policy, uint64_t policyFlag)
{
    size_t policySize = policy.size();
    if (policySize == 0 || policySize > POLICY_VECTOR_SIZE_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check policy size failed, size = %{public}zu.", policySize);
        return INVALID_PARAMTER;
    }
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check tokenId failed.");
        return INVALID_PARAMTER;
    }
    if ((policyFlag != 0) && (policyFlag != 1)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check policyFlag failed, policyFlag = %{public}" PRIu64 ".", policyFlag);
        return INVALID_PARAMTER;
    }
    return SandboxManagerClient::GetInstance().SetPolicyAsync(tokenId, policy, policyFlag);
}

int32_t SandboxManagerKit::UnSetPolicyAsync(uint32_t tokenId, const PolicyInfo &policy)
{
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check tokenId failed.");
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    return SandboxManagerClient::GetInstance().UnSetPolicyAsync(tokenId, policy);
}

int32_t SandboxManagerKit::CheckPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                       std::vector<bool> &result)
{
    size_t policySize = policy.size();
    if (policySize == 0 || policySize > POLICY_VECTOR_SIZE_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check policy size failed, size = %{public}zu.", policySize);
        return INVALID_PARAMTER;
    }
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check tokenId failed.");
        return INVALID_PARAMTER;
    }

    return SandboxManagerClient::GetInstance().CheckPolicy(tokenId, policy, result);
}

int32_t SandboxManagerKit::StartAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "called");
    size_t policySize = policy.size();
    if (policySize == 0 || policySize > POLICY_VECTOR_SIZE_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "PolicySize = %{public}u", static_cast<uint32_t>(policySize));
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
        SANDBOXMANAGER_LOG_ERROR(LABEL, "PolicySize = %{public}u", static_cast<uint32_t>(policySize));
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    result.clear();
    return SandboxManagerClient::GetInstance().StopAccessingPolicy(policy, result);
}

int32_t SandboxManagerKit::CheckPersistPolicy(
    uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "called");
    size_t policySize = policy.size();
    if (policySize == 0 || policySize > POLICY_VECTOR_SIZE_LIMIT || tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "PolicySize = %{public}u", static_cast<uint32_t>(policySize));
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    result.clear();
    return SandboxManagerClient::GetInstance().CheckPersistPolicy(tokenId, policy, result);
}

int32_t SandboxManagerKit::StartAccessingByTokenId(uint32_t tokenId)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "Input tokenId = %{public}d.", tokenId);
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Invalid input token.");
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    return SandboxManagerClient::GetInstance().StartAccessingByTokenId(tokenId);
}

int32_t SandboxManagerKit::UnSetAllPolicyByToken(uint32_t tokenId)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "Input tokenId = %{public}d.", tokenId);
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Invalid input token.");
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    return SandboxManagerClient::GetInstance().UnSetAllPolicyByToken(tokenId);
}
} // SandboxManager
} // AccessControl
} // OHOS