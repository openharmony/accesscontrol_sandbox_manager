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
const uint32_t POLICY_PATH_LIMIT = 4095;

int32_t SandboxManagerKit::CleanPersistPolicyByPath(const std::vector<std::string> &filePathList)
{
    size_t filePathSize = filePathList.size();
    if (filePathSize == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "FilePathSize = %{public}zu", filePathSize);
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    return SandboxManagerClient::GetInstance().CleanPersistPolicyByPath(filePathList);
}

int32_t SandboxManagerKit::PersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "Called");
    size_t policySize = policy.size();
    if (policySize == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "PolicySize = %{public}u", static_cast<uint32_t>(policySize));
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    result.clear();
    return SandboxManagerClient::GetInstance().PersistPolicy(policy, result);
}

int32_t SandboxManagerKit::UnPersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "Called");
    size_t policySize = policy.size();
    if (policySize == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "PolicySize = %{public}u", static_cast<uint32_t>(policySize));
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    result.clear();
    return SandboxManagerClient::GetInstance().UnPersistPolicy(policy, result);
}

int32_t SandboxManagerKit::PersistPolicy(
    uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "Called");
    size_t policySize = policy.size();
    if ((policySize == 0) || (tokenId == 0)) {
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
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "Called");
    size_t policySize = policy.size();
    if ((policySize == 0) || (tokenId == 0)) {
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
    return SetPolicy(tokenId, policy, policyFlag, result, 0);
}

int32_t SandboxManagerKit::SetPolicyByBundleName(const std::string &bundleName, int32_t appCloneIndex,
    const std::vector<PolicyInfo> &policy, uint64_t policyFlag, std::vector<uint32_t> &result)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "set policy by bundle name.");

    size_t policySize = policy.size();
    if (policySize == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check policy size failed, size = %{public}zu.", policySize);
        return INVALID_PARAMTER;
    }

    if ((policyFlag != 0) && (policyFlag != 1)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check policyFlag failed, policyFlag = %{public}" PRIu64 ".", policyFlag);
        return INVALID_PARAMTER;
    }
    return SandboxManagerClient::GetInstance().SetPolicyByBundleName(bundleName,
        appCloneIndex, policy, policyFlag, result);
}

int32_t SandboxManagerKit::SetPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                     uint64_t policyFlag, std::vector<uint32_t> &result, uint64_t timestamp)
{
    size_t policySize = policy.size();
    if (policySize == 0) {
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
    return SandboxManagerClient::GetInstance().SetPolicy(tokenId, policy, policyFlag, result, timestamp);
}

int32_t SandboxManagerKit::UnSetPolicy(uint32_t tokenId, const PolicyInfo &policy)
{
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check tokenId failed.");
        return INVALID_PARAMTER;
    }
    uint32_t length = policy.path.length();
    if (length == 0 || length > POLICY_PATH_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Policy path size check failed, path=%{private}s", policy.path.c_str());
        return INVALID_PARAMTER;
    }
    return SandboxManagerClient::GetInstance().UnSetPolicy(tokenId, policy);
}

int32_t SandboxManagerKit::SetPolicyAsync(uint32_t tokenId, const std::vector<PolicyInfo> &policy, uint64_t policyFlag)
{
    return SetPolicyAsync(tokenId, policy, policyFlag, 0);
}

int32_t SandboxManagerKit::SetPolicyAsync(uint32_t tokenId, const std::vector<PolicyInfo> &policy, uint64_t policyFlag,
    uint64_t timestamp)
{
    size_t policySize = policy.size();
    if (policySize == 0) {
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
    return SandboxManagerClient::GetInstance().SetPolicyAsync(tokenId, policy, policyFlag, timestamp);
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
    if (policySize == 0) {
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
    bool useCallerToken = true;
    uint64_t timestamp = 0;
    return StartAccessingPolicy(policy, result, useCallerToken, 0, timestamp);
}

int32_t SandboxManagerKit::StartAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result,
    bool useCallerToken, uint32_t tokenId, uint64_t timestamp)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "Called");
    size_t policySize = policy.size();
    if (policySize == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "PolicySize = %{public}u", static_cast<uint32_t>(policySize));
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    result.clear();
    return SandboxManagerClient::GetInstance().StartAccessingPolicy(policy, result, useCallerToken, tokenId, timestamp);
}

int32_t SandboxManagerKit::StopAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "Called");
    size_t policySize = policy.size();
    if (policySize == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "PolicySize = %{public}u", static_cast<uint32_t>(policySize));
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    result.clear();
    return SandboxManagerClient::GetInstance().StopAccessingPolicy(policy, result);
}

int32_t SandboxManagerKit::CheckPersistPolicy(
    uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "Check persist policy target:%{public}u policySize:%{public}zu", tokenId,
        policy.size());
    size_t policySize = policy.size();
    if (policySize == 0 || tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "PolicySize = %{public}u", static_cast<uint32_t>(policySize));
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    result.clear();
    return SandboxManagerClient::GetInstance().CheckPersistPolicy(tokenId, policy, result);
}

int32_t SandboxManagerKit::StartAccessingByTokenId(uint32_t tokenId)
{
    return StartAccessingByTokenId(tokenId, 0);
}

int32_t SandboxManagerKit::StartAccessingByTokenId(uint32_t tokenId, uint64_t timestamp)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "Input tokenId = %{public}d.", tokenId);
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Invalid input token.");
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    return SandboxManagerClient::GetInstance().StartAccessingByTokenId(tokenId, timestamp);
}

int32_t SandboxManagerKit::UnSetAllPolicyByToken(uint32_t tokenId)
{
    return UnSetAllPolicyByToken(tokenId, 0);
}

int32_t SandboxManagerKit::UnSetAllPolicyByToken(uint32_t tokenId, uint64_t timestamp)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "Input tokenId = %{public}d.", tokenId);
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Invalid input token.");
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    return SandboxManagerClient::GetInstance().UnSetAllPolicyByToken(tokenId, timestamp);
}

int32_t SandboxManagerKit::CleanPolicyByUserId(uint32_t userId, const std::vector<std::string> &filePathList)
{
    if (filePathList.empty()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "filePathList empty");
        return SandboxManagerErrCode::INVALID_PARAMTER;
    }
    return SandboxManagerClient::GetInstance().CleanPolicyByUserId(userId, filePathList);
}
} // SandboxManager
} // AccessControl
} // OHOS