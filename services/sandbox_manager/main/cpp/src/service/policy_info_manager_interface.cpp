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

#include "policy_info_manager_interface.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>
#include "policy_info_manager.h"
#include "sandbox_manager_const.h"
#include "sandbox_manager_dfx_helper.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"
#include "sandbox_param_validator.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxPolicyInfoManagerInterface"
};
}

PolicyInfoManagerInterface &PolicyInfoManagerInterface::GetInstance()
{
    static PolicyInfoManagerInterface instance;
    return instance;
}

void PolicyInfoManagerInterface::ReportValidationFailure(const std::string &operation, uint32_t tokenId,
    int32_t result, const std::string &path, uint64_t mode)
{
    SandboxManagerDfxHelper::WriteValidationFailure(operation, tokenId, result, path, mode);
}

// Template helper for batch processing with PolicyVecRawData
// Handles batch reading, result aggregation, and delegation to vector-based overloads
template<typename Func, typename ResultType>
int32_t PolicyInfoManagerInterface::ProcessPolicyBatch(
    const PolicyVecRawData &policyRawData,
    std::vector<ResultType> &result,
    Func&& processFunc,
    uint32_t batchSize,
    ResultType defaultValue)
{
    PolicyVecBatchReader reader(policyRawData);
    if (!reader.IsValid()) {
        LOGE_WITH_REPORT(LABEL, "PolicyVecBatchReader initialization failed");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    uint32_t policyCount = reader.GetPolicyCount();
    if (policyCount == 0) {
        LOGE_WITH_REPORT(LABEL, "Policy count is zero");
        return INVALID_PARAMTER;
    }

    uint32_t finalBatchSize = CalculateBatchSize(policyCount, batchSize);
    uint32_t globalIndex = 0;
    result.resize(policyCount, defaultValue);

    while (globalIndex < policyCount) {
        uint32_t currentBatchSize = std::min(finalBatchSize, policyCount - globalIndex);
        std::vector<PolicyInfo> batchPolicies;

        int32_t ret = reader.ReadNextBatch(currentBatchSize, batchPolicies);
        if (ret != SANDBOX_MANAGER_OK) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "ReadNextBatch failed at index %{public}u", globalIndex);
            return ret;
        }

        std::vector<ResultType> batchResult;
        ret = processFunc(batchPolicies, batchResult);
        if (ret != SANDBOX_MANAGER_OK) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Batch processing failed at index %{public}u", globalIndex);
            return ret;
        }

        for (size_t i = 0; i < batchResult.size(); ++i) {
            result[globalIndex + i] = batchResult[i];
        }

        globalIndex += currentBatchSize;
    }

    return SANDBOX_MANAGER_OK;
}

uint32_t PolicyInfoManagerInterface::CalculateBatchSize(uint32_t policyCount, uint32_t batchSize)
{
    if (batchSize == 0) {
        return 1;
    }
    if (policyCount <= batchSize) {
        return policyCount;
    }

    uint32_t dynamicBatchSize = policyCount >> MAX_BATCH_COUNT_SHIFT;
    if ((policyCount & (MAX_BATCH_COUNT - 1)) != 0) {
        ++dynamicBatchSize;
    }

    return std::max(batchSize, dynamicBatchSize);
}

// ---------------------------------------------------------------------------
// SetPolicy — validate temp policy, bypass report, delegate
// ---------------------------------------------------------------------------
int32_t PolicyInfoManagerInterface::SetPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
    uint64_t policyFlag, std::vector<uint32_t> &result, const SetInfo &setInfo)
{
    for (size_t i = 0; i < policy.size(); ++i) {
        int32_t ret = SandboxParamValidator::ValidateTempPolicy(policy[i], setInfo);
        if (ret != SANDBOX_MANAGER_OK) {
            ReportValidationFailure("SetPolicy", tokenId, ret, policy[i].path, policy[i].mode);
        }
    }
    return PolicyInfoManager::GetInstance().SetPolicy(tokenId, policy, policyFlag, result, setInfo);
}

int32_t PolicyInfoManagerInterface::SetPolicy(uint32_t tokenId, const PolicyVecRawData &policyRawData,
    uint64_t policyFlag, std::vector<uint32_t> &result, const SetInfo &setInfo)
{
    return ProcessPolicyBatch(policyRawData, result,
        [this, tokenId, policyFlag, &setInfo](const std::vector<PolicyInfo> &policies,
            std::vector<uint32_t> &batchResult) {
            return this->SetPolicy(tokenId, policies, policyFlag, batchResult, setInfo);
        }, NON_PERSIST_POLICY_BATCH_SIZE, static_cast<uint32_t>(SandboxRetType::INVALID_PATH));
}

// ---------------------------------------------------------------------------
// SetDenyPolicy — validate deny policy, bypass report, delegate
// ---------------------------------------------------------------------------
int32_t PolicyInfoManagerInterface::SetDenyPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
    std::vector<uint32_t> &result, int32_t userId)
{
    for (size_t i = 0; i < policy.size(); ++i) {
        int32_t pathRet = SandboxParamValidator::ValidateGenericPath(policy[i].path);
        if (pathRet != SANDBOX_MANAGER_OK) {
            ReportValidationFailure("SetDenyPolicy", tokenId, pathRet, policy[i].path, policy[i].mode);
        }
        int32_t modeRet = SandboxParamValidator::ValidateDenyMode(policy[i].mode);
        if (modeRet != SANDBOX_MANAGER_OK) {
            ReportValidationFailure("SetDenyPolicy", tokenId, modeRet, policy[i].path, policy[i].mode);
        }
    }
    return PolicyInfoManager::GetInstance().SetDenyPolicy(tokenId, policy, result, userId);
}

int32_t PolicyInfoManagerInterface::SetDenyPolicy(uint32_t tokenId, const PolicyVecRawData &policyRawData,
    std::vector<uint32_t> &result, int32_t userId)
{
    return ProcessPolicyBatch(policyRawData, result,
        [this, tokenId, userId](const std::vector<PolicyInfo> &policies,
            std::vector<uint32_t> &batchResult) {
            return this->SetDenyPolicy(tokenId, policies, batchResult, userId);
        }, NON_PERSIST_POLICY_BATCH_SIZE, static_cast<uint32_t>(SandboxRetType::INVALID_PATH));
}

// ---------------------------------------------------------------------------
// UnSetPolicy — validate temp mode, bypass report, delegate
// ---------------------------------------------------------------------------
int32_t PolicyInfoManagerInterface::UnSetPolicy(uint32_t tokenId, const PolicyInfo &policy)
{
    int32_t ret = SandboxParamValidator::ValidateTempMode(policy.mode);
    if (ret != SANDBOX_MANAGER_OK) {
        ReportValidationFailure("UnSetPolicy", tokenId, ret, policy.path, policy.mode);
    }
    return PolicyInfoManager::GetInstance().UnSetPolicy(tokenId, policy);
}

int32_t PolicyInfoManagerInterface::UnSetPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policies,
    std::vector<uint32_t> &result)
{
    for (size_t i = 0; i < policies.size(); ++i) {
        int32_t ret = SandboxParamValidator::ValidateTempMode(policies[i].mode);
        if (ret != SANDBOX_MANAGER_OK) {
            ReportValidationFailure("UnSetPolicyBatch", tokenId, ret, policies[i].path, policies[i].mode);
        }
    }
    return PolicyInfoManager::GetInstance().UnSetPolicy(tokenId, policies, result);
}

// ---------------------------------------------------------------------------
// UnSetDenyPolicy — validate deny mode, bypass report, delegate
// ---------------------------------------------------------------------------
int32_t PolicyInfoManagerInterface::UnSetDenyPolicy(uint32_t tokenId, const PolicyInfo &policy)
{
    int32_t ret = SandboxParamValidator::ValidateDenyMode(policy.mode);
    if (ret != SANDBOX_MANAGER_OK) {
        ReportValidationFailure("UnSetDenyPolicy", tokenId, ret, policy.path, policy.mode);
    }
    return PolicyInfoManager::GetInstance().UnSetDenyPolicy(tokenId, policy);
}

// ---------------------------------------------------------------------------
// CheckPolicy — validate path + temp mode, bypass report, delegate
// ---------------------------------------------------------------------------
int32_t PolicyInfoManagerInterface::CheckPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
    std::vector<bool> &result)
{
    for (size_t i = 0; i < policy.size(); ++i) {
        int32_t pathRet = SandboxParamValidator::ValidateGenericPath(policy[i].path);
        if (pathRet != SANDBOX_MANAGER_OK) {
            ReportValidationFailure("CheckPolicy", tokenId, pathRet, policy[i].path, policy[i].mode);
            continue;
        }
        int32_t modeRet = SandboxParamValidator::ValidateTempMode(policy[i].mode);
        if (modeRet != SANDBOX_MANAGER_OK) {
            ReportValidationFailure("CheckPolicy", tokenId, modeRet, policy[i].path, policy[i].mode);
        }
    }
    return PolicyInfoManager::GetInstance().CheckPolicy(tokenId, policy, result);
}

int32_t PolicyInfoManagerInterface::CheckPolicy(uint32_t tokenId, const PolicyVecRawData &policyRawData,
    std::vector<bool> &result)
{
    return ProcessPolicyBatch(policyRawData, result,
        [this, tokenId](const std::vector<PolicyInfo> &policies,
            std::vector<bool> &batchResult) {
            return this->CheckPolicy(tokenId, policies, batchResult);
        }, NON_PERSIST_POLICY_BATCH_SIZE, false);
}

// ---------------------------------------------------------------------------
// AddPolicy — validate persist policy, bypass report, delegate
// ---------------------------------------------------------------------------
int32_t PolicyInfoManagerInterface::AddPolicy(const uint32_t tokenId, const std::vector<PolicyInfo> &policy,
    std::vector<uint32_t> &result, const uint32_t flag)
{
    for (size_t i = 0; i < policy.size(); ++i) {
        int32_t pathRet = SandboxParamValidator::ValidateGenericPath(policy[i].path);
        if (pathRet != SANDBOX_MANAGER_OK) {
            ReportValidationFailure("AddPolicy", tokenId, pathRet, policy[i].path, policy[i].mode);
        }
        int32_t modeRet = SandboxParamValidator::ValidateTempMode(policy[i].mode);
        if (modeRet != SANDBOX_MANAGER_OK) {
            ReportValidationFailure("AddPolicy", tokenId, modeRet, policy[i].path, policy[i].mode);
        }
    }
    return PolicyInfoManager::GetInstance().AddPolicy(tokenId, policy, result, flag);
}

int32_t PolicyInfoManagerInterface::AddPolicy(const uint32_t tokenId, const PolicyVecRawData &policyRawData,
    std::vector<uint32_t> &result, const uint32_t flag)
{
    return ProcessPolicyBatch(policyRawData, result,
        [this, tokenId, flag](const std::vector<PolicyInfo> &policies,
            std::vector<uint32_t> &batchResult) {
            return this->AddPolicy(tokenId, policies, batchResult, flag);
        }, PERSIST_POLICY_BATCH_SIZE, static_cast<uint32_t>(SandboxRetType::INVALID_PATH));
}

// ---------------------------------------------------------------------------
// RemovePolicy — validate persist policy, bypass report, delegate
// ---------------------------------------------------------------------------
int32_t PolicyInfoManagerInterface::RemovePolicy(const uint32_t tokenId,
    const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    for (size_t i = 0; i < policy.size(); ++i) {
        int32_t pathRet = SandboxParamValidator::ValidateGenericPath(policy[i].path);
        if (pathRet != SANDBOX_MANAGER_OK) {
            ReportValidationFailure("RemovePolicy", tokenId, pathRet, policy[i].path, policy[i].mode);
        }
        int32_t modeRet = SandboxParamValidator::ValidateTempMode(policy[i].mode);
        if (modeRet != SANDBOX_MANAGER_OK) {
            ReportValidationFailure("RemovePolicy", tokenId, modeRet, policy[i].path, policy[i].mode);
        }
    }
    return PolicyInfoManager::GetInstance().RemovePolicy(tokenId, policy, result);
}

int32_t PolicyInfoManagerInterface::RemovePolicy(const uint32_t tokenId,
    const PolicyVecRawData &policyRawData, std::vector<uint32_t> &result)
{
    return ProcessPolicyBatch(policyRawData, result,
        [this, tokenId](const std::vector<PolicyInfo> &policies,
            std::vector<uint32_t> &batchResult) {
            return this->RemovePolicy(tokenId, policies, batchResult);
        }, PERSIST_POLICY_BATCH_SIZE, static_cast<uint32_t>(SandboxRetType::INVALID_PATH));
}

// ---------------------------------------------------------------------------
// MatchPolicy — validate path + temp mode, bypass report, delegate
// ---------------------------------------------------------------------------
int32_t PolicyInfoManagerInterface::MatchPolicy(const uint32_t tokenId,
    const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    for (size_t i = 0; i < policy.size(); ++i) {
        int32_t pathRet = SandboxParamValidator::ValidateGenericPath(policy[i].path);
        if (pathRet != SANDBOX_MANAGER_OK) {
            ReportValidationFailure("MatchPolicy", tokenId, pathRet, policy[i].path, policy[i].mode);
            continue;
        }
        int32_t modeRet = SandboxParamValidator::ValidateTempMode(policy[i].mode);
        if (modeRet != SANDBOX_MANAGER_OK) {
            ReportValidationFailure("MatchPolicy", tokenId, modeRet, policy[i].path, policy[i].mode);
        }
    }
    return PolicyInfoManager::GetInstance().MatchPolicy(tokenId, policy, result);
}

int32_t PolicyInfoManagerInterface::MatchPolicy(const uint32_t tokenId,
    const PolicyVecRawData &policyRawData, std::vector<uint32_t> &result)
{
    return ProcessPolicyBatch(policyRawData, result,
        [this, tokenId](const std::vector<PolicyInfo> &policies,
            std::vector<uint32_t> &batchResult) {
            return this->MatchPolicy(tokenId, policies, batchResult);
        }, PERSIST_POLICY_BATCH_SIZE, static_cast<uint32_t>(SandboxRetType::INVALID_PATH));
}

// ---------------------------------------------------------------------------
// StartAccessingPolicy — validate activation policy, bypass report, delegate
// ---------------------------------------------------------------------------
int32_t PolicyInfoManagerInterface::StartAccessingPolicy(const uint32_t tokenId,
    const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &results, int32_t userId,
    uint64_t timestamp)
{
    for (size_t i = 0; i < policy.size(); ++i) {
        bool isMediaPath = false;
        int32_t ret = SandboxParamValidator::ValidateActivationPolicy(policy[i], isMediaPath);
        if (ret != SANDBOX_MANAGER_OK) {
            ReportValidationFailure("StartAccessingPolicy", tokenId, ret, policy[i].path, policy[i].mode);
        }
    }
    return PolicyInfoManager::GetInstance().StartAccessingPolicy(tokenId, policy, results, userId, timestamp);
}

int32_t PolicyInfoManagerInterface::StartAccessingPolicy(const uint32_t tokenId,
    const PolicyVecRawData &policyRawData, std::vector<uint32_t> &results, int32_t userId,
    uint64_t timestamp)
{
    return ProcessPolicyBatch(policyRawData, results,
        [this, tokenId, timestamp, userId](const std::vector<PolicyInfo> &policies,
            std::vector<uint32_t> &batchResult) {
            return this->StartAccessingPolicy(tokenId, policies, batchResult, userId, timestamp);
        }, PERSIST_POLICY_BATCH_SIZE, static_cast<uint32_t>(SandboxRetType::INVALID_PATH));
}

// ---------------------------------------------------------------------------
// StopAccessingPolicy — validate activation policy, bypass report, delegate
// ---------------------------------------------------------------------------
int32_t PolicyInfoManagerInterface::StopAccessingPolicy(const uint32_t tokenId,
    const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &results)
{
    for (size_t i = 0; i < policy.size(); ++i) {
        bool isMediaPath = false;
        int32_t ret = SandboxParamValidator::ValidateActivationPolicy(policy[i], isMediaPath);
        if (ret != SANDBOX_MANAGER_OK) {
            ReportValidationFailure("StopAccessingPolicy", tokenId, ret, policy[i].path, policy[i].mode);
        }
    }
    return PolicyInfoManager::GetInstance().StopAccessingPolicy(tokenId, policy, results);
}

int32_t PolicyInfoManagerInterface::StopAccessingPolicy(const uint32_t tokenId,
    const PolicyVecRawData &policyRawData, std::vector<uint32_t> &results)
{
    return ProcessPolicyBatch(policyRawData, results,
        [this, tokenId](const std::vector<PolicyInfo> &policies,
            std::vector<uint32_t> &batchResult) {
            return this->StopAccessingPolicy(tokenId, policies, batchResult);
        }, PERSIST_POLICY_BATCH_SIZE, static_cast<uint32_t>(SandboxRetType::INVALID_PATH));
}

// ---------------------------------------------------------------------------
// CleanPolicyByUserId — validate generic path, bypass report, delegate
// ---------------------------------------------------------------------------
int32_t PolicyInfoManagerInterface::CleanPolicyByUserId(uint32_t userId,
    const std::vector<std::string> &filePaths)
{
    for (size_t i = 0; i < filePaths.size(); ++i) {
        int32_t ret = SandboxParamValidator::ValidateGenericPath(filePaths[i]);
        if (ret != SANDBOX_MANAGER_OK) {
            ReportValidationFailure("CleanPolicyByUserId", 0, ret, filePaths[i], 0);
        }
    }
    return PolicyInfoManager::GetInstance().CleanPolicyByUserId(userId, filePaths);
}

// ---------------------------------------------------------------------------
// Direct delegation methods (no validation needed)
// ---------------------------------------------------------------------------
int32_t PolicyInfoManagerInterface::StartAccessingByTokenId(const uint32_t tokenId,
    int32_t userId, uint64_t timestamp)
{
    return PolicyInfoManager::GetInstance().StartAccessingByTokenId(tokenId, userId, timestamp);
}

int32_t PolicyInfoManagerInterface::UnSetAllPolicyByToken(const uint32_t tokenId, uint64_t timestamp)
{
    return PolicyInfoManager::GetInstance().UnSetAllPolicyByToken(tokenId, timestamp);
}

int32_t PolicyInfoManagerInterface::GetPersistPolicy(const uint32_t tokenId, PolicyVecRawData &policyRawData)
{
    return PolicyInfoManager::GetInstance().GetPersistPolicy(tokenId, policyRawData);
}

bool PolicyInfoManagerInterface::RemoveBundlePolicy(const uint32_t tokenId)
{
    return PolicyInfoManager::GetInstance().RemoveBundlePolicy(tokenId);
}

int32_t PolicyInfoManagerInterface::CleanPolicyByPackageChanged(const std::string &bundleName, int32_t userID)
{
    return PolicyInfoManager::GetInstance().CleanPolicyByPackageChanged(bundleName, userID);
}

int32_t PolicyInfoManagerInterface::GetSharedDirectoryInfo(
    std::vector<SharedDirectoryInfo> &result, int32_t userId)
{
    return PolicyInfoManager::GetInstance().GetSharedDirectoryInfo(result, userId);
}

int32_t PolicyInfoManagerInterface::GrantSharedDirectoryPermission(
    const uint32_t tokenId, int32_t userId)
{
    return PolicyInfoManager::GetInstance().GrantSharedDirectoryPermission(tokenId, userId);
}

int32_t PolicyInfoManagerInterface::RevokeSharedDirectoryPermission(
    const uint32_t tokenId, int32_t userId)
{
    return PolicyInfoManager::GetInstance().RevokeSharedDirectoryPermission(tokenId, userId);
}

} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
