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

#ifndef POLICY_INFO_MANAGER_INTERFACE_H
#define POLICY_INFO_MANAGER_INTERFACE_H

#include <cstdint>
#include <string>
#include <vector>
#include "policy_info.h"
#include "policy_vec_raw_data.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

class PolicyInfoManager;

/**
 * @brief Transparent proxy above PolicyInfoManager with bypass sysevent monitoring.
 *
 * Architecture:
 *   SandboxManagerService -> PolicyInfoManagerInterface (validate + report)
 *                                     |
 *                                     v
 *                          PolicyInfoManager::Xxx()  (unchanged)
 *
 * Validation failures are reported via HiSysEvent but do NOT intercept the
 * request — execution always falls through to PolicyInfoManager.
 */
class PolicyInfoManagerInterface {
public:
    static PolicyInfoManagerInterface &GetInstance();

    int32_t SetPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy, uint64_t policyFlag,
        std::vector<uint32_t> &result, const SetInfo &setInfo);
    int32_t SetPolicy(uint32_t tokenId, const PolicyVecRawData &policyRawData, uint64_t policyFlag,
        std::vector<uint32_t> &result, const SetInfo &setInfo);
    int32_t SetDenyPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
        std::vector<uint32_t> &result, int32_t userId);
    int32_t SetDenyPolicy(uint32_t tokenId, const PolicyVecRawData &policyRawData,
        std::vector<uint32_t> &result, int32_t userId);
    int32_t UnSetPolicy(uint32_t tokenId, const PolicyInfo &policy);
    int32_t UnSetPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policies,
        std::vector<uint32_t> &result);
    int32_t UnSetDenyPolicy(uint32_t tokenId, const PolicyInfo &policy);
    int32_t CheckPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
        std::vector<bool> &result);
    int32_t CheckPolicy(uint32_t tokenId, const PolicyVecRawData &policyRawData,
        std::vector<bool> &result);
    int32_t AddPolicy(const uint32_t tokenId, const std::vector<PolicyInfo> &policy,
        std::vector<uint32_t> &result, const uint32_t flag = 0);
    int32_t AddPolicy(const uint32_t tokenId, const PolicyVecRawData &policyRawData,
        std::vector<uint32_t> &result, const uint32_t flag = 0);
    int32_t RemovePolicy(const uint32_t tokenId, const std::vector<PolicyInfo> &policy,
        std::vector<uint32_t> &result);
    int32_t RemovePolicy(const uint32_t tokenId, const PolicyVecRawData &policyRawData,
        std::vector<uint32_t> &result);
    int32_t MatchPolicy(const uint32_t tokenId, const std::vector<PolicyInfo> &policy,
        std::vector<uint32_t> &result);
    int32_t MatchPolicy(const uint32_t tokenId, const PolicyVecRawData &policyRawData,
        std::vector<uint32_t> &result);
    int32_t StartAccessingPolicy(const uint32_t tokenId, const std::vector<PolicyInfo> &policy,
        std::vector<uint32_t> &results, int32_t userId, uint64_t timestamp = 0);
    int32_t StartAccessingPolicy(const uint32_t tokenId, const PolicyVecRawData &policyRawData,
        std::vector<uint32_t> &results, int32_t userId, uint64_t timestamp = 0);
    int32_t StopAccessingPolicy(const uint32_t tokenId, const std::vector<PolicyInfo> &policy,
        std::vector<uint32_t> &results);
    int32_t StopAccessingPolicy(const uint32_t tokenId, const PolicyVecRawData &policyRawData,
        std::vector<uint32_t> &results);
    int32_t CleanPolicyByUserId(uint32_t userId, const std::vector<std::string> &filePaths);
    int32_t StartAccessingByTokenId(const uint32_t tokenId, int32_t userId, uint64_t timestamp = 0);
    int32_t UnSetAllPolicyByToken(const uint32_t tokenId, uint64_t timestamp = 0);
    int32_t GetPersistPolicy(const uint32_t tokenId, PolicyVecRawData &policyRawData);
    bool RemoveBundlePolicy(const uint32_t tokenId);
    int32_t CleanPolicyByPackageChanged(const std::string &bundleName, int32_t userID);
    int32_t GetSharedDirectoryInfo(std::vector<SharedDirectoryInfo> &result, int32_t userId);
    int32_t GrantSharedDirectoryPermission(const uint32_t tokenId, int32_t userId);
    int32_t RevokeSharedDirectoryPermission(const uint32_t tokenId, int32_t userId);

private:
    PolicyInfoManagerInterface() = default;
    ~PolicyInfoManagerInterface() = default;

    void ReportValidationFailure(const std::string &operation, uint32_t tokenId,
        int32_t result, const std::string &path, uint64_t mode);

    uint32_t CalculateBatchSize(uint32_t policyCount, uint32_t batchSize);

    /**
     * @brief Template helper for batch processing with PolicyVecRawData
     * @param policyRawData raw policy data to process in batches
     * @param result output vector for aggregated results
     * @param processFunc callable that processes a batch (calls vector-based overload)
     * @param batchSize batch size for processing
     * @param defaultValue default value for result initialization
     * @return SANDBOX_MANAGER_OK on success, error code on failure
     */
    template<typename Func, typename ResultType>
    int32_t ProcessPolicyBatch(
        const PolicyVecRawData &policyRawData,
        std::vector<ResultType> &result,
        Func&& processFunc,
        uint32_t batchSize,
        ResultType defaultValue = ResultType());
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // POLICY_INFO_MANAGER_INTERFACE_H
