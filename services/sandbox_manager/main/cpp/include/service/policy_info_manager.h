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

#ifndef POLICY_INFO_MANAGER_H
#define POLICY_INFO_MANAGER_H

#include <cstdint>
#include <string>
#include <vector>
#include "mac_adapter.h"
#include "generic_values.h"
#include "policy_info.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

class PolicyInfoManager {
public:
    static PolicyInfoManager &GetInstance();
    PolicyInfoManager() = default;
    virtual ~PolicyInfoManager() = default;
    void Init();
    /**
     * @brief Clear the persistence policy
     * @param policy vector of string, file path
     * @return SANDBOX_MANAGER_OK
     */
    int32_t CleanPersistPolicyByPath(const std::vector<std::string> &filePaths);
     /**
     * @brief Clear the policys of a given userid
     * @param userId a given userid
     * @param policy vector of string, file path
     * @return SANDBOX_MANAGER_OK
     */
    int32_t CleanPolicyByUserId(uint32_t userId, const std::vector<std::string> &filePaths);
    /**
     * @brief Insert policys to database
     * @param tokenId token id of the object
     * @param policy vector of PolicyInfo, see policy_info.h
     * @param result insert result of each policy
     * @return SANDBOX_MANAGER_DB_ERR / SANDBOX_MANAGER_OK
     */
    int32_t AddPolicy(const uint32_t tokenId, const std::vector<PolicyInfo> &policy,
        std::vector<uint32_t> &result, const uint32_t flag = 0);
    /**
     * @brief Match policys of a certain tokenId
     * @param tokenId token id of the object
     * @param policy vector of PolicyInfo, see policy_info.h
     * @param result match result of each policy
     * @return SANDBOX_MANAGER_DB_ERR / SANDBOX_MANAGER_OK
     */
    int32_t MatchPolicy(const uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    /**
     * @brief The mode of the same path policy performs or operations
     * @param GenericValues vector
     * @param dbResults size
     */
    void RepeatsPathPolicyModeCal(std::vector<GenericValues> &dbResults,
        uint64_t dbResultsSize);
    /**
     * @brief Match one policy of a certain tokenId
     * @param tokenId token id of the object
     * @param policy PolicyInfo, see policy_info.h
     * @param result match result of each policy
     * @return INVALID_PARAMTER / SANDBOX_MANAGER_DB_ERR
     *     / SANDBOX_MANAGER_POLICY_NOT_MATCH / SANDBOX_MANAGER_OK
     */
    int32_t MatchSinglePolicy(const uint32_t tokenId, const PolicyInfo &policy, uint32_t &result);
    /**
     * @brief remove policys of a certain tokenId
     * @param tokenId token id of the object
     * @param policy vector of PolicyInfo, see policy_info.h
     * @param result  remove result of each policy
     * @return INVALID_PARAMTER / SANDBOX_MANAGER_DB_ERR / SANDBOX_MANAGER_OK
     *      / SANDBOX_MANAGER_DB_RETURN_EMPTY
     */
    int32_t RemovePolicy(const uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    /**
     * @brief set policies of a certain tokenId
     * @param tokenId token id of the object
     * @param policy vector of PolicyInfo, see policy_info.h
     * @param result set result of each policy
     * @param timestamp timestamp of policy
     * @return SANDBOX_MANAGER_MAC_IOCTL_ERR / SANDBOX_MANAGER_OK
     */
    int32_t SetPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy, uint64_t policyFlag,
                      std::vector<uint32_t> &result, uint64_t timestamp = 0);
    /**
     * @brief unset policies of a certain tokenId
     * @param tokenId token id of the object
     * @param policy PolicyInfo, see policy_info.h
     * @return SANDBOX_MANAGER_MAC_IOCTL_ERR / SANDBOX_MANAGER_OK
     */
    int32_t UnSetPolicy(uint32_t tokenId, const PolicyInfo &policy);
    /**
     * @brief check policies of a certain tokenId
     * @param tokenId token id of the object
     * @param policy vector of PolicyInfo, see policy_info.h
     * @param result check result of each policy
     * @return SANDBOX_MANAGER_MAC_IOCTL_ERR / SANDBOX_MANAGER_OK
     */
    int32_t CheckPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result);
    /**
     * @brief remove all policys of a certain tokenId (bundle)
     * @param tokenId token id of the object
     * @return bool
     */
    bool RemoveBundlePolicy(const uint32_t tokenId);
    /**
     * @brief activate all policys of input token that flag = 1
     * @param tokenId token id of the object
     * @param timestamp timestamp to access policy
     * @return int32_t
     */
    int32_t StartAccessingByTokenId(const uint32_t tokenId, uint64_t timestamp = 0);
    /**
     * @brief activate input persist policys
     * @param tokenId token id of the object
     * @param policy vector of PolicyInfo, see policy_info.h
     * @param result  remove result of each policy
     * @param timestamp timestamp to access policy
     * @return int32_t
     */
    int32_t StartAccessingPolicy(const uint32_t tokenId, const std::vector<PolicyInfo> &policy,
        std::vector<uint32_t> &results, uint64_t timestamp = 0);
    /**
     * @brief deactivate input persist policys
     * @param tokenId token id of the object
     * @param policy vector of PolicyInfo, see policy_info.h
     * @param result  remove result of each policy
     * @return int32_t
     */
    int32_t StopAccessingPolicy(
        const uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &results);
    /**
     * @brief deactivate all policys with given tokenid
     * @param tokenId token id of the object
     * @param timestamp timestamp to unset policy
     * @return int32_t
     */
    int32_t UnSetAllPolicyByToken(const uint32_t tokenId, uint64_t timestamp = 0);
private:
    /**
     * @brief Clean policy list on MAC
     * @param GenericValues vector
     */
    void CleanPolicyOnMac(const std::vector<std::string> &filePathList, int32_t userId);

    /**
     * @brief find a record with same token and policy path (mode not inclued)
     * @param tokenId token id of the object
     * @param policy search policy
     * @param result search result
     * @return SANDBOX_MANAGER_DB_ERR / SANDBOX_MANAGER_DB_RETURN_EMPTY / SANDBOX_MANAGER_OK
     */
    int32_t ExactFind(const uint32_t tokenId,  const PolicyInfo &policy, PolicyInfo &result);
    /**
     * @brief check policy validity in batch
     * @param policies input policy, see policy_info.h
     * @param result output result
     * @param passIndexes index of policy which is valid
     * @param mediaIndexes index of media policy which is valid
     * @return uint32_t invalid policy count
     */
    uint32_t FilterValidPolicyInBatch(const std::vector<PolicyInfo> &policies, std::vector<uint32_t> &results,
        std::vector<size_t> &passIndexes, std::vector<size_t> &mediaIndexes);
    /**
     * @brief AddToDatabaseIfNotDuplicate by remove deplicate records
     * @param tokenId token id of the object
     * @param policy input policy, see policy_info.h
     * @param result output result
     * @param passIndex index of policy which is valid
     * @param flag persist flag
     * @return
     */
    int32_t AddToDatabaseIfNotDuplicate(const uint32_t tokenId,
        const std::vector<PolicyInfo> &policies, const std::vector<size_t> &passIndexes,
        const uint32_t flag, std::vector<uint32_t> &results);
    /**
     * @brief find a record with input conditions
     * @param conditions input conditions
     * @param symbols input symbols of conditions, like depthColumn <= 2, 2 in condition, <= in symbols
     * @param results search result
     * @return SANDBOX_MANAGER_DB_ERR / SANDBOX_MANAGER_DB_RETURN_EMPTY / SANDBOX_MANAGER_OK
     */
    int32_t RangeFind(const GenericValues &conditions, const GenericValues &symbols,
        std::vector<GenericValues> &results);
    /**
     * @brief transfer a policy and token to GenericValues style
     * @param tokenId token id of the object
     * @param policy input policy
     * @param generic transfer result
     * @return
     */
    void TransferPolicyToGeneric(const uint32_t tokenId, const PolicyInfo &policy, GenericValues &generic);
    /**
     * @brief transfer a GenericValues and token to policy style
     * @param tokenId token id of the object
     * @param policy input GenericValues
     * @param generic transfer result
     * @return
     */
    void TransferGenericToPolicy(const GenericValues &generic, uint32_t &tokenId, PolicyInfo &policy);
    /**
     * @brief cal depth of a given path string
     * @param path path of file system
     * @return depth of a path: "/" = 0, "/a" = 1, "/a/b" = 2
     */
    int64_t GetDepth(const std::string &path);
    /**
     * @brief judge two polict whether match
     * @param searchPolicy input policy
     * @param searchDepth depth of input policy
     * @param referPolicy refer policy
     * @param referDepth depth of refer policy
     * @return true / false
     */
    bool IsPolicyMatch(const PolicyInfo &searchPolicy, const uint64_t searchDepth,
        const PolicyInfo &referPolicy, const uint64_t referDepth);
    /**
     * @brief remove the end '/' of a file path
     * @param path input path
     * @return
     */
    std::string AdjustPath(const std::string &path);
    /**
     * @brief check policy validity
     * @param policy input policy, see policy_info.h
     * @return INVALID_PATH / INVALID_MODE / SANDBOX_MANAGER_OK
     */
    int32_t CheckPolicyValidity(const PolicyInfo &policy);
    /**
     * @brief unset sandboxpolicy and record conditions
     * @param tokenId a given tokenId
     * @param policy a policy to be unset
     * @param conditions conditions to be record
     * @return SANDBOX_MANAGER_MAC_IOCTL_ERR / SANDBOX_MANAGER_OK
     */
    int32_t UnsetSandboxPolicyAndRecord(const uint32_t tokenId, const PolicyInfo &policy,
        std::vector<GenericValues> &conditions);
    /**
     * @brief remove policies not belong to the user
     * @param results input policies to check
     * @param userId delete policies not belong to this user
     * @return
     */
    void RemoveResultByUserId(std::vector<GenericValues> &results, int32_t userId);
    /**
     * @brief get mac params with inputs
     * @param tokenId a given tokenId
     * @param policyFlag persist policy flag
     * @param timestamp timestamp of the policy
     * @return mac params structure
     */
    MacParams GetMacParams(uint32_t tokenId, uint64_t policyFlag, uint64_t timestamp);

private:
    MacAdapter macAdapter_;
    int32_t AddNormalPolicy(const uint32_t tokenId, const std::vector<PolicyInfo> &policy,
        std::vector<uint32_t> &result, const uint32_t flag, std::vector<size_t> &queryPolicyIndex, uint32_t invalidNum);
    int32_t StartAccessingNormalPolicy(const uint32_t tokenId, const std::vector<PolicyInfo> &policy,
        std::vector<uint32_t> &results, uint64_t timestamp);
    int32_t MatchNormalPolicy(const uint32_t tokenId, const std::vector<PolicyInfo> &policy,
        std::vector<uint32_t> &result);
    int32_t StopAccessingNormalPolicy(
        const uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &results);
    int32_t GetMediaPolicyCommonWork(const uint32_t tokenId, const std::vector<PolicyInfo> &policy,
        std::vector<uint32_t> &results, std::vector<size_t> &validIndex, std::vector<PolicyInfo> &normalPolicy);
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // POLICY_INFO_MANAGER_H