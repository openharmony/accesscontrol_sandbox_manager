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

#include "policy_info_manager.h"

#include <algorithm>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include "accesstoken_kit.h"
#include "generic_values.h"
#include "policy_field_const.h"
#include "policy_info.h"
#include "sandbox_manager_const.h"
#include "sandbox_manager_db.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxPolicyInfoManager"
};
}

PolicyInfoManager &PolicyInfoManager::GetInstance()
{
    static PolicyInfoManager instance;
    return instance;
}

void PolicyInfoManager::Init()
{
    SandboxManagerDb::GetInstance();
    macAdapter_.Init();
}

void PolicyInfoManager::CleanPolicyOnMac(const std::vector<GenericValues>& results)
{
    if (!macAdapter_.IsMacSupport()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Mac not enable, default success.");
        return;
    }
    std::map<uint32_t, std::vector<PolicyInfo>> allPersistPolicy;
    for (const auto& res : results) {
        uint32_t tokenId;
        PolicyInfo policy;
        TransferGenericToPolicy(res, tokenId, policy);
        auto it = allPersistPolicy.find(tokenId);
        if (it == allPersistPolicy.end()) {
            std::vector<PolicyInfo> policies;
            policies.emplace_back(policy);
            allPersistPolicy.insert(std::make_pair(tokenId, policies));
        } else {
            it->second.emplace_back(policy);
        }
    }

    for (auto& it : allPersistPolicy) {
        std::vector<bool> result(it.second.size());
        int32_t count = 0;
        macAdapter_.UnSetSandboxPolicy(it.first, it.second, result);
        for (bool res : result) {
            if (!res) {
                ++count;
            }
        }
        SANDBOXMANAGER_LOG_INFO(LABEL, "Mac UnSetSandboxPolicy size = %{public}zu, fail size = %{public}d.",
            it.second.size(), count);
    }
}

int32_t PolicyInfoManager::CleanPersistPolicyByPath(const std::vector<std::string>& filePathList)
{
    //Gets the persistence policy to be cleaned up
    std::vector<GenericValues> results;
    for (const std::string& path : filePathList) {
        uint32_t length = path.length();
        if ((length == 0) || (length > POLICY_PATH_LIMIT)) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Policy path check fail, length = %{public}zu.", path.length());
            continue;
        }
        std::string pathTmp = AdjustPath(path);
        SandboxManagerDb::GetInstance().FindSubPath(
            SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY, pathTmp, results);
    }
    if (results.empty()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "No persistence policy was found to delete.");
        return SANDBOX_MANAGER_OK;
    }

    //clean MAC
    CleanPolicyOnMac(results);

    //clear the persistence policy
    for (const auto& res: results) {
        int32_t ret = SandboxManagerDb::GetInstance().Remove(
            SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY, res);
        if (ret != SandboxManagerDb::SUCCESS) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Delete fail!");
        }
    }
    return SANDBOX_MANAGER_OK;
}

int32_t PolicyInfoManager::AddPolicy(const uint32_t tokenId, const std::vector<PolicyInfo> &policy,
    std::vector<uint32_t> &result, const uint32_t flag)
{
    if (!macAdapter_.IsMacSupport()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Mac not enable, default success.");
        return SANDBOX_MANAGER_OK;
    }
    size_t policySize = policy.size();
    result.resize(policySize);
    // check validity
    std::vector<size_t> queryPolicyIndex;
    FilterValidPolicyInBatch(policy, result, queryPolicyIndex);
    // query mac kernel
    size_t queryPolicyIndexSize = queryPolicyIndex.size();
    std::vector<bool> queryResults(queryPolicyIndexSize);
    std::vector<PolicyInfo> queryPolicys(queryPolicyIndexSize);
    std::transform(queryPolicyIndex.begin(), queryPolicyIndex.end(),
        queryPolicys.begin(), [policy](const size_t index) { return policy[index]; });
    int32_t ret = macAdapter_.QuerySandboxPolicy(tokenId, queryPolicys, queryResults);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "MacAdapter query error, err code = %{public}d", ret);
        result.clear();
        return ret;
    }
    // add to database
    std::vector<GenericValues> addPolicyGeneric;
    std::vector<size_t> addPolicyIndex;
    for (size_t i = 0; i < queryPolicyIndexSize; ++i) {
        if (queryResults[i]) {
            addPolicyIndex.emplace_back(queryPolicyIndex[i]);
        } else {
            result[queryPolicyIndex[i]] = SandboxRetType::FORBIDDEN_TO_BE_PERSISTED;
        }
    }
    ret = AddToDatabaseIfNotDuplicate(tokenId, policy, addPolicyIndex, flag, result);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "AddToDatabaseIfNotDuplicate failed.");
        result.clear();
        return ret;
    }
    return SANDBOX_MANAGER_OK;
}

void PolicyInfoManager::FilterValidPolicyInBatch(
    const std::vector<PolicyInfo> &policies, std::vector<uint32_t> &results, std::vector<size_t> &passIndexes)
{
    size_t policySize = policies.size();
    for (size_t i = 0; i < policySize; ++i) {
        int32_t checkPolicyRet = CheckPolicyValidity(policies[i]);
        if (checkPolicyRet != SANDBOX_MANAGER_OK) {
            results[i] = static_cast<uint32_t>(checkPolicyRet);
            continue;
        }
        passIndexes.emplace_back(i);
    }
}
int32_t PolicyInfoManager::AddToDatabaseIfNotDuplicate(const uint32_t tokenId, const std::vector<PolicyInfo> &policies,
    const std::vector<size_t> &passIndexes, const uint32_t flag, std::vector<uint32_t> &results)
{
    std::vector<GenericValues> addPolicyGeneric;
    for (size_t each : passIndexes) {
        GenericValues condition;
        TransferPolicyToGeneric(tokenId, policies[each], condition);
        int32_t ret = SandboxManagerDb::GetInstance().Remove(
            SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY, condition);
        if (ret != SandboxManagerDb::SUCCESS) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Database remove error");
            return SANDBOX_MANAGER_DB_ERR;
        }
        condition.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(flag));
        addPolicyGeneric.emplace_back(condition);
    }
    int32_t ret = SandboxManagerDb::GetInstance().Add(
        SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY, addPolicyGeneric);
    if (ret != SandboxManagerDb::SUCCESS) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "database operate error");
        results.clear();
        return SANDBOX_MANAGER_DB_ERR;
    }
    // write results
    for (size_t each: passIndexes) {
        results[each] = SandboxRetType::OPERATE_SUCCESSFULLY;
    }
    return SANDBOX_MANAGER_OK;
}

int32_t PolicyInfoManager::MatchSinglePolicy(const uint32_t tokenId, const PolicyInfo &policy, uint32_t &result)
{
    int32_t checkPolicyRet = CheckPolicyValidity(policy);
    if (checkPolicyRet != SANDBOX_MANAGER_OK) {
        result = static_cast<uint32_t>(checkPolicyRet);
        return INVALID_PARAMTER;
    }

    // search records have same tokenId and depth <= input policy
    GenericValues conditions;
    GenericValues symbols;
    uint64_t searchDepth = static_cast<uint64_t>(GetDepth(policy.path));

    conditions.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int32_t>(tokenId));
    symbols.Put(PolicyFiledConst::FIELD_TOKENID, std::string("="));

    conditions.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(searchDepth));
    symbols.Put(PolicyFiledConst::FIELD_DEPTH, std::string("<="));

    std::vector<GenericValues> dbResults;
    int32_t ret = RangeFind(conditions, symbols, dbResults);
    if (ret == SANDBOX_MANAGER_DB_ERR) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "database operate error");
        return SANDBOX_MANAGER_DB_ERR;
    }
    size_t dbResultsSize = dbResults.size();
    if (ret == SANDBOX_MANAGER_OK && dbResultsSize == 0) {
        // find nothing, return not match
        SANDBOXMANAGER_LOG_DEBUG(LABEL, "database return empty");
        result = POLICY_HAS_NOT_BEEN_PERSISTED;
        return SANDBOX_MANAGER_OK;
    }
    for (size_t i = 0; i < dbResultsSize; ++i) {
        PolicyInfo referPolicy;
        referPolicy.path = dbResults[i].GetString(PolicyFiledConst::FIELD_PATH);
        referPolicy.mode = static_cast<uint64_t>(dbResults[i].GetInt(PolicyFiledConst::FIELD_MODE));
        uint64_t referDepth = static_cast<uint64_t>(dbResults[i].GetInt(PolicyFiledConst::FIELD_DEPTH));
        
        PolicyInfo searchPolicy;
        searchPolicy.mode = policy.mode;
        searchPolicy.path = AdjustPath(policy.path);
        if (IsPolicyMatch(searchPolicy, searchDepth, referPolicy, referDepth)) {
            result = SandboxRetType::OPERATE_SUCCESSFULLY;
            return SANDBOX_MANAGER_OK;
        }
    }
    result = SandboxRetType::POLICY_HAS_NOT_BEEN_PERSISTED;
    return SANDBOX_MANAGER_OK;
}

int32_t PolicyInfoManager::MatchPolicy(const uint32_t tokenId, const std::vector<PolicyInfo> &policy,
    std::vector<uint32_t> &result)
{
    size_t policySize = policy.size();
    if (result.size() != policySize) {
        result.resize(policySize);
    }
    for (size_t i = 0; i < policySize; ++i) {
        int32_t ret = MatchSinglePolicy(tokenId, policy[i], result[i]);
        if (ret == SANDBOX_MANAGER_DB_ERR) {
            return ret;
        }
    }
    return SANDBOX_MANAGER_OK;
}

int32_t PolicyInfoManager::RemovePolicy(
    const uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    if (!macAdapter_.IsMacSupport()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Mac not enable, default success.");
        return SANDBOX_MANAGER_OK;
    }
    // remove only token, path, mode equal
    size_t policySize = policy.size();
    if (result.size() != policySize) {
        result.resize(policySize);
    }
    for (size_t i = 0; i < policySize; ++i) {
        int32_t checkPolicyRet = CheckPolicyValidity(policy[i]);
        if (checkPolicyRet != SANDBOX_MANAGER_OK) {
            result[i] = static_cast<uint32_t>(checkPolicyRet);
            continue;
        }
        PolicyInfo exactFindRes;
        int32_t ret = ExactFind(tokenId, policy[i], exactFindRes);
        if (ret == SANDBOX_MANAGER_DB_RETURN_EMPTY) {
            result[i] = SandboxRetType::POLICY_HAS_NOT_BEEN_PERSISTED;
            continue;
        }
        
        ret = macAdapter_.UnSetSandboxPolicy(tokenId, policy[i]);
        if (ret != SANDBOX_MANAGER_OK) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "MacAdapter unset error, err code = %{public}d.", ret);
            return ret;
        }

        GenericValues condition;
        TransferPolicyToGeneric(tokenId, policy[i], condition);
        ret = SandboxManagerDb::GetInstance().Remove(
            SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY, condition);
        if (ret != SandboxManagerDb::SUCCESS) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "database operate error");
            return SANDBOX_MANAGER_DB_ERR;
        }
    }
    return SANDBOX_MANAGER_OK;
}

int32_t PolicyInfoManager::SetPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy, uint64_t policyFlag,
                                     std::vector<uint32_t> &result)
{
    if (!macAdapter_.IsMacSupport()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Mac not enable, default success.");
        return SANDBOX_MANAGER_OK;
    }
    result.resize(policy.size(), INVALID_PATH);
    std::vector<size_t> validIndex;
    std::vector<PolicyInfo> validPolicies;
    for (size_t index = 0; index < policy.size(); ++index) {
        int32_t res = CheckPolicyValidity(policy[index]);
        if (res == SANDBOX_MANAGER_OK) {
            validIndex.emplace_back(index);
            validPolicies.emplace_back(policy[index]);
        } else {
            result[index] = res;
        }
    }

    if (validPolicies.empty()) {
        SANDBOXMANAGER_LOG_WARN(LABEL, "No valid policy to set.");
        return SANDBOX_MANAGER_OK;
    }

    std::vector<uint32_t> setResult(validPolicies.size(), SANDBOX_MANAGER_OK);
    int32_t ret = macAdapter_.SetSandboxPolicy(tokenId, validPolicies, policyFlag, setResult);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Set sandbox policy failed, error=%{public}d.", ret);
        result.clear();
        return ret;
    }
    size_t resultIndex = 0;
    for (const auto &index : validIndex) {
        result[index] = setResult[resultIndex++];
    }

    return SANDBOX_MANAGER_OK;
}

int32_t PolicyInfoManager::UnSetPolicy(uint32_t tokenId, const PolicyInfo &policy)
{
    if (!macAdapter_.IsMacSupport()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Mac not enable, default success.");
        return SANDBOX_MANAGER_OK;
    }
    return macAdapter_.UnSetSandboxPolicy(tokenId, policy);
}

int32_t PolicyInfoManager::CheckPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                       std::vector<bool> &result)
{
    if (!macAdapter_.IsMacSupport()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Mac not enable, default success.");
        return SANDBOX_MANAGER_OK;
    }
    result.resize(policy.size(), false);
    std::vector<size_t> validIndex;
    std::vector<PolicyInfo> validPolicies;
    for (size_t index = 0; index < policy.size(); ++index) {
        int32_t res = CheckPolicyValidity(policy[index]);
        if (res == SANDBOX_MANAGER_OK) {
            validIndex.emplace_back(index);
            validPolicies.emplace_back(policy[index]);
        }
    }

    if (validPolicies.empty()) {
        SANDBOXMANAGER_LOG_WARN(LABEL, "No valid policy to set.");
        return SANDBOX_MANAGER_OK;
    }

    std::vector<bool> checkResult(validPolicies.size(), false);
    int32_t ret = macAdapter_.CheckSandboxPolicy(tokenId, validPolicies, checkResult);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check sandbox policy failed, error=%{public}d.", ret);
        result.clear();
        return ret;
    }
    size_t resultIndex = 0;
    for (const auto &index : validIndex) {
        result[index] = checkResult[resultIndex++];
    }

    return SANDBOX_MANAGER_OK;
}

bool PolicyInfoManager::RemoveBundlePolicy(const uint32_t tokenId)
{
    GenericValues conditions;
    conditions.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int32_t>(tokenId));
    // remove policys that have same tokenId
    int32_t ret = SandboxManagerDb::GetInstance().Remove(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
        conditions);
    if (ret != SandboxManagerDb::SUCCESS) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "database operate error");
        return false;
    }
    return true;
}

int32_t PolicyInfoManager::StartAccessingByTokenId(const uint32_t tokenId)
{
    if (!macAdapter_.IsMacSupport()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Mac not enable, default success.");
        return SANDBOX_MANAGER_OK;
    }
    GenericValues conditions;
    GenericValues symbols;

    conditions.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int32_t>(tokenId));
    symbols.Put(PolicyFiledConst::FIELD_TOKENID, std::string("="));
    conditions.Put(PolicyFiledConst::FIELD_FLAG, 1);
    symbols.Put(PolicyFiledConst::FIELD_FLAG, std::string("="));

    std::vector<GenericValues> dbResults;
    int32_t ret = RangeFind(conditions, symbols, dbResults);
    if (ret == SANDBOX_MANAGER_DB_ERR) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Database operate error");
        return SANDBOX_MANAGER_DB_ERR;
    }
    size_t searchSize = dbResults.size();
    if (searchSize == 0) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Database find result empty");
        return SANDBOX_MANAGER_DB_RETURN_EMPTY;
    }

    std::vector<PolicyInfo> policys(searchSize);
    for (size_t i = 0; i < searchSize; ++i) {
        PolicyInfo policy;
        policy.path = dbResults[i].GetString(PolicyFiledConst::FIELD_PATH);
        policy.mode = static_cast<uint64_t>(dbResults[i].GetInt(PolicyFiledConst::FIELD_MODE));
        policys[i] = policy;
    }
    std::vector<uint32_t> macResults(searchSize);
    ret = macAdapter_.SetSandboxPolicy(tokenId, policys, 0, macResults);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "MacAdapter set policy error, err code = %{public}d.", ret);
        return ret;
    }
    return SANDBOX_MANAGER_OK;
}

int32_t PolicyInfoManager::StartAccessingPolicy(
    const uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &results)
{
    if (!macAdapter_.IsMacSupport()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Mac not enable, default success.");
        return SANDBOX_MANAGER_OK;
    }
    size_t policySize = policy.size();
    results.resize(policySize);
    // check database, check validity in MatchPolicy
    std::vector<uint32_t> matchResults(policySize);
    int32_t ret = MatchPolicy(tokenId, policy, matchResults);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "MatchPolicy error.");
        results.clear();
        return ret;
    }
    // set to mac
    std::vector<size_t> accessingIndex;
    for (size_t i = 0; i < policySize; ++i) {
        if (matchResults[i] == SandboxRetType::OPERATE_SUCCESSFULLY) {
            accessingIndex.emplace_back(i);
        } else {
            results[i] = matchResults[i];
        }
    }
    size_t accessingIndexSize = accessingIndex.size();
    std::vector<PolicyInfo> accessingPolicy(accessingIndexSize);
    std::transform(accessingIndex.begin(), accessingIndex.end(),
        accessingPolicy.begin(), [policy](size_t index) { return policy[index]; });
    std::vector<uint32_t> macResults(accessingIndexSize);
    ret = macAdapter_.SetSandboxPolicy(tokenId, accessingPolicy, 0, macResults);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "MacAdapter set policy error, err code = %{public}d.", ret);
        results.clear();
        return ret;
    }
    // write ok flag
    for (size_t i = 0; i < accessingIndexSize; ++i) {
        if (macResults[i] == SANDBOX_MANAGER_OK) {
            results[accessingIndex[i]] = SandboxRetType::OPERATE_SUCCESSFULLY;
        } else {
            results[accessingIndex[i]] = SandboxRetType::POLICY_MAC_FAIL;
        }
    }
    return SANDBOX_MANAGER_OK;
}

int32_t PolicyInfoManager::StopAccessingPolicy(
    const uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &results)
{
    if (!macAdapter_.IsMacSupport()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Mac not enable, default success.");
        return SANDBOX_MANAGER_OK;
    }
    size_t policySize = policy.size();
    results.resize(policySize);
    // check database, check validity in MatchPolicy
    std::vector<uint32_t> matchResults(policy.size());
    int32_t ret = MatchPolicy(tokenId, policy, matchResults);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "MatchPolicy error.");
        results.clear();
        return ret;
    }
    // set to mac
    std::vector<size_t> accessingIndex;
    for (size_t i = 0; i < policySize; ++i) {
        if (matchResults[i] == SandboxRetType::OPERATE_SUCCESSFULLY) {
            accessingIndex.emplace_back(i);
        } else {
            results[i] = matchResults[i];
        }
    }
    size_t accessingIndexSize = accessingIndex.size();
    std::vector<PolicyInfo> accessingPolicy(accessingIndexSize);
    std::transform(accessingIndex.begin(), accessingIndex.end(),
        accessingPolicy.begin(), [policy](size_t index) { return policy[index]; });
    std::vector<bool> macResults(accessingIndexSize);
    ret = macAdapter_.UnSetSandboxPolicy(tokenId, accessingPolicy, macResults);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "MacAdapter unset policy error, err code = %{public}d.", ret);
        results.clear();
        return ret;
    }
    // write ok flag
    for (size_t i = 0; i < accessingIndexSize; ++i) {
        if (macResults[i]) {
            results[accessingIndex[i]] = SandboxRetType::OPERATE_SUCCESSFULLY;
        } else {
            results[accessingIndex[i]] = SandboxRetType::POLICY_MAC_FAIL;
        }
    }
    return SANDBOX_MANAGER_OK;
}

int32_t PolicyInfoManager::UnSetAllPolicyByToken(const uint32_t tokenId)
{
    if (!macAdapter_.IsMacSupport()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Mac not enable, default success.");
        return SANDBOX_MANAGER_OK;
    }
    return macAdapter_.DestroySandboxPolicy(tokenId);
}

int32_t PolicyInfoManager::RangeFind(const GenericValues &conditions, const GenericValues &symbols,
    std::vector<GenericValues> &results)
{
    int32_t ret = SandboxManagerDb::GetInstance().Find(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
        conditions, symbols, results);
    if (ret != SandboxManagerDb::SUCCESS) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "database operate error");
        return SANDBOX_MANAGER_DB_ERR;
    }
    if (results.empty()) {
        SANDBOXMANAGER_LOG_DEBUG(LABEL, "database return empty");
        return SANDBOX_MANAGER_OK;
    }
    return SANDBOX_MANAGER_OK;
}

int32_t PolicyInfoManager::ExactFind(const uint32_t tokenId, const PolicyInfo &policy, PolicyInfo &result)
{
    // search policy that have same tokenId, path, depth, mode
    GenericValues conditions;
    GenericValues symbols;
    TransferPolicyToGeneric(tokenId, policy, conditions);

    std::vector<GenericValues> searchResults;
    int32_t ret = SandboxManagerDb::GetInstance().Find(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
        conditions, symbols, searchResults);
    if (ret != SandboxManagerDb::SUCCESS) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "database operate error");
        return SANDBOX_MANAGER_DB_ERR;
    }
    if (searchResults.empty()) {
        SANDBOXMANAGER_LOG_DEBUG(LABEL, "database return empty");
        return SANDBOX_MANAGER_DB_RETURN_EMPTY;
    }
    result.path = searchResults[0].GetString(PolicyFiledConst::FIELD_PATH);
    result.mode = static_cast<uint64_t>(searchResults[0].GetInt(PolicyFiledConst::FIELD_MODE));
    return SANDBOX_MANAGER_OK;
}

void PolicyInfoManager::TransferPolicyToGeneric(const uint32_t tokenId, const PolicyInfo &policy,
    GenericValues &generic)
{
    // generate GenericValues
    std::string path = AdjustPath(policy.path);
    generic.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int32_t>(tokenId));
    generic.Put(PolicyFiledConst::FIELD_PATH, path);
    generic.Put(PolicyFiledConst::FIELD_DEPTH, GetDepth(path));
    generic.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(policy.mode));
}
void PolicyInfoManager::TransferGenericToPolicy(const GenericValues &generic, uint32_t &tokenId, PolicyInfo &policy)
{
    policy.path = generic.GetString(PolicyFiledConst::FIELD_PATH);
    policy.mode = static_cast<uint64_t>(generic.GetInt(PolicyFiledConst::FIELD_MODE));
    tokenId = static_cast<uint32_t>(generic.GetInt(PolicyFiledConst::FIELD_TOKENID));
}

int64_t PolicyInfoManager::GetDepth(const std::string &path)
{
    std::string inputPath = AdjustPath(path);
    // if path end with '/', depth -1
    if (inputPath[inputPath.length()-1] == '/') {
        return static_cast<int64_t>(count(inputPath.begin(), inputPath.end(), '/') - 1);
    } else {
        return static_cast<int64_t>(count(inputPath.begin(), inputPath.end(), '/'));
    }
}

bool PolicyInfoManager::IsPolicyMatch(const PolicyInfo &searchPolicy, const uint64_t searchDepth,
    const PolicyInfo &referPolicy, const uint64_t referDepth)
{
    bool pathMatch;
    bool modeMatch;
    if (searchDepth == referDepth) {
        // if depth equal, path should be strict equal
        pathMatch = (searchPolicy.path == referPolicy.path);
    } else if (searchDepth > referDepth && referPolicy.path.length() <= searchPolicy.path.length()) {
        // if depth not equal, searchPath should startwith referPath
        std::string referPath = referPolicy.path + "/";
        pathMatch = (searchPolicy.path.substr(0, referPath.length()) == referPath);
    } else {
        // searchDepth < referDepth, wrong input, return false
        return false;
    }

    uint64_t searchMode;
    uint64_t referMode;
    searchMode = searchPolicy.mode & MODE_FILTER;
    referMode = referPolicy.mode & MODE_FILTER;
    // refer RW, search R or W shoule return true
    if (referMode == searchMode) {
        modeMatch = true;
    } else if (referMode > searchMode) {
        modeMatch = ((referMode & searchMode) != 0);
    } else {
        modeMatch = false;
    }
    return pathMatch && modeMatch;
}

std::string PolicyInfoManager::AdjustPath(const std::string &path)
{
    if (path[path.length() - 1] == '/') {
        return path.substr(0, path.length() - 1);
    }
    return path;
}

int32_t PolicyInfoManager::CheckPolicyValidity(const PolicyInfo &policy)
{
    // path not empty and lenth < POLICY_PATH_LIMIT
    uint32_t length = policy.path.length();
    if (length == 0 || length > POLICY_PATH_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "policy path check fail, length = %{public}zu", policy.path.length());
        return SandboxRetType::INVALID_PATH;
    }
    std::string path = AdjustPath(policy.path);

    // mode between 0 and 0b11(READ_MODE+WRITE_MODE)
    if (policy.mode < OperateMode::READ_MODE ||
        policy.mode > OperateMode::READ_MODE + OperateMode::WRITE_MODE) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "policy mode check fail: %{public}" PRIu64, policy.mode);
        return SandboxRetType::INVALID_MODE;
    }
    return SANDBOX_MANAGER_OK;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS