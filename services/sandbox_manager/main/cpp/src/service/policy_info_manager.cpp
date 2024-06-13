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

#include "policy_info_manager.h"

#include <cinttypes>
#include <cstdint>
#include <string>
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
}

int32_t PolicyInfoManager::AddPolicy(const uint64_t tokenId, const std::vector<PolicyInfo> &policy,
    std::vector<uint32_t> &result, const uint32_t flag)
{
    uint64_t policySize = policy.size();
    if (policySize == 0 || policySize > POLICY_VECTOR_SIZE_LIMIT) {
        return INVALID_PARAMTER;
    }
    result.resize(policySize);
    
    for (size_t i = 0; i < policySize; i++) {
        int32_t checkPolicyRet = CheckPolicyValidity(policy[i]);
        if (checkPolicyRet != SANDBOX_MANAGER_OK) {
            result[i] = static_cast<uint32_t>(checkPolicyRet);
            continue;
        }
        // find duplicate record (have same tokenId, path), delete it
        PolicyInfo findresult;
        int32_t exactFindRet = ExactFind(tokenId, policy[i], findresult);
        if (exactFindRet == SANDBOX_MANAGER_DB_ERR) {
            return SANDBOX_MANAGER_DB_ERR;
        }

        if (exactFindRet == SANDBOX_MANAGER_OK && findresult.mode == policy[i].mode) {
            result[i] = SandboxRetType::OPERATE_SUCCESSFULLY;
            continue;
        }

        GenericValues addRecord;
        TransferPolicyToGeneric(tokenId, policy[i], addRecord);
        addRecord.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(flag));

        std::vector<GenericValues> recordVec = {addRecord};
        int32_t ret = SandboxManagerDb::GetInstance().Add(
            SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY, recordVec);
        if (ret != SandboxManagerDb::SUCCESS) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "database operate error");
            return SANDBOX_MANAGER_DB_ERR;
        }
        result[i] = SandboxRetType::OPERATE_SUCCESSFULLY;
    }
    return SANDBOX_MANAGER_OK;
}

int32_t PolicyInfoManager::MatchSinglePolicy(const uint64_t tokenId, const PolicyInfo &policy, uint32_t &result)
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

    conditions.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(tokenId));
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
    for (size_t i = 0; i < dbResultsSize; i++) {
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

int32_t PolicyInfoManager::MatchPolicy(const uint64_t tokenId, const std::vector<PolicyInfo> &policy,
    std::vector<uint32_t> &result)
{
    uint64_t policySize = policy.size();
    if (policySize == 0 || policySize > POLICY_VECTOR_SIZE_LIMIT) {
        return INVALID_PARAMTER;
    }
    if (result.size() != policySize) {
        result.resize(policySize);
    }
    for (size_t i = 0; i < policySize; i++) {
        int32_t ret = MatchSinglePolicy(tokenId, policy[i], result[i]);
        if (ret == SANDBOX_MANAGER_DB_ERR) {
            return ret;
        }
    }
    return SANDBOX_MANAGER_OK;
}

int32_t PolicyInfoManager::RemovePolicy(
    const uint64_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    // remove only token, path, mode equal
    uint64_t policySize = policy.size();
    if (policySize == 0 || policySize > POLICY_VECTOR_SIZE_LIMIT) {
        return INVALID_PARAMTER;
    }
    if (result.size() != policySize) {
        result.resize(policySize);
    }
    for (size_t i = 0; i < policySize; i++) {
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

bool PolicyInfoManager::RemoveBundlePolicy(const uint64_t tokenId)
{
    GenericValues conditions;
    conditions.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(tokenId));
    // remove policys that have same tokenId
    int32_t ret = SandboxManagerDb::GetInstance().Remove(SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY,
        conditions);
    if (ret != SandboxManagerDb::SUCCESS) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "database operate error");
        return false;
    }
    return true;
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

int32_t PolicyInfoManager::ExactFind(const uint64_t tokenId, const PolicyInfo &policy, PolicyInfo &result)
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

void PolicyInfoManager::TransferPolicyToGeneric(const uint64_t tokenId, const PolicyInfo &policy,
    GenericValues &generic)
{
    // generate GenericValues
    std::string path = AdjustPath(policy.path);
    generic.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(tokenId));
    generic.Put(PolicyFiledConst::FIELD_PATH, path);
    generic.Put(PolicyFiledConst::FIELD_DEPTH, GetDepth(path));
    generic.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(policy.mode));
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
    // mode should strict equal
    modeMatch = (searchMode == referMode);
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
        SANDBOXMANAGER_LOG_ERROR(LABEL, "policy path check fail: %{public}s", policy.path.c_str());
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