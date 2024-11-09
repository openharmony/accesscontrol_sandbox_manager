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
#include "sandbox_manager_rdb.h"
#include "sandbox_manager_dfx_helper.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"
#include "os_account_manager.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxPolicyInfoManager"
};
static std::mutex g_instanceMutex;
}

PolicyInfoManager &PolicyInfoManager::GetInstance()
{
    static PolicyInfoManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new PolicyInfoManager();
        }
    }
    return *instance;
}

void PolicyInfoManager::Init()
{
    SandboxManagerRdb::GetInstance();
    macAdapter_.Init();
}

void PolicyInfoManager::CleanPolicyOnMac(const std::vector<std::string> &filePathList, int32_t userId)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "Clean policy on Mac by userId:%{private}d", userId);
    if (!macAdapter_.IsMacSupport()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Mac not enable, default success.");
        return;
    }
    std::vector<PolicyInfo> policies;
    for (const std::string &path:filePathList) {
        PolicyInfo policy;
        policy.path = path;
        policies.emplace_back(policy);
    }

    std::vector<bool> result(policies.size());

    macAdapter_.UnSetSandboxPolicyByUser(userId, policies, result);
    int32_t count = 0;
    for (bool res : result) {
        if (!res) {
            ++count;
        }
    }
    size_t resultSize = result.size();
    PolicyOperateInfo info(resultSize, resultSize - count, count, 0);
    SandboxManagerDfxHelper::WritePersistPolicyOperateSucc(OperateTypeEnum::CLEAN_PERSIST_POLICY_BY_PATH, info);
}

void PolicyInfoManager::RemoveResultByUserId(std::vector<GenericValues> &results, int32_t userId)
{
    for (auto it = results.begin(); it != results.end();) {
        uint32_t tokenId = static_cast<uint32_t>(it->GetInt(PolicyFiledConst::FIELD_TOKENID));
        Security::AccessToken::HapTokenInfo hapTokenInfoRes;
        int ret = Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapTokenInfoRes);
        if (ret != 0) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "find user id by token id failed ret:%{public}d", ret);
            ++it;
            continue;
        }
        SANDBOXMANAGER_LOG_INFO(LABEL, "check result userId:%{public}d hap userId:%{public}d target:%{public}u", userId,
            hapTokenInfoRes.userID, tokenId);

        if (hapTokenInfoRes.userID != userId) {
            SANDBOXMANAGER_LOG_INFO(LABEL,
                "userId:%{public}d hap userId:%{public}d mismatch, do not delete target:%{public}u", userId,
                hapTokenInfoRes.userID, tokenId);
            it = results.erase(it);
        } else {
            ++it;
        }
    }
}

int32_t PolicyInfoManager::CleanPersistPolicyByPath(const std::vector<std::string>& filePathList)
{
    // clean MAC
    int32_t userId = 0;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "clean persist failed, get user id failed error=%{public}d", ret);
        userId = 0; // set default userId
    }

    SANDBOXMANAGER_LOG_INFO(LABEL, "clean policy by path and userId:%{public}d", userId);
    CleanPolicyOnMac(filePathList, userId);
    //Gets the persistence policy to be cleaned up
    std::vector<GenericValues> results;
    for (const std::string& path : filePathList) {
        uint32_t length = path.length();
        if ((length == 0) || (length > POLICY_PATH_LIMIT)) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Policy path check fail, length = %{public}zu.", path.length());
            continue;
        }
        std::string pathTmp = AdjustPath(path);
        SandboxManagerRdb::GetInstance().FindSubPath(
            SANDBOX_MANAGER_PERSISTED_POLICY, pathTmp, results);
    }
    if (results.empty()) {
        PolicyOperateInfo info(0, 0, 0, 0);
        SandboxManagerDfxHelper::WritePersistPolicyOperateSucc(
            OperateTypeEnum::CLEAN_PERSIST_POLICY_BY_PATH, info);
        SANDBOXMANAGER_LOG_INFO(LABEL, "No persistence policy was found to delete.");
        return SANDBOX_MANAGER_OK;
    }

    RemoveResultByUserId(results, userId);

    //clear the persistence policy
    for (const auto& res: results) {
        int32_t ret = SandboxManagerRdb::GetInstance().Remove(
            SANDBOX_MANAGER_PERSISTED_POLICY, res);
        if (ret != SandboxManagerRdb::SUCCESS) {
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
        result.resize(policy.size(), SandboxRetType::OPERATE_SUCCESSFULLY);
        return SANDBOX_MANAGER_OK;
    }
    size_t policySize = policy.size();
    result.resize(policySize);
    // check validity
    std::vector<size_t> queryPolicyIndex;
    uint32_t invalidNum = FilterValidPolicyInBatch(policy, result, queryPolicyIndex);
    // query mac kernel
    size_t queryPolicyIndexSize = queryPolicyIndex.size();
    std::vector<bool> queryResults(queryPolicyIndexSize);
    std::vector<PolicyInfo> queryPolicys(queryPolicyIndexSize);
    std::transform(queryPolicyIndex.begin(), queryPolicyIndex.end(),
        queryPolicys.begin(), [policy](const size_t index) { return policy[index]; });
    int32_t ret = macAdapter_.QuerySandboxPolicy(tokenId, queryPolicys, queryResults);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "MacAdapter query error, err code = %{public}d", ret);
        PolicyOperateInfo info(policySize, 0, policySize - invalidNum, invalidNum);
        SandboxManagerDfxHelper::WritePersistPolicyOperateSucc(OperateTypeEnum::PERSIST_POLICY, info);
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
    uint32_t failNum = queryPolicyIndexSize - addPolicyIndex.size();
    ret = AddToDatabaseIfNotDuplicate(tokenId, policy, addPolicyIndex, flag, result);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "AddToDatabaseIfNotDuplicate failed.");
        result.clear();
        return ret;
    }
    PolicyOperateInfo info(policySize, addPolicyIndex.size(), failNum, invalidNum);
    SandboxManagerDfxHelper::WritePersistPolicyOperateSucc(OperateTypeEnum::PERSIST_POLICY, info);
    return SANDBOX_MANAGER_OK;
}

uint32_t PolicyInfoManager::FilterValidPolicyInBatch(
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
    return policySize - passIndexes.size();
}
int32_t PolicyInfoManager::AddToDatabaseIfNotDuplicate(const uint32_t tokenId, const std::vector<PolicyInfo> &policies,
    const std::vector<size_t> &passIndexes, const uint32_t flag, std::vector<uint32_t> &results)
{
    std::vector<GenericValues> addPolicyGeneric;
    if (passIndexes.empty()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "No policies need to add.");
        return SANDBOX_MANAGER_OK;
    }
    
    for (size_t each : passIndexes) {
        GenericValues condition;
        TransferPolicyToGeneric(tokenId, policies[each], condition);
        condition.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(flag));
        addPolicyGeneric.emplace_back(condition);
    }
    std::string duplicateMode = SandboxManagerRdb::IGNORE;
    // replace duplicate policy when flag is 1
    if (flag == 1) {
        duplicateMode = SandboxManagerRdb::REPLACE;
    }
    int32_t ret = SandboxManagerRdb::GetInstance().Add(
        SANDBOX_MANAGER_PERSISTED_POLICY, addPolicyGeneric, duplicateMode);
    if (ret != SandboxManagerRdb::SUCCESS) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Database operate error");
        results.clear();
        return SANDBOX_MANAGER_DB_ERR;
    }
    // write results
    for (size_t each: passIndexes) {
        results[each] = SandboxRetType::OPERATE_SUCCESSFULLY;
    }
    return SANDBOX_MANAGER_OK;
}

void PolicyInfoManager::RepeatsPathPolicyModeCal(std::vector<GenericValues> &dbResults, uint64_t dbResultsSize)
{
    std::map<std::string, uint32_t> dbResultsMap;
    for (size_t i = 0; i < dbResultsSize; ++i) {
        std::string currPath = dbResults[i].GetString(PolicyFiledConst::FIELD_PATH);
        uint32_t currMode = static_cast<uint32_t>(dbResults[i].GetInt(PolicyFiledConst::FIELD_MODE));
        if (dbResultsMap.find(currPath) != dbResultsMap.end()) {
            dbResultsMap[currPath] |= currMode;
        } else {
            dbResultsMap.insert(std::make_pair(currPath, currMode));
        }
    }
    for (size_t i = 0; i < dbResultsSize; ++i) {
        std::string polisyPath = dbResults[i].GetString(PolicyFiledConst::FIELD_PATH);
        dbResults[i].Remove(PolicyFiledConst::FIELD_MODE);
        dbResults[i].Put(PolicyFiledConst::FIELD_MODE, static_cast<int32_t>(dbResultsMap[polisyPath]));
    }
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
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Database operate error");
        return SANDBOX_MANAGER_DB_ERR;
    }
    size_t dbResultsSize = dbResults.size();
    if (ret == SANDBOX_MANAGER_OK && dbResultsSize == 0) {
        // find nothing, return not match
        SANDBOXMANAGER_LOG_DEBUG(LABEL, "Database return empty");
        result = POLICY_HAS_NOT_BEEN_PERSISTED;
        return SANDBOX_MANAGER_OK;
    }
    RepeatsPathPolicyModeCal(dbResults, dbResultsSize);
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
        result.resize(policy.size(), SandboxRetType::OPERATE_SUCCESSFULLY);
        return SANDBOX_MANAGER_OK;
    }
    // remove only token, path, mode equal
    size_t policySize = policy.size();
    if (result.size() != policySize) {
        result.resize(policySize);
    }
    uint32_t invalidNum = 0;
    uint32_t failNum = 0;
    uint32_t successNum = 0;
    for (size_t i = 0; i < policySize; ++i) {
        int32_t checkPolicyRet = CheckPolicyValidity(policy[i]);
        if (checkPolicyRet != SANDBOX_MANAGER_OK) {
            result[i] = static_cast<uint32_t>(checkPolicyRet);
            ++invalidNum;
            continue;
        }
        PolicyInfo exactFindRes;
        int32_t ret = ExactFind(tokenId, policy[i], exactFindRes);
        if (ret == SANDBOX_MANAGER_DB_RETURN_EMPTY) {
            result[i] = SandboxRetType::POLICY_HAS_NOT_BEEN_PERSISTED;
            ++successNum;
            continue;
        }
        
        ret = macAdapter_.UnSetSandboxPolicy(tokenId, policy[i]);
        if (ret != SANDBOX_MANAGER_OK) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "MacAdapter unset error, err code = %{public}d.", ret);
            ++failNum;
            PolicyOperateInfo info(policySize, successNum, failNum, invalidNum);
            SandboxManagerDfxHelper::WritePersistPolicyOperateSucc(OperateTypeEnum::UNPERSIST_POLICY, info);
            return ret;
        }

        GenericValues condition;
        TransferPolicyToGeneric(tokenId, policy[i], condition);
        ret = SandboxManagerRdb::GetInstance().Remove(
            SANDBOX_MANAGER_PERSISTED_POLICY, condition);
        if (ret != SandboxManagerRdb::SUCCESS) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Database operate error");
            return SANDBOX_MANAGER_DB_ERR;
        }
        ++successNum;
    }
    PolicyOperateInfo info(result.size(), successNum, failNum, invalidNum);
    SandboxManagerDfxHelper::WritePersistPolicyOperateSucc(OperateTypeEnum::UNPERSIST_POLICY, info);
    return SANDBOX_MANAGER_OK;
}

MacParams PolicyInfoManager::GetMacParams(uint32_t tokenId, uint64_t policyFlag, uint64_t timestamp)
{
    MacParams macParams;
    macParams.tokenId = tokenId;
    macParams.policyFlag = policyFlag;
    macParams.timestamp = timestamp;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(macParams.userId);
    if (ret != 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "get user id failed error=%{public}d", ret);
        macParams.userId = 0; // set default userId
    }
    return macParams;
}

int32_t PolicyInfoManager::SetPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy, uint64_t policyFlag,
                                     std::vector<uint32_t> &result, uint64_t timestamp)
{
    size_t policySize = policy.size();
    if (!macAdapter_.IsMacSupport()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Mac not enable, default success.");
        result.resize(policySize, SandboxRetType::OPERATE_SUCCESSFULLY);
        return SANDBOX_MANAGER_OK;
    }
    result.resize(policySize, INVALID_PATH);
    std::vector<size_t> validIndex;
    std::vector<PolicyInfo> validPolicies;
    uint32_t invalidNum = 0;
    uint32_t failNum = 0;
    uint32_t successNum = 0;
    for (size_t index = 0; index < policySize; ++index) {
        int32_t res = CheckPolicyValidity(policy[index]);
        if (res == SANDBOX_MANAGER_OK) {
            validIndex.emplace_back(index);
            validPolicies.emplace_back(policy[index]);
        } else {
            result[index] = static_cast<uint32_t>(res);
            ++invalidNum;
        }
    }

    if (validPolicies.empty()) {
        SANDBOXMANAGER_LOG_WARN(LABEL, "No valid policy to set.");
        PolicyOperateInfo info(policySize, successNum, failNum, invalidNum);
        SandboxManagerDfxHelper::WriteTempPolicyOperateSucc(OperateTypeEnum::SET_POLICY, info);
        return SANDBOX_MANAGER_OK;
    }

    std::vector<uint32_t> setResult(validPolicies.size(), SANDBOX_MANAGER_OK);
    MacParams macParams = GetMacParams(tokenId, policyFlag, timestamp);
    int32_t ret = macAdapter_.SetSandboxPolicy(validPolicies, setResult, macParams);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Set sandbox policy failed, error=%{public}d.", ret);
        PolicyOperateInfo info(policySize, successNum, failNum, invalidNum);
        SandboxManagerDfxHelper::WriteTempPolicyOperateSucc(OperateTypeEnum::SET_POLICY, info);
        result.clear();
        return ret;
    }
    size_t resultIndex = 0;
    for (const auto &index : validIndex) {
        result[index] = setResult[resultIndex++];
    }
    successNum = static_cast<uint32_t>(std::count(setResult.begin(), setResult.end(), SANDBOX_MANAGER_OK));
    failNum = validPolicies.size() - successNum;
    PolicyOperateInfo info(policySize, successNum, failNum, invalidNum);
    SandboxManagerDfxHelper::WriteTempPolicyOperateSucc(OperateTypeEnum::SET_POLICY, info);
    return SANDBOX_MANAGER_OK;
}

int32_t PolicyInfoManager::UnSetPolicy(uint32_t tokenId, const PolicyInfo &policy)
{
    if (!macAdapter_.IsMacSupport()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Mac not enable, default success.");
        return SANDBOX_MANAGER_OK;
    }
    int32_t ret = macAdapter_.UnSetSandboxPolicy(tokenId, policy);
    if (ret != SANDBOX_MANAGER_OK) {
        PolicyOperateInfo info(1, 0, 1, 0);
        SandboxManagerDfxHelper::WriteTempPolicyOperateSucc(OperateTypeEnum::UNSET_POLICY, info);
    }
    PolicyOperateInfo info(1, 1, 0, 0);
    SandboxManagerDfxHelper::WriteTempPolicyOperateSucc(OperateTypeEnum::UNSET_POLICY, info);
    return ret;
}

int32_t PolicyInfoManager::CheckPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                       std::vector<bool> &result)
{
    if (!macAdapter_.IsMacSupport()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Mac not enable, default success.");
        result.resize(policy.size(), true);
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
    int32_t ret = SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY,
        conditions);
    if (ret != SandboxManagerRdb::SUCCESS) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Database operate error");
        return false;
    }
    PolicyOperateInfo info(0, 0, 0, 0);
    info.callerTokenid = tokenId;
    SandboxManagerDfxHelper::WritePersistPolicyOperateSucc(OperateTypeEnum::REMOVE_BUNDLE_POLICY_BY_EVENT, info);
    return true;
}

int32_t PolicyInfoManager::StartAccessingByTokenId(const uint32_t tokenId, uint64_t timestamp)
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
        PolicyOperateInfo info(0, 0, 0, 0);
        SandboxManagerDfxHelper::WritePersistPolicyOperateSucc(OperateTypeEnum::START_ACCESSING_POLICY_BY_TOKEN, info);
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
    MacParams macParams = GetMacParams(tokenId, 0, timestamp);
    ret = macAdapter_.SetSandboxPolicy(policys, macResults, macParams);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "MacAdapter set policy error, err code = %{public}d.", ret);
        return ret;
    }
    uint32_t successNum = static_cast<uint32_t>(std::count(macResults.begin(), macResults.end(), SANDBOX_MANAGER_OK));
    if (searchSize >= successNum) {
        PolicyOperateInfo info(searchSize, successNum, searchSize - successNum, 0);
        SandboxManagerDfxHelper::WritePersistPolicyOperateSucc(OperateTypeEnum::START_ACCESSING_POLICY_BY_TOKEN, info);
    }
    return SANDBOX_MANAGER_OK;
}

int32_t PolicyInfoManager::StartAccessingPolicy(
    const uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &results, uint64_t timestamp)
{
    if (!macAdapter_.IsMacSupport()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Mac not enable, default success.");
        results.resize(policy.size(), SandboxRetType::OPERATE_SUCCESSFULLY);
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
    uint32_t invalidNum = 0;
    for (size_t i = 0; i < policySize; ++i) {
        if (matchResults[i] == SandboxRetType::OPERATE_SUCCESSFULLY) {
            accessingIndex.emplace_back(i);
        } else {
            results[i] = matchResults[i];
            ++invalidNum;
        }
    }
    size_t accessingIndexSize = accessingIndex.size();
    std::vector<PolicyInfo> accessingPolicy(accessingIndexSize);
    std::transform(accessingIndex.begin(), accessingIndex.end(),
        accessingPolicy.begin(), [policy](size_t index) { return policy[index]; });
    std::vector<uint32_t> macResults(accessingIndexSize);
    MacParams macParams = GetMacParams(tokenId, 0, timestamp);
    ret = macAdapter_.SetSandboxPolicy(accessingPolicy, macResults, macParams);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "MacAdapter set policy error, err code = %{public}d.", ret);
        results.clear();
        return ret;
    }
    // write ok flag
    uint32_t successNum = 0;
    for (size_t i = 0; i < accessingIndexSize; ++i) {
        if (macResults[i] == SANDBOX_MANAGER_OK) {
            results[accessingIndex[i]] = SandboxRetType::OPERATE_SUCCESSFULLY;
            ++successNum;
        } else {
            results[accessingIndex[i]] = SandboxRetType::POLICY_MAC_FAIL;
        }
    }
    PolicyOperateInfo info(policySize, successNum, accessingIndexSize - successNum, invalidNum);
    SandboxManagerDfxHelper::WritePersistPolicyOperateSucc(OperateTypeEnum::START_ACCESSING_POLICY, info);
    return SANDBOX_MANAGER_OK;
}

int32_t PolicyInfoManager::StopAccessingPolicy(
    const uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &results)
{
    if (!macAdapter_.IsMacSupport()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Mac not enable, default success.");
        results.resize(policy.size(), SandboxRetType::OPERATE_SUCCESSFULLY);
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
    uint32_t invalidNum = 0;
    for (size_t i = 0; i < policySize; ++i) {
        if (matchResults[i] == SandboxRetType::OPERATE_SUCCESSFULLY) {
            accessingIndex.emplace_back(i);
        } else {
            results[i] = matchResults[i];
            ++invalidNum;
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
    uint32_t successNum = 0;
    for (size_t i = 0; i < accessingIndexSize; ++i) {
        if (macResults[i]) {
            results[accessingIndex[i]] = SandboxRetType::OPERATE_SUCCESSFULLY;
            ++successNum;
        } else {
            results[accessingIndex[i]] = SandboxRetType::POLICY_MAC_FAIL;
        }
    }
    PolicyOperateInfo info(policySize, successNum, accessingIndexSize - successNum, invalidNum);
    SandboxManagerDfxHelper::WritePersistPolicyOperateSucc(OperateTypeEnum::STOP_ACCESSING_POLICY, info);
    return SANDBOX_MANAGER_OK;
}

int32_t PolicyInfoManager::UnSetAllPolicyByToken(const uint32_t tokenId, uint64_t timestamp)
{
    if (!macAdapter_.IsMacSupport()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Mac not enable, default success.");
        return SANDBOX_MANAGER_OK;
    }
    PolicyOperateInfo info(0, 0, 0, 0);
    info.callerTokenid = tokenId;
    SandboxManagerDfxHelper::WritePersistPolicyOperateSucc(OperateTypeEnum::UNSET_ALL_POLICY_BY_TOKEN, info);
    return macAdapter_.DestroySandboxPolicy(tokenId, timestamp);
}

int32_t PolicyInfoManager::RangeFind(const GenericValues &conditions, const GenericValues &symbols,
    std::vector<GenericValues> &results)
{
    int32_t ret = SandboxManagerRdb::GetInstance().Find(SANDBOX_MANAGER_PERSISTED_POLICY,
        conditions, symbols, results);
    if (ret != SandboxManagerRdb::SUCCESS) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Database operate error");
        return SANDBOX_MANAGER_DB_ERR;
    }
    if (results.empty()) {
        SANDBOXMANAGER_LOG_DEBUG(LABEL, "Database return empty");
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
    int32_t ret = SandboxManagerRdb::GetInstance().Find(SANDBOX_MANAGER_PERSISTED_POLICY,
        conditions, symbols, searchResults);
    if (ret != SandboxManagerRdb::SUCCESS) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Database operate error");
        return SANDBOX_MANAGER_DB_ERR;
    }
    if (searchResults.empty()) {
        SANDBOXMANAGER_LOG_DEBUG(LABEL, "Database return empty");
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
    if (inputPath.empty()) {
        return 0;
    }
    // if path end with '/', depth -1
    if (inputPath.back() == '/') {
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
    if (path.empty()) {
        return path;
    }
    // delete '/' at the end of string
    std::string retPath = path;
    if (retPath.back() == '/') {
        retPath.pop_back();
    }
    return retPath;
}

int32_t PolicyInfoManager::CheckPolicyValidity(const PolicyInfo &policy)
{
    // path not empty and lenth < POLICY_PATH_LIMIT
    uint32_t length = policy.path.length();
    if (length == 0 || length > POLICY_PATH_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Policy path check fail, length = %{public}zu", policy.path.length());
        return SandboxRetType::INVALID_PATH;
    }
    std::string path = AdjustPath(policy.path);

    // mode between 0 and 0b11(READ_MODE+WRITE_MODE)
    if (policy.mode < OperateMode::READ_MODE ||
        policy.mode > OperateMode::READ_MODE + OperateMode::WRITE_MODE) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Policy mode check fail: %{public}" PRIu64, policy.mode);
        return SandboxRetType::INVALID_MODE;
    }
    return SANDBOX_MANAGER_OK;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS