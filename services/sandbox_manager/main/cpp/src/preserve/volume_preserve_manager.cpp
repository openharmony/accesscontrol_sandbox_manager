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

#include "volume_preserve_manager.h"

#include <chrono>
#include "accesstoken_kit.h"
#include "hap_token_info.h"
#include "os_account_manager.h"
#include "policy_field_const.h"
#include "policy_info_manager.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"
#include "sandbox_manager_rdb.h"
#include "sandbox_param_validator.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "VolumePreserveManager"
};

struct VolumePrefixEntry {
    VolumeType type;
    const char *prefix;
};

const VolumePrefixEntry VOLUME_PREFIXES[] = {
    {VolumeType::EXTERNAL, "/storage/External/"},
    {VolumeType::VOLDATA,  "/storage/voldata/"},
};

void GenericToPolicy(const GenericValues &generic, uint32_t &tokenId, PolicyInfo &policy)
{
    policy.path = generic.GetString(PolicyFiledConst::FIELD_PATH);
    policy.mode = static_cast<uint64_t>(generic.GetInt(PolicyFiledConst::FIELD_MODE));
    tokenId = static_cast<uint32_t>(generic.GetInt(PolicyFiledConst::FIELD_TOKENID));
}
} // namespace

VolumePreserveManager &VolumePreserveManager::GetInstance()
{
    static VolumePreserveManager instance;
    return instance;
}

void VolumePreserveManager::SetAgingTtlMs(int64_t ttlMs)
{
    agingTtlMs_ = ttlMs;
}

int64_t VolumePreserveManager::CurrentTimeMs()
{
    return static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

bool VolumePreserveManager::MatchVolumePrefix(const std::string &path, std::string &suffixOut)
{
    for (const auto &entry : VOLUME_PREFIXES) {
        std::string prefix(entry.prefix);
        if (path.find(prefix) == 0) {
            suffixOut = path.substr(prefix.length());
            return true;
        }
    }
    return false;
}

bool VolumePreserveManager::ValidatePath(const std::string &path, std::string &adjustedOut)
{
    if (path.empty()) {
        return false;
    }
    adjustedOut = path;
    if (adjustedOut.back() == '/') {
        adjustedOut.pop_back();
    }
    if (SandboxParamValidator::ValidateGenericPath(adjustedOut) != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Path failed generic validation");
        return false;
    }
    std::string suffix;
    if (!MatchVolumePrefix(adjustedOut, suffix)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Path must start with a valid volume prefix");
        return false;
    }
    if (suffix.empty()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Path must be at least 3 layers: /storage/<type>/uuid");
        return false;
    }
    return true;
}

void VolumePreserveManager::BuildRecordConditions(
    const GenericValues &record, GenericValues &conditions)
{
    conditions.Put(PolicyFiledConst::FIELD_TOKENID, record.GetInt(PolicyFiledConst::FIELD_TOKENID));
    conditions.Put(PolicyFiledConst::FIELD_PATH, record.GetString(PolicyFiledConst::FIELD_PATH));
    conditions.Put(PolicyFiledConst::FIELD_MODE, record.GetInt(PolicyFiledConst::FIELD_MODE));
    conditions.Put(PolicyFiledConst::FIELD_DEPTH, record.GetInt(PolicyFiledConst::FIELD_DEPTH));
}

int32_t VolumePreserveManager::QuerySubPathRecords(
    const std::string &path, std::vector<GenericValues> &results)
{
    int32_t ret = SandboxManagerRdb::GetInstance().FindSubPathIgnoreCase(
        SANDBOX_MANAGER_PERSISTED_POLICY, path, results);
    if (ret != SandboxManagerRdb::SUCCESS) {
        LOGE_WITH_REPORT(LABEL, "FindSubPathIgnoreCase failed, ret=%{public}d", ret);
        return SANDBOX_MANAGER_DB_ERR;
    }
    return SANDBOX_MANAGER_OK;
}

int32_t VolumePreserveManager::UnsetMacPolicy(uint32_t tokenId, const PolicyInfo &policy)
{
    return PolicyInfoManager::GetInstance().UnSetPolicy(tokenId, policy);
}

int32_t VolumePreserveManager::ActivateMacPolicy(
    uint32_t tokenId, const PolicyInfo &policy, int32_t userId)
{
    SetInfo setInfo;
    setInfo.userId = userId;
    std::vector<PolicyInfo> policies = {policy};
    std::vector<uint32_t> results;
    return PolicyInfoManager::GetInstance().SetPolicy(
        tokenId, policies, 1, results, setInfo);
}

void VolumePreserveManager::CleanMacPolicyByPath(const std::string &adjustedPath)
{
    int32_t userId = -1;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        LOGE_WITH_REPORT(LABEL, "CleanMacPolicyByPath get user id failed error=%{public}d", ret);
        return;
    }
    std::vector<std::string> filePathList = {adjustedPath};
    PolicyInfoManager::GetInstance().CleanPolicyOnMac(filePathList, userId);
}

int32_t VolumePreserveManager::DeactiveRecords(
    const std::vector<GenericValues> &records, int64_t now)
{
    bool hasError = false;
    for (const auto &record : records) {
        GenericValues modifyValues;
        modifyValues.Put(PolicyFiledConst::FIELD_VOLUME_UNMOUNT_TS, now);
        GenericValues conditions;
        BuildRecordConditions(record, conditions);
        int32_t ret = SandboxManagerRdb::GetInstance().Modify(
            SANDBOX_MANAGER_PERSISTED_POLICY, modifyValues, conditions);
        if (ret != SandboxManagerRdb::SUCCESS) {
            LOGE_WITH_REPORT(LABEL, "Modify volumeUnmountTs failed, ret=%{public}d", ret);
            hasError = true;
            continue;
        }
        uint32_t tokenId = 0;
        PolicyInfo policy;
        GenericToPolicy(record, tokenId, policy);
        int32_t macRet = UnsetMacPolicy(tokenId, policy);
        if (macRet != SANDBOX_MANAGER_OK) {
            LOGE_WITH_REPORT(LABEL,
                "UnSetSandboxPolicy failed, tokenId=%{public}u, ret=%{public}d", tokenId, macRet);
        }
    }
    return hasError ? SANDBOX_MANAGER_DB_ERR : SANDBOX_MANAGER_OK;
}

int32_t VolumePreserveManager::DeleteExpiredRecords(int64_t now)
{
    int64_t expiryThreshold = now - agingTtlMs_;
    std::vector<GenericValues> expired;
    int32_t ret = SandboxManagerRdb::GetInstance().FindExpiredVolumeRecords(expiryThreshold, expired);
    if (ret != SandboxManagerRdb::SUCCESS) {
        LOGE_WITH_REPORT(LABEL, "Aging scan FindExpiredVolumeRecords failed, ret=%{public}d", ret);
        return SANDBOX_MANAGER_DB_ERR;
    }
    if (expired.empty()) {
        return SANDBOX_MANAGER_OK;
    }
    ret = SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_PERSISTED_POLICY, expired);
    if (ret != SandboxManagerRdb::SUCCESS) {
        LOGE_WITH_REPORT(LABEL, "Aging scan Remove failed, ret=%{public}d", ret);
        return SANDBOX_MANAGER_DB_ERR;
    }
    SANDBOXMANAGER_LOG_INFO(LABEL, "Aging scan: deleted %{public}zu expired records", expired.size());
    return SANDBOX_MANAGER_OK;
}

void VolumePreserveManager::FilterRestorableRecords(
    std::vector<GenericValues> &records, int64_t now)
{
    std::vector<GenericValues> filtered;
    for (const auto &record : records) {
        int64_t ts = record.GetInt64(PolicyFiledConst::FIELD_VOLUME_UNMOUNT_TS);
        if (ts > 0 && (now - ts) <= agingTtlMs_) {
            filtered.emplace_back(record);
        }
    }
    records.swap(filtered);
}

int32_t VolumePreserveManager::ActivateRecords(const std::vector<GenericValues> &records)
{
    bool hasError = false;
    for (const auto &record : records) {
        uint32_t tokenId = 0;
        PolicyInfo policy;
        GenericToPolicy(record, tokenId, policy);
        int32_t userId = -1;
        Security::AccessToken::HapTokenInfo hapTokenInfoRes;
        int tokenRet = Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapTokenInfoRes);
        if (tokenRet == 0) {
            userId = hapTokenInfoRes.userID;
        }
        int32_t macRet = ActivateMacPolicy(tokenId, policy, userId);
        if (macRet != SANDBOX_MANAGER_OK) {
            LOGE_WITH_REPORT(LABEL,
                "ActivateMacPolicy failed, tokenId=%{public}u, ret=%{public}d", tokenId, macRet);
            hasError = true;
            continue;
        }
        GenericValues modifyValues;
        modifyValues.Put(PolicyFiledConst::FIELD_VOLUME_UNMOUNT_TS, static_cast<int64_t>(0));
        GenericValues conditions;
        BuildRecordConditions(record, conditions);
        int32_t ret = SandboxManagerRdb::GetInstance().Modify(
            SANDBOX_MANAGER_PERSISTED_POLICY, modifyValues, conditions);
        if (ret != SandboxManagerRdb::SUCCESS) {
            LOGE_WITH_REPORT(LABEL, "Clear volumeUnmountTs failed, ret=%{public}d", ret);
            hasError = true;
        }
    }
    return hasError ? SANDBOX_MANAGER_DB_ERR : SANDBOX_MANAGER_OK;
}

int32_t VolumePreserveManager::DeactivePolicyByPath(const std::string &volumeMountPath)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "DeactivePolicyByPath called, path=%{public}s", volumeMountPath.c_str());
    std::string adjustedPath;
    if (!ValidatePath(volumeMountPath, adjustedPath)) {
        return INVALID_PARAMTER;
    }
    std::vector<GenericValues> dbResults;
    int32_t ret = QuerySubPathRecords(adjustedPath, dbResults);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    if (dbResults.empty()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "No policies found for path=%{public}s", adjustedPath.c_str());
        return SANDBOX_MANAGER_OK;
    }
    int64_t now = CurrentTimeMs();
    ret = DeactiveRecords(dbResults, now);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "DeactiveRecords has errors, but continued processing all records");
    }
    CleanMacPolicyByPath(adjustedPath);
    SANDBOXMANAGER_LOG_INFO(LABEL, "DeactivePolicyByPath success, count=%{public}zu", dbResults.size());
    return SANDBOX_MANAGER_OK;
}

int32_t VolumePreserveManager::ActivePolicyByPath(const std::string &volumeMountPath)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "ActivePolicyByPath called, path=%{public}s", volumeMountPath.c_str());
    std::string adjustedPath;
    if (!ValidatePath(volumeMountPath, adjustedPath)) {
        return INVALID_PARAMTER;
    }
    int64_t now = CurrentTimeMs();
    int32_t ret = DeleteExpiredRecords(now);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    std::vector<GenericValues> dbResults;
    ret = QuerySubPathRecords(adjustedPath, dbResults);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    FilterRestorableRecords(dbResults, now);
    if (dbResults.empty()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "No policies to restore for path=%{public}s", adjustedPath.c_str());
        return SANDBOX_MANAGER_OK;
    }
    ret = ActivateRecords(dbResults);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "ActivateRecords has errors, but continued processing all records");
    }
    SANDBOXMANAGER_LOG_INFO(LABEL, "ActivePolicyByPath success, count=%{public}zu", dbResults.size());
    return SANDBOX_MANAGER_OK;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
