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

#include "persistent_preserve.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "media_path_support.h"
#include "policy_info.h"
#include "sandbox_manager_const.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"
#include "sandbox_manager_rdb.h"
#include "system_ability_definition.h"
#include "generic_values.h"
#include "policy_field_const.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "PersistentPreserve"
};

int32_t PersistentPreserve::GetPersistedPoliciesByTokenId(const uint32_t tokenId,
    std::vector<GenericValues> &policies)
{
    GenericValues conditions;
    conditions.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int32_t>(tokenId));

    GenericValues symbols;
    symbols.Put(PolicyFiledConst::FIELD_TOKENID, std::string("="));

    int32_t ret = SandboxManagerRdb::GetInstance().Find(
        SANDBOX_MANAGER_PERSISTED_POLICY, conditions, symbols, policies);
    if (ret != SandboxManagerRdb::SUCCESS) {
        LOGE_WITH_REPORT(LABEL, "GetPersistedPoliciesByTokenId failed for token=%{public}u", tokenId);
        return SANDBOX_MANAGER_DB_ERR;
    }
    return SANDBOX_MANAGER_OK;
}

int32_t PersistentPreserve::SaveBundlePersistentPolicies(const std::string &bundleName, int32_t userId,
    const std::string &appIdentifier, uint32_t tokenId)
{
    if (appIdentifier.empty()) {
        LOGE_WITH_REPORT(LABEL, "SaveBundlePersistentPolicies: appIdentifier is empty");
        return INVALID_PARAMTER;
    }

    // Reserve media policies (failure does not affect the main persistence flow)
    (void)SandboxManagerMedia::GetInstance().ReserveMediaPoliciesOnRemove(appIdentifier, bundleName, tokenId);

    // Delete existing records to avoid duplicates
    DeleteBundlePersistentPolicies(appIdentifier, userId);

    std::vector<GenericValues> bundlePolicies;
    int64_t timestamp = static_cast<int64_t>(time(nullptr));
    SANDBOXMANAGER_LOG_INFO(LABEL, "SaveBundlePersistentPolicies: appIdentifier=%{public}s", appIdentifier.c_str());
    GenericValues bundlePolicy;
    bundlePolicy.Put(PolicyFiledConst::FIELD_BUNDLENAME, bundleName);
    bundlePolicy.Put(PolicyFiledConst::FIELD_USERID, userId);
    bundlePolicy.Put(PolicyFiledConst::FIELD_APPIDENTIFIER, appIdentifier);
    bundlePolicy.Put(PolicyFiledConst::FIELD_ORIGINAL_TOKENID, static_cast<int32_t>(tokenId));
    bundlePolicy.Put(PolicyFiledConst::FIELD_TIMESTAMP, static_cast<int64_t>(timestamp));
    bundlePolicies.push_back(bundlePolicy);

    int32_t ret = SandboxManagerRdb::GetInstance().Add(
        SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY, bundlePolicies);
    if (ret != SandboxManagerRdb::SUCCESS) {
        LOGE_WITH_REPORT(LABEL, "SaveBundlePersistentPolicies: failed to save policies for %{public}s",
            bundleName.c_str());
        return SANDBOX_MANAGER_DB_ERR;
    }

    SANDBOXMANAGER_LOG_INFO(LABEL, "SaveBundlePersistentPolicies finish");
    return SANDBOX_MANAGER_OK;
}

int32_t PersistentPreserve::RestoreBundlePersistentPolicies(const std::string &appIdentifier, int32_t userId,
    uint32_t newTokenId, const std::string &bundleName)
{
    if (appIdentifier.empty()) {
        LOGE_WITH_REPORT(LABEL, "RestorePersistent: appIdentifier is empty");
        return INVALID_PARAMTER;
    }

    // Resume media policies (failure does not affect the main restore flow)
    (void)SandboxManagerMedia::GetInstance().ResumeMediaPoliciesOnAdd(appIdentifier, bundleName, newTokenId);

    GenericValues bundleRecord;
    int32_t ret = FindBundleRecord(appIdentifier, userId, bundleRecord);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }

    if (bundleRecord.GetAllKeys().empty()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "RestorePersistent: no bundle record found %{public}s", appIdentifier.c_str());
        return SANDBOX_MANAGER_OK;
    }

    uint32_t originalTokenId = static_cast<uint32_t>(bundleRecord.GetInt(PolicyFiledConst::FIELD_ORIGINAL_TOKENID));

    std::vector<GenericValues> persistedPolicies;
    ret = GetPersistedPoliciesByTokenId(originalTokenId, persistedPolicies);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "RestorePersistent: get policies failed for token=%{public}u", originalTokenId);
        return ret;
    }

    if (persistedPolicies.empty()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "RestorePersistent: no persisted policies to restore");
        return SANDBOX_MANAGER_OK;
    }

    GenericValues modifyValues;
    modifyValues.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int32_t>(newTokenId));

    GenericValues conditions;
    conditions.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int32_t>(originalTokenId));

    ret = SandboxManagerRdb::GetInstance().Modify(SANDBOX_MANAGER_PERSISTED_POLICY, modifyValues, conditions);
    if (ret != SandboxManagerRdb::SUCCESS) {
        LOGE_WITH_REPORT(LABEL, "RestorePersistent: failed to update tokenId for token=%{public}u", originalTokenId);
        return SANDBOX_MANAGER_DB_ERR;
    }

    SANDBOXMANAGER_LOG_INFO(LABEL, "RestorePersistent: restored %{public}zu policies", persistedPolicies.size());
    return SANDBOX_MANAGER_OK;
}

int32_t PersistentPreserve::DeleteBundlePersistentPolicies(const std::string &appIdentifier, int32_t userId)
{
    if (appIdentifier.empty()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "DeleteBundlePersistentPolicies: appIdentifier is empty");
        return INVALID_PARAMTER;
    }

    GenericValues conditions;
    conditions.Put(PolicyFiledConst::FIELD_APPIDENTIFIER, appIdentifier);
    conditions.Put(PolicyFiledConst::FIELD_USERID, userId);

    int32_t ret = SandboxManagerRdb::GetInstance().Remove(
        SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY, conditions);
    if (ret != SandboxManagerRdb::SUCCESS) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "DeleteBundlePersistentPolicies: failed to delete policies for %{public}s",
            appIdentifier.c_str());
        return SANDBOX_MANAGER_DB_ERR;
    }

    SANDBOXMANAGER_LOG_INFO(LABEL, "DeleteBundlePersistentPolicies for %{public}s", appIdentifier.c_str());
    return SANDBOX_MANAGER_OK;
}

int32_t PersistentPreserve::FindBundleRecord(const std::string &appIdentifier, int32_t userId,
    GenericValues &bundleRecord)
{
    std::vector<GenericValues> bundleRecords;
    int32_t ret = FetchBundleRecordsByIdentifier(appIdentifier, userId, bundleRecords);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }

    if (bundleRecords.empty()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "FindBundleRecord: no bundle record found for %{public}s",
            appIdentifier.c_str());
        return SANDBOX_MANAGER_OK;
    }

    if (bundleRecords.size() == 1) {
        bundleRecord = bundleRecords[0];
        return SANDBOX_MANAGER_OK;
    }

    // Multiple records found, use latest and delete old ones
    return HandleDuplicateBundleRecords(appIdentifier, userId, bundleRecords, bundleRecord);
}

int32_t PersistentPreserve::FetchBundleRecordsByIdentifier(const std::string &appIdentifier, int32_t userId,
    std::vector<GenericValues> &bundleRecords)
{
    GenericValues bundleConditions;
    bundleConditions.Put(PolicyFiledConst::FIELD_APPIDENTIFIER, appIdentifier);
    bundleConditions.Put(PolicyFiledConst::FIELD_USERID, userId);

    GenericValues bundleSymbols;
    bundleSymbols.Put(PolicyFiledConst::FIELD_APPIDENTIFIER, std::string("="));
    bundleSymbols.Put(PolicyFiledConst::FIELD_USERID, std::string("="));

    int32_t ret = SandboxManagerRdb::GetInstance().Find(
        SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY, bundleConditions, bundleSymbols, bundleRecords);
    if (ret != SandboxManagerRdb::SUCCESS) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "FetchBundleRecordsByIdentifier: failed to find bundle record for %{public}s",
            appIdentifier.c_str());
        return SANDBOX_MANAGER_DB_ERR;
    }
    return SANDBOX_MANAGER_OK;
}

int32_t PersistentPreserve::HandleDuplicateBundleRecords(const std::string &appIdentifier, int32_t userId,
    const std::vector<GenericValues> &bundleRecords, GenericValues &bundleRecord)
{
    LOGE_WITH_REPORT(LABEL, "HandleDuplicateBundleRecords: found %{public}zu duplicate records for %{public}s",
        bundleRecords.size(), appIdentifier.c_str());

    // Find the record with latest timestamp
    size_t latestIndex = 0;
    int64_t latestTimestamp = bundleRecords[0].GetInt64(PolicyFiledConst::FIELD_TIMESTAMP);
    for (size_t i = 1; i < bundleRecords.size(); i++) {
        int64_t timestamp = bundleRecords[i].GetInt64(PolicyFiledConst::FIELD_TIMESTAMP);
        if (timestamp > latestTimestamp) {
            latestTimestamp = timestamp;
            latestIndex = i;
        }
    }

    bundleRecord = bundleRecords[latestIndex];
    std::string bundleName = bundleRecord.GetString(PolicyFiledConst::FIELD_BUNDLENAME);

    // Delete old records (except the latest one)
    for (size_t i = 0; i < bundleRecords.size(); i++) {
        if (i != latestIndex) {
            GenericValues deleteConditions;
            deleteConditions.Put(PolicyFiledConst::FIELD_APPIDENTIFIER, appIdentifier);
            deleteConditions.Put(PolicyFiledConst::FIELD_USERID, userId);
            deleteConditions.Put(PolicyFiledConst::FIELD_ORIGINAL_TOKENID,
                bundleRecords[i].GetInt(PolicyFiledConst::FIELD_ORIGINAL_TOKENID));
            SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_BUNDLE_PERSISTENT_POLICY, deleteConditions);
        }
    }

    SANDBOXMANAGER_LOG_INFO(LABEL, "using latest record for %{public}s, bundleName=%{public}s, timestamp=%{public}lld",
        appIdentifier.c_str(), bundleName.c_str(), static_cast<long long>(latestTimestamp));
    return SANDBOX_MANAGER_OK;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
