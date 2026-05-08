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

#include "sandbox_stats_reporter.h"
#include "sandbox_manager_log.h"
#include "sandbox_manager_rdb.h"
#include "sandbox_manager_err_code.h"
#include "accesstoken_kit.h"
#include "hap_token_info.h"
#include "hisysevent.h"
#include <cinttypes>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>

#define TOKENID_MASK 0xFFFFFFFF

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

SandboxStatsReporter::SandboxStatsReporter()
    : lastReportTime_(std::chrono::steady_clock::time_point{})
{
    macAdapter_.Init(false);
}

SandboxStatsReporter::~SandboxStatsReporter() = default;

std::string SandboxStatsReporter::GetBundleNameByTokenId(uint32_t tokenId)
{
    Security::AccessToken::HapTokenInfo hapTokenInfoRes;
    int ret = Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapTokenInfoRes);
    if (ret != 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to get HapTokenInfo, tokenId: %{public}u, ret:%{public}d",
            tokenId, ret);
        return "not_get";
    }
    return hapTokenInfoRes.bundleName;
}

int32_t SandboxStatsReporter::GetAppWithMostTempAuth(std::string &bundleName, uint32_t &tokenId, int32_t &count)
{
    uint64_t tokenId64 = 0;
    int32_t ret = macAdapter_.GetMaxAuthTokenId(tokenId64, count);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to get max auth tokenId, ret:%{public}d", ret);
        return ret;
    }

    tokenId = static_cast<uint32_t>(tokenId64 & TOKENID_MASK);
    if (tokenId != 0) {
        bundleName = GetBundleNameByTokenId(tokenId);
    } else {
        bundleName = "global";
    }
    if (bundleName == "not_get") {
        return INVALID_PARAMTER;
    }

    return SANDBOX_MANAGER_OK;
}

bool SandboxStatsReporter::ShouldReport()
{
    // First time: lastReportTime_ is zero, always report
    if (lastReportTime_.time_since_epoch().count() == 0) {
        return true;
    }
    
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastReportTime_).count();
    return elapsed >= REPORT_INTERVAL_SECONDS;
}

void SandboxStatsReporter::ReportInternal()
{
    SandboxStatsData statsData = ParseStats();
    uint64_t pathTreeNodeNumObjs = GetPathTreeNodeNumObjs(statsData);
    int32_t recordCount = GetPersistRecordCount();

    uint32_t persistTokenId = 0;
    uint32_t topPersistRuleNum = 0;
    std::string persistBundleName = "not_get";
    GetTopPersistApp(persistTokenId, topPersistRuleNum, persistBundleName);

    std::string bundleName;
    int32_t topTempRuleNum = 0;
    uint32_t tokenId = 0;
    GetTopTempApp(bundleName, tokenId, topTempRuleNum);

    WriteAuthorizationStatEvent(statsData, pathTreeNodeNumObjs, recordCount, tokenId, bundleName, topTempRuleNum,
        persistTokenId, persistBundleName, topPersistRuleNum);
}

uint64_t SandboxStatsReporter::GetPathTreeNodeNumObjs(const SandboxStatsData &statsData) const
{
    for (const auto &field : statsData.fieldStats) {
        if (field.name == "path_tree_node") {
            return field.numObjs;
        }
    }
    return 0;
}

int32_t SandboxStatsReporter::GetPersistRecordCount()
{
    int32_t recordCount = 0;
    int32_t recordRet = SandboxManagerRdb::GetInstance().GetRecordCount(
        DataType::SANDBOX_MANAGER_PERSISTED_POLICY, recordCount);
    if (recordRet != SandboxManagerRdb::SUCCESS) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to get persist policy record count, ret:%{public}d", recordRet);
    }
    return recordCount;
}

void SandboxStatsReporter::GetTopPersistApp(uint32_t &persistTokenId, uint32_t &topPersistRuleNum,
    std::string &persistBundleName)
{
    int32_t tokenIdRet = SandboxManagerRdb::GetInstance().GetTokenIdWithMostRecords(
        DataType::SANDBOX_MANAGER_PERSISTED_POLICY, persistTokenId, topPersistRuleNum);
    if (tokenIdRet != SandboxManagerRdb::SUCCESS || persistTokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to get tokenId with most persist policy records, ret:%{public}d",
            tokenIdRet);
    }
    if (persistTokenId != 0) {
        persistBundleName = GetBundleNameByTokenId(persistTokenId);
    }
}

void SandboxStatsReporter::GetTopTempApp(std::string &bundleName, uint32_t &tokenId, int32_t &topTempRuleNum)
{
    int32_t tempAuthRet = GetAppWithMostTempAuth(bundleName, tokenId, topTempRuleNum);
    if (tempAuthRet != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to get app with most temporary auth, ret:%{public}d",
            tempAuthRet);
    }
}

void SandboxStatsReporter::WriteAuthorizationStatEvent(const SandboxStatsData &statsData,
    uint64_t pathTreeNodeNumObjs, int32_t recordCount, uint32_t tokenId, const std::string &bundleName,
    int32_t topTempRuleNum, uint32_t persistTokenId, const std::string &persistBundleName,
    uint32_t topPersistRuleNum)
{
    SANDBOXMANAGER_LOG_INFO(LABEL,
        "=== Sandbox Statistics Report === "
        "TotalMemory: %{public}" PRIu64 " bytes, path_tree_node num_objs: %{public}" PRIu64 ", "
        "TokenId: %{public}u, BundleName: %{public}s, "
        "PersistTokenId: %{public}u, PersistBundleName: %{public}s, "
        "DbRecordCount: %{public}d",
        statsData.totalMemoryBytes, pathTreeNodeNumObjs,
        tokenId, bundleName.c_str(),
        persistTokenId, persistBundleName.c_str(),
        recordCount);

    int reportRet = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::SANDBOX_MANAGER, "AUTHORIZATION_STAT",
        HiviewDFX::HiSysEvent::EventType::STATISTIC, "TEMPORARY_RULE_NUM", pathTreeNodeNumObjs,
        "PERSIST_RULE_NUM", recordCount, "KERNEL_MEMORY_USAGE", statsData.totalMemoryBytes,
        "TOP_TEMP_APP", bundleName.c_str(), "TOP_TEMP_NUM", topTempRuleNum,
        "TOP_PERSIST_APP", persistBundleName.c_str(), "TOP_PERSIST_NUM", topPersistRuleNum);
    if (reportRet != 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Report authorization stat failed, ret=%{public}d", reportRet);
    }
}

void SandboxStatsReporter::Report()
{
    // Lock and check atomically to avoid race condition
    bool shouldReport = false;
    {
        std::lock_guard<std::mutex> lock(reportMutex_);
        shouldReport = ShouldReport();
        if (shouldReport) {
            lastReportTime_ = std::chrono::steady_clock::now();
        }
    }
    
    if (!shouldReport) {
        SANDBOXMANAGER_LOG_DEBUG(LABEL, "Skip report: last report is within 1 hour.");
        return;
    }

    // Async call: start a new thread to avoid blocking the caller
    std::thread(&SandboxStatsReporter::ReportInternal, this).detach();
}

bool SandboxStatsReporter::IsTargetField(const std::string &name) const
{
    // Exact match
    for (const auto &match : EXACT_MATCHES) {
        if (name == match) {
            return true;
        }
    }

    // Prefix match
    for (const auto &prefix : TARGET_PREFIXES) {
        if (name.find(prefix) == 0) {
            return true;
        }
    }

    return false;
}

SandboxStatsData SandboxStatsReporter::ParseStats()
{
    SandboxStatsData statsData;
    
    std::ifstream file(SLABINFO_PATH);
    if (!file.is_open()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to open file: %{public}s", SLABINFO_PATH);
        return statsData;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) {
            continue;
        }

        std::istringstream iss(line);
        std::string name;
        uint64_t activeObjs = 0;
        uint64_t numObjs = 0;
        uint64_t objSize = 0;
        uint64_t objsPerSlab = 0;

        if (!(iss >> name >> activeObjs >> numObjs >> objSize >> objsPerSlab)) {
            continue;
        }

        if (IsTargetField(name)) {
            uint64_t memoryBytes = numObjs * objSize;
            statsData.totalMemoryBytes += memoryBytes;

            FieldStats &fieldStats = statsData.fieldStats.emplace_back();

            SANDBOXMANAGER_LOG_INFO(LABEL, "name=%{public}s, numObjs=%{public}" PRIu64, name.c_str(), numObjs);
            fieldStats.name = name;
            fieldStats.numObjs = numObjs;
            fieldStats.objSize = objSize;
            fieldStats.memoryBytes = memoryBytes;
        }
    }

    SANDBOXMANAGER_LOG_INFO(LABEL, "total=%{public}" PRIu64, statsData.totalMemoryBytes);

    // file.close() omitted - RAII handles it
    return statsData;
}

} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
