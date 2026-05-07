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

#ifndef SANDBOX_STATS_REPORTER_H
#define SANDBOX_STATS_REPORTER_H

#include "singleton.h"
#include "mac_adapter.h"
#include "sandbox_manager_log.h"
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

struct FieldStats {
    std::string name;
    uint64_t numObjs = 0;
    uint64_t objSize = 0;
    uint64_t memoryBytes = 0;
};

struct SandboxStatsData {
    uint64_t totalMemoryBytes = 0;
    std::vector<FieldStats> fieldStats;
};

class SandboxStatsReporter {
    DECLARE_DELAYED_SINGLETON(SandboxStatsReporter);

public:
    void Report();
    std::string GetBundleNameByTokenId(uint32_t tokenId);
    int32_t GetAppWithMostTempAuth(std::string &bundleName, uint32_t &tokenId, int32_t &count);

private:
    bool IsTargetField(const std::string &name) const;
    SandboxStatsData ParseStats();
    bool ShouldReport();
    void ReportInternal();
    uint64_t GetPathTreeNodeNumObjs(const SandboxStatsData &statsData) const;
    int32_t GetPersistRecordCount();
    void GetTopPersistApp(uint32_t &persistTokenId, uint32_t &topPersistRuleNum, std::string &persistBundleName);
    void GetTopTempApp(std::string &bundleName, uint32_t &tokenId, int32_t &topTempRuleNum);
    void WriteAuthorizationStatEvent(const SandboxStatsData &statsData, uint64_t pathTreeNodeNumObjs,
        int32_t recordCount, uint32_t tokenId, const std::string &bundleName, int32_t topTempRuleNum,
        uint32_t persistTokenId, const std::string &persistBundleName, uint32_t topPersistRuleNum);
    inline static const char* SLABINFO_PATH = "/proc/slabinfo";
    inline static const std::vector<std::string> TARGET_PREFIXES = {"dec_str", "dec_common"};
    inline static const std::vector<std::string> EXACT_MATCHES = {"path_tree_node", "dec_permission"};
    static constexpr int64_t REPORT_INTERVAL_SECONDS = 1 * 60 * 60; // 1 hour
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
        LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxStatsReporter"
    };

    std::chrono::steady_clock::time_point lastReportTime_;
    std::mutex reportMutex_;
    MacAdapter macAdapter_;
};

} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS

#endif // SANDBOX_STATS_REPORTER_H
