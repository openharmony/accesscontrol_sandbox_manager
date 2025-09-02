/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "data_size_report_adapter.h"
#include "hisysevent.h"

#include <sstream>
#include <thread>
#include <vector>
#include <sys/statfs.h>
#include <sys/stat.h>
#include "directory_ex.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
using namespace OHOS::HiviewDFX;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerDataSizeReportAdapter"
};
static const std::string SANDBOX_MGR_NAME = "sandbox_manager";
static const std::string SYS_EL1_SANDBOX_MGR_DIR = "/data/service/el1/public/sandbox_manager";
static const std::string USER_DATA_DIR = "/data";
static constexpr uint64_t INVALID_SIZE = 0;
static const double UNITS = 1024.0;
static const long ONE_DAY = 24 * 60 * 60;
static time_t g_lastTime = 0;
}

double GetPartitionRemainSize(const std::string& path)
{
    struct statfs stat;
    if (statfs(path.c_str(), &stat) != 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to get %{public}s's remaining size.", path.c_str());
        return INVALID_SIZE;
    }

    /* change B to MB */
    return (static_cast<double>(stat.f_bfree) * static_cast<double>(stat.f_bsize)) / (UNITS * UNITS);
}

void ReportTask()
{
    int ret = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::FILEMANAGEMENT, "USER_DATA_SIZE",
        HiviewDFX::HiSysEvent::EventType::STATISTIC, "COMPONENT_NAME", SANDBOX_MGR_NAME, "PARTITION_NAME",
        USER_DATA_DIR, "REMAIN_PARTITION_SIZE", GetPartitionRemainSize(USER_DATA_DIR),
        "FILE_OR_FOLDER_PATH", SYS_EL1_SANDBOX_MGR_DIR, "FILE_OR_FOLDER_SIZE", GetFolderSize(SYS_EL1_SANDBOX_MGR_DIR));
    if (ret != 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Hisysevent report data size failed!");
    }
}

bool GetInterval(time_t lastTime, time_t nowTime)
{
    return (nowTime - lastTime) > ONE_DAY;
}

void ReportUserDataSize()
{
    time_t nowTime = time(nullptr);
    if (nowTime == -1) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "nowTime get failed!");
        return;
    }
    if (GetInterval(g_lastTime, nowTime)) {
        g_lastTime = nowTime;
        std::thread task(ReportTask);
        task.join();
    }
}
} // namespace SandboxManager
} // namespace AccessControl
} // OHOS