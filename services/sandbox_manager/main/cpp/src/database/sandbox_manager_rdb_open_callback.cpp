/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sandbox_manager_rdb_open_callback.h"

#include <algorithm>
#include <cinttypes>
#include <mutex>
#include "sandbox_manager_log.h"
#include "policy_field_const.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE,
    ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerRdbCallback"};

constexpr const char *INTEGER_STR = " integer not null,";
constexpr const char *TEXT_STR = " text not null,";
}  // namespace

int32_t SandboxManagerRdbOpenCallback::OnCreate(NativeRdb::RdbStore &rdbStore)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "%{public}s called.", __func__);
    SANDBOXMANAGER_LOG_INFO(LABEL, "DB OnCreate");
    int32_t res = CreatePersistedPolicyTable(rdbStore, PERSISTED_POLICY_TABLE);
    if (res != NativeRdb::E_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to create table PERSISTED_POLICY_TABLE");
        return res;
    }
    // Restore if back_db exist
    std::string backupDbPath = DATABASE_PATH + BACK_UP_RDB_NAME;
    if (access(backupDbPath.c_str(), NativeRdb::E_OK) == 0) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "backup db exist, need to restore");
        int32_t restoreRet = rdbStore.Restore(std::string(""), {});
        if (restoreRet != NativeRdb::E_OK) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "rdb restore failed ret:%{public}d", restoreRet);
        }
    }
    return NativeRdb::E_OK;
}

int32_t SandboxManagerRdbOpenCallback::OnUpgrade(
    NativeRdb::RdbStore &rdbStore, int32_t currentVersion, int32_t targetVersion) { return NativeRdb::E_OK; }

int32_t SandboxManagerRdbOpenCallback::CreatePersistedPolicyTable(NativeRdb::RdbStore &rdbStore,
    const std::string &tableName) const
{
    std::string sql = "create table if not exists ";
    sql.append(tableName + " (")
        .append(PolicyFiledConst::FIELD_TOKENID)
        .append(INTEGER_STR)
        .append(PolicyFiledConst::FIELD_PATH)
        .append(TEXT_STR)
        .append(PolicyFiledConst::FIELD_MODE)
        .append(INTEGER_STR)
        .append(PolicyFiledConst::FIELD_DEPTH)
        .append(INTEGER_STR)
        .append(PolicyFiledConst::FIELD_FLAG)
        .append(INTEGER_STR)
        .append("primary key(")
        .append(PolicyFiledConst::FIELD_TOKENID)
        .append(",")
        .append(PolicyFiledConst::FIELD_DEPTH)
        .append(",")
        .append(PolicyFiledConst::FIELD_PATH)
        .append(",")
        .append(PolicyFiledConst::FIELD_MODE)
        .append("))");
    return rdbStore.ExecuteSql(sql);
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS