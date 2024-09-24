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

#include "sandbox_manager_rdb.h"

#include <algorithm>
#include <cinttypes>
#include <mutex>
#include <cstdint>
#include "sandbox_manager_rdb_open_callback.h"
#include "sandbox_manager_rdb_utils.h"
#include "rdb_helper.h"
#include "policy_field_const.h"
#include "sandbox_manager_log.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE,
    ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerRdb"};

inline static const std::string DATABASE_NAME = "sandbox_manager.db";
inline static const std::string DATABASE_PATH = "/data/service/el1/public/sandbox_manager/";
inline static const std::string SANDBOX_MANAGER_SERVICE_NAME = "sandbox_manager_service";
static std::mutex g_instanceMutex;
}

const std::string SandboxManagerRdb::IGNORE = "ignore";
const std::string SandboxManagerRdb::REPLACE = "replace";

SandboxManagerRdb& SandboxManagerRdb::GetInstance()
{
    static SandboxManagerRdb* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new SandboxManagerRdb();
        }
    }
    return *instance;
}

SandboxManagerRdb::SandboxManagerRdb()
{
    std::string dbPath = DATABASE_PATH;
    dbPath.append(DATABASE_NAME);
    NativeRdb::RdbStoreConfig config(dbPath);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    config.SetAllowRebuild(true);
    // set Real-time dual-write backup database
    config.SetHaMode(NativeRdb::HAMode::MAIN_REPLICA);
    config.SetServiceName(std::string(SANDBOX_MANAGER_SERVICE_NAME));
    SandboxManagerRdbOpenCallback callback;
    int32_t res = NativeRdb::E_OK;
    // pragma user_version will done by rdb, they store path and db_ as pair in RdbStoreManager
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "ready to init db_.");
    db_ = NativeRdb::RdbHelper::GetRdbStore(config, SandboxManagerRdb::DATABASE_VERSION, callback, res);
    if ((res != NativeRdb::E_OK) || (db_ == nullptr)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "GetRdbStore fail, error code:%{public}d", res);
        return;
    }
    // Restore if needed
    NativeRdb::RebuiltType rebuildType = NativeRdb::RebuiltType::NONE;
    int32_t rebuildCode = db_->GetRebuilt(rebuildType);
    SANDBOXMANAGER_LOG_INFO(LABEL, "rdb restore rebuildCode ret:%{public}d", rebuildCode);
    if (rebuildType == NativeRdb::RebuiltType::REBUILT) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "start %{public}s restore ret %{public}d, type:%{public}d",
            DATABASE_NAME.c_str(),
            rebuildCode,
            static_cast<int32_t>(rebuildType));
        int32_t restoreRet = db_->Restore(std::string(""), {});
        if (restoreRet != NativeRdb::E_OK) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "rdb restore failed ret:%{public}d", restoreRet);
        }
    }
}

int32_t SandboxManagerRdb::GetConflictResolution(const std::string &duplicateMode,
    NativeRdb::ConflictResolution &solution)
{
    if (duplicateMode == IGNORE) {
        solution = NativeRdb::ConflictResolution::ON_CONFLICT_IGNORE;
        return SUCCESS;
    }
    if (duplicateMode == REPLACE) {
        solution = NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE;
        return SUCCESS;
    }
    SANDBOXMANAGER_LOG_ERROR(LABEL, "Duplicate mode should be ignore or replace, input = %{public}s.",
        duplicateMode.c_str());
    return FAILURE;
}

int32_t  SandboxManagerRdb::Add(const DataType type, const std::vector<GenericValues> &values,
    const std::string &duplicateMode)
{
    std::string tableName;
    GetTableNameByType(type, tableName);
    if (tableName.empty()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "cannot find tableName by type:%{public}u, please check", type);
        return FAILURE;
    }
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "Add table name is : %{public}s", tableName.c_str());

    NativeRdb::ConflictResolution solution;
    int32_t res = GetConflictResolution(duplicateMode, solution);
    if (res != SUCCESS) {
        return FAILURE;
    }

    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    if (db_ == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "db is null, open db first");
        return FAILURE;
    }
    db_->BeginTransaction();
    for (const auto& value : values) {
        NativeRdb::ValuesBucket bucket;
        ToRdbValueBucket(value, bucket);
        if (bucket.IsEmpty()) {
            continue;
        }
        int64_t rowId = -1;
        res = db_->InsertWithConflictResolution(rowId, tableName, bucket, solution);
        if (res != NativeRdb::E_OK) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to batch insert into table %{public}s, res is %{public}d.",
                tableName.c_str(), res);
            db_->RollBack();
            if (res != NativeRdb::E_SQLITE_CORRUPT) {
                return FAILURE;
            }
            SANDBOXMANAGER_LOG_INFO(LABEL, "db corrupt detected, attempt to restore");
            int ret = db_->Restore(std::string(""), {});
            if (ret != NativeRdb::E_OK) {
                SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to restore from db, ret is %{public}d.", ret);
            }
            return FAILURE;
        }
    }
    db_->Commit();
    return SUCCESS;
}

int32_t SandboxManagerRdb::Remove(const DataType type, const GenericValues& conditions)
{
    std::string tableName;
    GetTableNameByType(type, tableName);
    if (tableName.empty()) {
        return FAILURE;
    }
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "Remove tableName: %{public}s", tableName.c_str());
    NativeRdb::RdbPredicates predicates(tableName);
    ToRdbPredicates(conditions, predicates);

    int32_t deletedRows = 0;
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    if (db_ == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "db is null, open db first");
        return FAILURE;
    }
    int32_t res = db_->Delete(deletedRows, predicates);
    if (res != NativeRdb::E_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to delete record from table %{public}s, res is %{public}d.",
            tableName.c_str(), res);
        if (res != NativeRdb::E_SQLITE_CORRUPT) {
            return FAILURE;
        }
        SANDBOXMANAGER_LOG_INFO(LABEL, "db corrupt detected, attempt to restore");
        int ret = db_->Restore(std::string(""), {});
        if (ret != NativeRdb::E_OK) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to restore from db, ret is %{public}d.", ret);
        }
        return FAILURE;
    }
    return SUCCESS;
}

int32_t SandboxManagerRdb::Modify(const DataType type, const GenericValues& modifyValues,
    const GenericValues& conditions)
{
    std::string tableName;
    GetTableNameByType(type, tableName);
    if (tableName.empty()) {
        return FAILURE;
    }

    NativeRdb::ValuesBucket bucket;
    ToRdbValueBucket(modifyValues, bucket);
    if (bucket.IsEmpty()) {
        return FAILURE;
    }
    NativeRdb::RdbPredicates predicates(tableName);
    ToRdbPredicates(conditions, predicates);
 
    int32_t changedRows = 0;
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    if (db_ == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "db is null, open db first");
        return FAILURE;
    }
    int32_t res = db_->Update(changedRows, bucket, predicates);
    if (res != NativeRdb::E_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to update record from table %{public}s, res is %{public}d.",
            tableName.c_str(), res);
        if (res != NativeRdb::E_SQLITE_CORRUPT) {
            return FAILURE;
        }
        SANDBOXMANAGER_LOG_INFO(LABEL, "db corrupt detected, attempt to restore");
        int ret = db_->Restore(std::string(""), {});
        if (ret != NativeRdb::E_OK) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to restore from db, ret is %{public}d.", ret);
        }
        return FAILURE;
    }
    return SUCCESS;
}

int32_t SandboxManagerRdb::FindSubPath(
    const DataType type, const std::string& filePath, std::vector<GenericValues>& results)
{
    std::string tableName;
    GetTableNameByType(type, tableName);
    if (tableName.empty()) {
        return FAILURE;
    }
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "Find tableName: %{public}s", tableName.c_str());

    OHOS::Utils::UniqueReadGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::vector<NativeRdb::ValueObject> bindArgs;
    std::string like_arg_str = filePath + "/%";
    NativeRdb::ValueObject arg1(like_arg_str);
    NativeRdb::ValueObject arg2(filePath);
    bindArgs.push_back(arg1);
    bindArgs.push_back(arg2);
    std::string sql = "select * from " + tableName + " where " + PolicyFiledConst::FIELD_PATH
        + " like ? or " + PolicyFiledConst::FIELD_PATH + " = ?";
    auto queryResultSet = db_->QuerySql(sql, bindArgs);
    if (queryResultSet == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to find records from table %{public}s.", tableName.c_str());
        return FAILURE;
    }
    while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        GenericValues value;
        ResultToGenericValues(queryResultSet, value);
        if (value.GetAllKeys().empty()) {
            continue;
        }
        results.emplace_back(value);
    }
    return SUCCESS;
}

int32_t SandboxManagerRdb::Find(const DataType type, const GenericValues& conditions,
    const GenericValues& symbols, std::vector<GenericValues>& results)
{
    std::string tableName;
    GetTableNameByType(type, tableName);
    if (tableName.empty()) {
        return FAILURE;
    }
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "Find tableName: %{public}s", tableName.c_str());
    NativeRdb::RdbPredicates predicates(tableName);
    ToRdbPredicates(conditions, symbols, predicates);

    std::vector<std::string> columns;  // empty columns means query all columns
    OHOS::Utils::UniqueReadGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    if (db_ == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "db is null, open db first");
        return FAILURE;
    }
    auto queryResultSet = db_->Query(predicates, columns);
    if (queryResultSet == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to find records from table %{public}s.", tableName.c_str());
        return FAILURE;
    }
    while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        GenericValues value;
        ResultToGenericValues(queryResultSet, value);
        if (value.GetAllKeys().empty()) {
            continue;
        }
        results.emplace_back(value);
    }
    return SUCCESS;
}
} // namespace SANDBOXMANAGER
} // namespace Security
} // namespace OHOS