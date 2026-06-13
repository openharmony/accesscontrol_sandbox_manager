/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
}

const std::string SandboxManagerRdb::IGNORE = "ignore";
const std::string SandboxManagerRdb::REPLACE = "replace";

SandboxManagerRdb& SandboxManagerRdb::GetInstance()
{
    static SandboxManagerRdb instance;
    return instance;
}

int32_t SandboxManagerRdb::OpenDatabaseInternal()
{
    if (db_ != nullptr) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Db is already inited.");
        return SUCCESS;
    }

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
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "Ready to init db_.");
    db_ = NativeRdb::RdbHelper::GetRdbStore(config, SandboxManagerRdb::DATABASE_VERSION, callback, res);
    if ((res != NativeRdb::E_OK) || (db_ == nullptr)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "GetRdbStore fail, error code:%{public}d", res);
        return res;
    }
    // Restore if needed
    NativeRdb::RebuiltType rebuildType = NativeRdb::RebuiltType::NONE;
    int32_t rebuildCode = db_->GetRebuilt(rebuildType);
    SANDBOXMANAGER_LOG_INFO(LABEL, "Rdb restore rebuildCode ret:%{public}d", rebuildCode);
    if (rebuildType == NativeRdb::RebuiltType::REBUILT) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Start %{public}s restore ret %{public}d, type:%{public}d",
            DATABASE_NAME.c_str(),
            rebuildCode,
            static_cast<int32_t>(rebuildType));
        int32_t restoreRet = db_->Restore(std::string(""), {});
        if (restoreRet != NativeRdb::E_OK) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Rdb restore failed ret:%{public}d", restoreRet);
            return restoreRet;
        }
    }

    return SUCCESS;
}

void SandboxManagerRdb::InitEventHandlerInternal()
{
    if (eventHandler_ != nullptr) {
        SANDBOXMANAGER_LOG_DEBUG(LABEL, "EventHandler already initialized, skip");
        return;
    }
    auto runner = AppExecFwk::EventRunner::Create("SandboxManagerRdb");
    if (runner) {
        eventHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
        SANDBOXMANAGER_LOG_INFO(LABEL, "EventHandler initialized successfully");
    } else {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to create EventRunner for database cleanup");
    }
}

int32_t SandboxManagerRdb::Init()
{
    std::lock_guard<std::mutex> lock(dbLock_);
    int32_t ret = OpenDatabaseInternal();
    if (ret != SUCCESS) {
        return ret;
    }
    InitEventHandlerInternal();
    return SUCCESS;
}

void SandboxManagerRdb::CleanupDbInternal()
{
    std::lock_guard<std::mutex> lock(dbLock_);
    if (db_ != nullptr) {
        db_ = nullptr;
        SANDBOXMANAGER_LOG_INFO(LABEL, "Database connection cleaned up");
    } else {
        SANDBOXMANAGER_LOG_DEBUG(LABEL, "Database connection already null during cleanup");
    }
}

void SandboxManagerRdb::ScheduleDbCleanup()
{
    std::lock_guard<std::mutex> lock(dbLock_);
    if (eventHandler_ == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Event handler not initialized");
        return;
    }

    // Cancel any existing scheduled cleanup
    eventHandler_->RemoveTask("DbCleanup");
    SANDBOXMANAGER_LOG_INFO(LABEL, "Cancelled scheduled database cleanup");

    // Schedule a new cleanup after dbCleanupDelay_ milliseconds
    SandboxManagerRdb *self = this;
    auto callback = [self]() {
        self->CleanupDbInternal();
    };
    if (!eventHandler_->PostTask(callback, "DbCleanup", self->dbCleanupDelay_)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to schedule database cleanup");
    } else {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Scheduled database cleanup in %{public}" PRId64 " milliseconds",
            self->dbCleanupDelay_);
    }
}

std::shared_ptr<NativeRdb::RdbStore> SandboxManagerRdb::GetRdb()
{
    std::lock_guard<std::mutex> lock(dbLock_);
    if (db_ == nullptr) {
        int32_t ret = OpenDatabaseInternal();
        if (ret != SUCCESS) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Open db failed, errno: %{public}d", ret);
            db_ = nullptr;
        }
    }
    return db_;
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

void SandboxManagerRdb::DbOperateFailure(const std::shared_ptr<NativeRdb::RdbStore> &db,
    const std::string& tableName, int32_t res)
{
    db->RollBack();
    if (res != NativeRdb::E_SQLITE_CORRUPT) {
        return;
    }
    SANDBOXMANAGER_LOG_INFO(LABEL, "Db corrupt detected, attempt to restore");
    int ret = db->Restore(std::string(""), {});
    if (ret != NativeRdb::E_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to restore from db, ret is %{public}d.", ret);
    }
    return;
}

int32_t  SandboxManagerRdb::Add(const DataType type, const std::vector<GenericValues> &values,
    const std::string &duplicateMode)
{
    std::string tableName;
    GetTableNameByType(type, tableName);
    if (tableName.empty()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Cannot find tableName by type:%{public}u, please check", type);
        return FAILURE;
    }
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "Add table name is : %{public}s", tableName.c_str());

    NativeRdb::ConflictResolution solution;
    int32_t res = GetConflictResolution(duplicateMode, solution);
    if (res != SUCCESS) {
        return FAILURE;
    }

    std::shared_ptr<NativeRdb::RdbStore> db = GetRdb();
    if (db == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Db is null, open db first");
        return FAILURE;
    }

    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(rwLock_);
    db->BeginTransaction();
    for (const auto& value : values) {
        NativeRdb::ValuesBucket bucket;
        ToRdbValueBucket(value, bucket);
        if (bucket.IsEmpty()) {
            continue;
        }
        int64_t rowId = -1;
        res = db->InsertWithConflictResolution(rowId, tableName, bucket, solution);
        if (res != NativeRdb::E_OK) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to batch insert into table %{public}s, res is %{public}d.",
                tableName.c_str(), res);
            DbOperateFailure(db, tableName, res);
            return FAILURE;
        }
    }
    res = db->Commit();
    if (res != NativeRdb::E_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Db commit failed, res is %{public}d, trying restore db.", res);
        DbOperateFailure(db, tableName, res);
        return FAILURE;
    }
    
    ScheduleDbCleanup();
    
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
    std::shared_ptr<NativeRdb::RdbStore> db = GetRdb();
    if (db == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Db is null, open db first");
        return FAILURE;
    }

    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(rwLock_);
    int32_t res = db->Delete(deletedRows, predicates);
    if (res != NativeRdb::E_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to delete record from table %{public}s, res is %{public}d.",
            tableName.c_str(), res);
        if (res != NativeRdb::E_SQLITE_CORRUPT) {
            return FAILURE;
        }
        SANDBOXMANAGER_LOG_INFO(LABEL, "Db corrupt detected, attempt to restore");
        int ret = db->Restore(std::string(""), {});
        if (ret != NativeRdb::E_OK) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to restore from db, ret is %{public}d.", ret);
        }
        return FAILURE;
    }
    
    ScheduleDbCleanup();
    
    return SUCCESS;
}

int32_t SandboxManagerRdb::Remove(const DataType type, const std::vector<GenericValues> &conditions)
{
    std::string tableName;
    GetTableNameByType(type, tableName);
    if (tableName.empty()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Cannot find tableName by type:%{public}u, please check", type);
        return FAILURE;
    }
    SANDBOXMANAGER_LOG_INFO(LABEL, "Remove tableName: %{public}s", tableName.c_str());

    std::shared_ptr<NativeRdb::RdbStore> db = GetRdb();
    if (db == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Db is null, open db first");
        return FAILURE;
    }

    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(rwLock_);
    db->BeginTransaction();
    for (const auto& condition : conditions) {
        NativeRdb::RdbPredicates predicates(tableName);
        ToRdbPredicates(condition, predicates);
        int32_t deletedRows = 0;
        int32_t res = db->Delete(deletedRows, predicates);
        if (res != NativeRdb::E_OK) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to delete record from table %{public}s, res is %{public}d.",
                tableName.c_str(), res);
            DbOperateFailure(db, tableName, res);
            return FAILURE;
        }
    }
    int32_t res = db->Commit();
    if (res != NativeRdb::E_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Db commit failed, res is %{public}d, trying restore db.", res);
        DbOperateFailure(db, tableName, res);
        return FAILURE;
    }
    
    ScheduleDbCleanup();
    
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
    std::shared_ptr<NativeRdb::RdbStore> db = GetRdb();
    if (db == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Db is null, open db first");
        return FAILURE;
    }

    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(rwLock_);
    int32_t res = db->Update(changedRows, bucket, predicates);
    if (res != NativeRdb::E_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to update record from table %{public}s, res is %{public}d.",
            tableName.c_str(), res);
        if (res != NativeRdb::E_SQLITE_CORRUPT) {
            return FAILURE;
        }
        SANDBOXMANAGER_LOG_INFO(LABEL, "Db corrupt detected, attempt to restore");
        int ret = db->Restore(std::string(""), {});
        if (ret != NativeRdb::E_OK) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to restore from db, ret is %{public}d.", ret);
        }
        return FAILURE;
    }
    
    ScheduleDbCleanup();
    
    return SUCCESS;
}

int32_t SandboxManagerRdb::FindSubPathIgnoreCase(
    const DataType type, const std::string &filePath, std::vector<GenericValues> &results)
{
    std::string tableName;
    GetTableNameByType(type, tableName);
    if (tableName.empty()) {
        return FAILURE;
    }
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "Find tableName: %{public}s", tableName.c_str());

    std::shared_ptr<NativeRdb::RdbStore> db = GetRdb();
    if (db == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Db is null, open db first");
        return FAILURE;
    }
    std::vector<NativeRdb::ValueObject> bindArgs;
    std::string like_arg_str = filePath + "/%";
    NativeRdb::ValueObject arg1(like_arg_str);
    NativeRdb::ValueObject arg2(filePath);
    bindArgs.push_back(arg1);
    bindArgs.push_back(arg2);

    std::string sql = "select * from " + tableName + " where " + PolicyFiledConst::FIELD_PATH
        + " LIKE ? COLLATE NOCASE or " + PolicyFiledConst::FIELD_PATH + " = ? COLLATE NOCASE";

    OHOS::Utils::UniqueReadGuard<OHOS::Utils::RWLock> lock(rwLock_);
    auto queryResultSet = db->QuerySql(sql, bindArgs);
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
    
    ScheduleDbCleanup();
    
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
    std::shared_ptr<NativeRdb::RdbStore> db = GetRdb();
    if (db == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Db is null, open db first");
        return FAILURE;
    }

    OHOS::Utils::UniqueReadGuard<OHOS::Utils::RWLock> lock(rwLock_);
    auto queryResultSet = db->Query(predicates, columns);
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

    ScheduleDbCleanup();

    return SUCCESS;
}

int32_t SandboxManagerRdb::GetRecordCount(const DataType type, int32_t &count)
{
    std::string tableName;
    GetTableNameByType(type, tableName);
    if (tableName.empty()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Cannot find tableName by type: %{public}u, please check", type);
        return FAILURE;
    }
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "GetRecordCount tableName: %{public}s", tableName.c_str());

    std::shared_ptr<NativeRdb::RdbStore> db = GetRdb();
    if (db == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Db is null, open db first");
        return FAILURE;
    }

    std::string sql = "SELECT COUNT(*) FROM " + tableName;
    OHOS::Utils::UniqueReadGuard<OHOS::Utils::RWLock> lock(rwLock_);
    auto queryResultSet = db->QuerySql(sql);
    if (queryResultSet == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to get record count from table %{public}s.", tableName.c_str());
        return FAILURE;
    }

    count = 0;
    if (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        int64_t countValue = 0;
        int32_t res = queryResultSet->GetLong(0, countValue);
        if (res == NativeRdb::E_OK) {
            count = static_cast<int32_t>(countValue);
        }
    }

    SANDBOXMANAGER_LOG_INFO(LABEL, "Table %{public}s record count: %{public}d", tableName.c_str(), count);
    
    ScheduleDbCleanup();
    
    return SUCCESS;
}

int32_t SandboxManagerRdb::GetTokenIdWithMostRecords(const DataType type, uint32_t &tokenId, uint32_t &count)
{
    std::string tableName;
    GetTableNameByType(type, tableName);
    if (tableName.empty()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Cannot find tableName by type: %{public}u, please check", type);
        return FAILURE;
    }
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "GetTokenIdWithMostRecords tableName: %{public}s", tableName.c_str());

    std::shared_ptr<NativeRdb::RdbStore> db = GetRdb();
    if (db == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Db is null, open db first");
        return FAILURE;
    }

    std::string sql = "SELECT " + PolicyFiledConst::FIELD_TOKENID + ", COUNT(*) as count" +
                      " FROM " + tableName +
                      " GROUP BY " + PolicyFiledConst::FIELD_TOKENID +
                      " ORDER BY count DESC LIMIT 1";
    OHOS::Utils::UniqueReadGuard<OHOS::Utils::RWLock> lock(rwLock_);
    auto queryResultSet = db->QuerySql(sql);
    if (queryResultSet == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to get tokenId with most records from table %{public}s.",
            tableName.c_str());
        return FAILURE;
    }

    tokenId = 0;
    count = 0;
    if (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        int64_t tokenIdValue = 0;
        int64_t countValue = 0;
        int32_t res = queryResultSet->GetLong(0, tokenIdValue);
        int32_t resCount = queryResultSet->GetLong(1, countValue);
        if (res == NativeRdb::E_OK && resCount == NativeRdb::E_OK) {
            tokenId = static_cast<uint32_t>(tokenIdValue);
            count = static_cast<uint32_t>(countValue);
            SANDBOXMANAGER_LOG_INFO(LABEL, "Tokenid with most records: %{public}u, count: %{public}u", tokenId, count);
        }
    }

    ScheduleDbCleanup();
    
    return SUCCESS;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
