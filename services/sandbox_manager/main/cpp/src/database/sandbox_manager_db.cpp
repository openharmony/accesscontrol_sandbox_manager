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

#include "sandbox_manager_db.h"

#include <cstdint>
#include <string>
#include "policy_field_const.h"
#include "sandbox_manager_log.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE,
    ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerDb"};
static const std::string INTEGER_STR = " integer not null,";
static const std::string TEXT_STR = " text not null,";
}

SandboxManagerDb& SandboxManagerDb::GetInstance()
{
    static SandboxManagerDb instance;
    return instance;
}

SandboxManagerDb::~SandboxManagerDb()
{
    Close();
}

void SandboxManagerDb::OnCreate()
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "%{public}s called.", __func__);
    CreatePersistedPolicyTable();
}

void SandboxManagerDb::OnUpdate()
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "%{public}s called.", __func__);
}

SandboxManagerDb::SandboxManagerDb() : SqliteHelper(DATABASE_NAME, DATABASE_PATH, DATABASE_VERSION)
{
    SqliteTable persistedPolicyTable;
    persistedPolicyTable.tableName_ = PERSISTED_POLICY_TABLE;
    persistedPolicyTable.tableColumnNames_ = {
        PolicyFiledConst::FIELD_TOKENID, PolicyFiledConst::FIELD_PATH,
        PolicyFiledConst::FIELD_MODE, PolicyFiledConst::FIELD_DEPTH,
        PolicyFiledConst::FIELD_FLAG
    };

    dataTypeToSqlTable_ = {
        {SANDBOX_MANAGER_PERSISTED_POLICY, persistedPolicyTable},
    };

    Open();
}

int32_t SandboxManagerDb::Add(const DataType type, const std::vector<GenericValues>& values)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::string prepareSql = CreateInsertPrepareSqlCmd(type);
    auto statement = Prepare(prepareSql);
    BeginTransaction();
    bool isExecuteSuccessfully = true;
    for (const auto& value : values) {
        std::vector<std::string> columnNames = value.GetAllKeys();
        for (const auto& columnName : columnNames) {
            statement.Bind(columnName, value.Get(columnName));
        }
        int ret = statement.Step();
        if (ret != Statement::State::DONE) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "failed, errorMsg: %{public}s", SpitError().c_str());
            isExecuteSuccessfully = false;
        }
        statement.Reset();
    }
    if (!isExecuteSuccessfully) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "rollback transaction.");
        RollbackTransaction();
        return FAILURE;
    }
    SANDBOXMANAGER_LOG_INFO(LABEL, "commit transaction.");
    CommitTransaction();
    return SUCCESS;
}

int32_t SandboxManagerDb::Remove(const DataType type, const GenericValues& conditions)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::vector<std::string> columnNames = conditions.GetAllKeys();
    std::string prepareSql = CreateDeletePrepareSqlCmd(type, columnNames);
    auto statement = Prepare(prepareSql);
    for (const auto& columnName : columnNames) {
        statement.Bind(columnName, conditions.Get(columnName));
    }
    int ret = statement.Step();
    return (ret == Statement::State::DONE) ? SUCCESS : FAILURE;
}

int32_t SandboxManagerDb::Modify(const DataType type, const GenericValues& modifyValues,
    const GenericValues& conditions)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::vector<std::string> modifyColumns = modifyValues.GetAllKeys();
    std::vector<std::string> conditionColumns = conditions.GetAllKeys();
    std::string prepareSql = CreateUpdatePrepareSqlCmd(type, modifyColumns, conditionColumns);
    auto statement = Prepare(prepareSql);
    for (const auto& columnName : modifyColumns) {
        statement.Bind(columnName, modifyValues.Get(columnName));
    }
    for (const auto& columnName : conditionColumns) {
        statement.Bind(columnName, conditions.Get(columnName));
    }
    int ret = statement.Step();
    return (ret == Statement::State::DONE) ? SUCCESS : FAILURE;
}

int32_t SandboxManagerDb::FindSubPath(
    const DataType type, const std::string& filePath, std::vector<GenericValues>& results)
{
    OHOS::Utils::UniqueReadGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return FAILURE;
    }
    std::string sql = "select * from " + it->second.tableName_ + " where " + PolicyFiledConst::FIELD_PATH
        + " like '" + filePath + "/%'" + " or " + PolicyFiledConst::FIELD_PATH + " = '" + filePath + "'";
    auto statement = Prepare(sql);

    while (statement.Step() == Statement::State::ROW) {
        int32_t columnCount = statement.GetColumnCount();
        GenericValues value;
        for (int32_t i = 0; i < columnCount; i++) {
            value.Put(statement.GetColumnName(i), statement.GetValue(i, false));
        }
        results.emplace_back(value);
    }
    return SUCCESS;
}

int32_t SandboxManagerDb::Find(const DataType type, const GenericValues& conditions,
    const GenericValues& symbols, std::vector<GenericValues>& results)
{
    OHOS::Utils::UniqueReadGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::vector<std::string> searchColumns = conditions.GetAllKeys();
    std::string prepareSql = CreateSelectPrepareSqlCmd(type, searchColumns, symbols);
    auto statement = Prepare(prepareSql);
    for (const auto& columnName : searchColumns) {
        statement.Bind(columnName, conditions.Get(columnName));
    }
    while (statement.Step() == Statement::State::ROW) {
        int columnCount = statement.GetColumnCount();
        GenericValues value;
        for (int i = 0; i < columnCount; i++) {
            value.Put(statement.GetColumnName(i), statement.GetValue(i, false));
        }
        results.emplace_back(value);
    }
    return SUCCESS;
}

int32_t SandboxManagerDb::RefreshAll(const DataType type, const std::vector<GenericValues>& values)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::string deleteSql = CreateDeletePrepareSqlCmd(type);
    std::string insertSql = CreateInsertPrepareSqlCmd(type);
    auto deleteStatement = Prepare(deleteSql);
    auto insertStatement = Prepare(insertSql);
    BeginTransaction();
    bool canCommit = deleteStatement.Step() == Statement::State::DONE;
    for (const auto& value : values) {
        std::vector<std::string> columnNames = value.GetAllKeys();
        for (const auto& columnName : columnNames) {
            insertStatement.Bind(columnName, value.Get(columnName));
        }
        int ret = insertStatement.Step();
        if (ret != Statement::State::DONE) {
            SANDBOXMANAGER_LOG_ERROR(
                LABEL, "insert failed, errorMsg: %{public}s", SpitError().c_str());
            canCommit = false;
        }
        insertStatement.Reset();
    }
    if (!canCommit) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "rollback transaction.");
        RollbackTransaction();
        return FAILURE;
    }
    SANDBOXMANAGER_LOG_INFO(LABEL, "commit transaction.");
    CommitTransaction();
    return SUCCESS;
}

std::string SandboxManagerDb::CreateInsertPrepareSqlCmd(const DataType type) const
{
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }
    std::string sql = "insert into " + it->second.tableName_ + " values(";
    int i = 1;
    for (const auto& columnName : it->second.tableColumnNames_) {
        sql.append(":" + columnName);
        if (i < static_cast<int32_t>(it->second.tableColumnNames_.size())) {
            sql.append(",");
        }
        i += 1;
    }
    sql.append(")");
    return sql;
}

std::string SandboxManagerDb::CreateDeletePrepareSqlCmd(
    const DataType type, const std::vector<std::string>& columnNames) const
{
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }
    std::string sql = "delete from " + it->second.tableName_ + " where 1 = 1";
    for (const auto& columnName : columnNames) {
        sql.append(" and ");
        sql.append(columnName + "=:" + columnName);
    }
    return sql;
}

std::string SandboxManagerDb::CreateUpdatePrepareSqlCmd(const DataType type,
    const std::vector<std::string>& modifyColumns, const std::vector<std::string>& conditionColumns) const
{
    if (modifyColumns.empty()) {
        return std::string();
    }

    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }

    std::string sql = "update " + it->second.tableName_ + " set ";
    int i = 1;
    for (const auto& columnName : modifyColumns) {
        sql.append(columnName + "=:" + columnName);
        if (i < static_cast<int32_t>(modifyColumns.size())) {
            sql.append(",");
        }
        i += 1;
    }

    if (!conditionColumns.empty()) {
        sql.append(" where 1 = 1");
        for (const auto& columnName : conditionColumns) {
            sql.append(" and ");
            sql.append(columnName + "=:" + columnName);
        }
    }
    return sql;
}

std::string SandboxManagerDb::CreateSelectPrepareSqlCmd(const DataType type,
    const std::vector<std::string>& searchColumns, const GenericValues& symbols) const
{
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }
    std::string sql = "select * from " + it->second.tableName_ + " where 1 = 1";
    for (const auto& columnName : searchColumns) {
        sql.append(" and ");
        std::string symbol = symbols.GetString(columnName);
        std::string insertSql = columnName;
        if (symbol.empty() || symbol== "=") {
            insertSql += "=:";
        } else if (symbol == "<=") {
            insertSql += "<=:";
        } else {
            SANDBOXMANAGER_LOG_ERROR(
                LABEL, "unknown symbol, input: %{public}s", symbol.c_str());
            return std::string();
        }
        sql.append(insertSql + columnName);
    }
    return sql;
}

int32_t SandboxManagerDb::CreatePersistedPolicyTable() const
{
    auto it = dataTypeToSqlTable_.find(DataType::SANDBOX_MANAGER_PERSISTED_POLICY);
    if (it == dataTypeToSqlTable_.end()) {
        return FAILURE;
    }
    std::string sql = "create table if not exists ";
    sql.append(it->second.tableName_ + " (")
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
    return ExecuteSql(sql);
}
} // namespace SANDBOXMANAGER
} // namespace Security
} // namespace OHOS