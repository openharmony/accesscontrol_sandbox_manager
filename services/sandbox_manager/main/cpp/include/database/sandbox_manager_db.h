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

#ifndef SANDBOX_MANAGER_DB_H
#define SANDBOX_MANAGER_DB_H

#include <cstdint>
#include <vector>
#include <map>
#include <string>
#include "generic_values.h"
#include "nocopyable.h"
#include "policy_field_const.h"
#include "rwlock.h"
#include "sqlite_helper.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class SandboxManagerDb : public SqliteHelper {
public:
    enum ExecuteResult { FAILURE = -1, SUCCESS };
    struct SqliteTable {
    public:
        std::string tableName_;
        std::vector<std::string> tableColumnNames_;
    };
    enum DataType {
        SANDBOX_MANAGER_PERSISTED_POLICY,
    };

    static SandboxManagerDb &GetInstance();

    ~SandboxManagerDb() override;

    int32_t Add(const DataType type, const std::vector<GenericValues> &values);

    int32_t Remove(const DataType type, const GenericValues &conditions);

    int32_t Modify(const DataType type, const GenericValues &modifyValues, const GenericValues &conditions);

    int32_t FindSubPath(const DataType type, const std::string& filePath, std::vector<GenericValues>& results);
    int32_t Find(const DataType type, const GenericValues &conditions,
        const GenericValues &symbols, std::vector<GenericValues> &results);

    int32_t RefreshAll(const DataType type, const std::vector<GenericValues> &values);

    void OnCreate() override;
    void OnUpdate() override;

private:
    int32_t CreatePersistedPolicyTable() const;

    std::string CreateInsertPrepareSqlCmd(const DataType type) const;
    std::string CreateDeletePrepareSqlCmd(
        const DataType type, const std::vector<std::string> &columnNames = std::vector<std::string>()) const;
    std::string CreateUpdatePrepareSqlCmd(const DataType type, const std::vector<std::string> &modifyColumns,
        const std::vector<std::string> &conditionColumns) const;
    std::string CreateSelectPrepareSqlCmd(const DataType type, const std::vector<std::string> &searchColumns,
    const GenericValues &conditions) const;

    SandboxManagerDb();
    DISALLOW_COPY_AND_MOVE(SandboxManagerDb);

    std::map<DataType, SqliteTable> dataTypeToSqlTable_;
    OHOS::Utils::RWLock rwLock_;
    inline static const std::string PERSISTED_POLICY_TABLE = "persisted_policy_table";

    inline static const std::string DATABASE_NAME = "sandbox_manager.db";
    inline static const std::string DATABASE_PATH = "/data/service/el1/public/sandbox_manager/";
    static const int DATABASE_VERSION = 1;
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // SANDBOX_MANAGER_DB_H