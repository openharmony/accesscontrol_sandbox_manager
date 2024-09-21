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

#include "sandbox_manager_rdb_utils.h"

#include <chrono>
#include "sandbox_manager_log.h"
#include "policy_field_const.h"
#include "rdb_helper.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
static const std::vector<std::string> g_StringTypeColumns = {
    PolicyFiledConst::FIELD_PATH
};

static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE,
    ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerRdbUtils"};

static const std::map<DataType, std::string> dataTypeToSqlTable_ = {
    {SANDBOX_MANAGER_PERSISTED_POLICY, "persisted_policy_table"},
};
}  // namespace

void GetTableNameByType(const DataType type, std::string &tableName)
{
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return;
    }
    tableName = it->second;
}

static bool IsColumnStringType(const std::string &column)
{
    return std::find(g_StringTypeColumns.begin(), g_StringTypeColumns.end(), column) !=
        g_StringTypeColumns.end();
}

void ToRdbValueBucket(const GenericValues &value, NativeRdb::ValuesBucket &bucket)
{
    std::vector<std::string> columnNames = value.GetAllKeys();
    uint32_t size = columnNames.size();
    for (uint32_t i = 0; i < size; ++i) {
        std::string column = columnNames[i];
        if (IsColumnStringType(column)) {
            bucket.PutString(column, value.GetString(column));
        } else {
            if (value.Get(column).GetType() == ValueType::TYPE_INT) {
                bucket.PutInt(column, value.GetInt(column));
            } else {
                bucket.PutLong(column, value.GetInt64(column));
            }
        }
    }
}

void ToRdbValueBuckets(const std::vector<GenericValues>& values,
    std::vector<NativeRdb::ValuesBucket> &buckets)
{
    for (const auto& value : values) {
        NativeRdb::ValuesBucket bucket;
        ToRdbValueBucket(value, bucket);
        if (bucket.IsEmpty()) {
            continue;
        }
        buckets.emplace_back(bucket);
    }
}

static inline int64_t HandleValueToInt(const VariantValue &variantvalue)
{
    if (variantvalue.GetType() == ValueType::TYPE_INT) {
        return variantvalue.GetInt();
    } else {
        return variantvalue.GetInt64();
    }
}

void ToRdbPredicates(const GenericValues &conditionValue, const GenericValues& symbols,
    NativeRdb::RdbPredicates &predicates)
{
    std::vector<std::string> columnNames = conditionValue.GetAllKeys();
    size_t size = columnNames.size();
    // size 0 is possible, maybe delete or query or update all records
    for (uint32_t i = 0; i < size; ++i) {
        std::string column = columnNames[i];
        if (IsColumnStringType(column)) {
            std::string str = conditionValue.GetString(column);
            predicates.EqualTo(column, conditionValue.GetString(column));
        } else {
            int64_t value = HandleValueToInt(conditionValue.Get(column));
            std::string symbol = symbols.GetString(column);
            if (symbol.empty() || symbol== "=") {
                predicates.EqualTo(column, value);
            } else if (symbol == "<=") {
                predicates.LessThanOrEqualTo(column, value);
            } else {
                SANDBOXMANAGER_LOG_ERROR(
                    LABEL, "unknown symbol, input: %{public}s", symbol.c_str());
                return;
            }
        }
        if (i != size - 1) {
            predicates.And();
        }
    }
}

void ToRdbPredicates(const GenericValues &conditionValue, NativeRdb::RdbPredicates &predicates)
{
    std::vector<std::string> columnNames = conditionValue.GetAllKeys();
    uint32_t size = columnNames.size();
    // size 0 is possible, maybe delete or query or update all records
    for (uint32_t i = 0; i < size; ++i) {
        std::string column = columnNames[i];
        if (IsColumnStringType(column)) {
            std::string str = conditionValue.GetString(column);
            predicates.EqualTo(column, conditionValue.GetString(column));
        } else {
            int64_t value = HandleValueToInt(conditionValue.Get(column));
            predicates.EqualTo(column, value);
        }
        if (i != size - 1) {
            predicates.And();
        }
    }
}

void ResultToGenericValues(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, GenericValues &value)
{
    std::vector<std::string> columnNames;
    resultSet->GetAllColumnNames(columnNames);
    uint64_t size = columnNames.size();
    for (uint64_t i = 0; i < size; ++i) {
        std::string columnName = columnNames[i];
        int32_t columnIndex = 0;
        resultSet->GetColumnIndex(columnName, columnIndex);

        NativeRdb::ColumnType type;
        resultSet->GetColumnType(columnIndex, type);

        if (type == NativeRdb::ColumnType::TYPE_INTEGER) {
            size_t type_size = 0;
            resultSet->GetSize(columnIndex, type_size);
            if (type_size == sizeof(int64_t)) {
                int64_t data = 0;
                resultSet->GetLong(columnIndex, data);
                value.Put(columnName, data);
            } else {
                int32_t data = 0;
                resultSet->GetInt(columnIndex, data);
                value.Put(columnName, data);
            }
        } else if (type == NativeRdb::ColumnType::TYPE_STRING) {
            std::string data;
            resultSet->GetString(columnIndex, data);
            value.Put(columnName, data);
        }
    }
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS