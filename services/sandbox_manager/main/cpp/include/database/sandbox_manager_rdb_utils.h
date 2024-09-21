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

#ifndef SANDBOX_MANAGER_RDB_UTILS_H
#define SANDBOX_MANAGER_RDB_UTILS_H

#include <vector>

#include "generic_values.h"
#include "rdb_predicates.h"
#include "rdb_store.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

enum DataType {
    SANDBOX_MANAGER_PERSISTED_POLICY,
};

void GetTableNameByType(const DataType type, std::string &tableName);
void ToRdbValueBucket(const AccessControl::SandboxManager::GenericValues &value, NativeRdb::ValuesBucket &bucket);
void ToRdbValueBuckets(const std::vector<GenericValues>& values, std::vector<NativeRdb::ValuesBucket> &buckets);
void ToRdbPredicates(const AccessControl::SandboxManager::GenericValues &conditionValue,
    const AccessControl::SandboxManager::GenericValues &symbols, NativeRdb::RdbPredicates &predicates);
void ToRdbPredicates(const AccessControl::SandboxManager::GenericValues &conditionValue,
    NativeRdb::RdbPredicates &predicates);
void ResultToGenericValues(
    const std::shared_ptr<NativeRdb::ResultSet> &resultSet, AccessControl::SandboxManager::GenericValues &value);
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif  // SANDBOX_MANAGER_RDB_UTILS_H