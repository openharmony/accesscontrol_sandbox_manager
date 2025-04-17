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

#ifndef SANDBOX_MANAGER_RDB_H
#define SANDBOX_MANAGER_RDB_H

#include <cstdint>
#include <vector>
#include <map>
#include <string>
#include "generic_values.h"
#include "nocopyable.h"
#include "policy_field_const.h"
#include "rwlock.h"
#include "sandbox_manager_rdb_utils.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class SandboxManagerRdb {
public:
    enum ExecuteResult { FAILURE = -1, SUCCESS };
    static const std::string IGNORE;
    static const std::string REPLACE;

    static SandboxManagerRdb &GetInstance();

    virtual ~SandboxManagerRdb() = default;

    int32_t Add(const DataType type, const std::vector<GenericValues> &values,
        const std::string &duplicateMode = IGNORE);

    int32_t Remove(const DataType type, const GenericValues &conditions);

    int32_t Remove(const DataType type, const std::vector<GenericValues> &conditions);

    int32_t Modify(const DataType type, const GenericValues &modifyValues, const GenericValues &conditions);

    int32_t FindSubPath(const DataType type, const std::string& filePath, std::vector<GenericValues>& results);
    int32_t Find(const DataType type, const GenericValues &conditions,
        const GenericValues &symbols, std::vector<GenericValues> &results);

private:
    SandboxManagerRdb();
    int32_t OpenDataBase();
    std::shared_ptr<NativeRdb::RdbStore> GetRdb();
    void DbOperateFailure(const std::string& tableName, int32_t res);
    inline static int32_t GetConflictResolution(const std::string &duplicateMode,
        NativeRdb::ConflictResolution &solution);
    DISALLOW_COPY_AND_MOVE(SandboxManagerRdb);

    OHOS::Utils::RWLock rwLock_;
    std::shared_ptr<NativeRdb::RdbStore> db_ = nullptr;
    std::mutex dbLock_;
    static const int DATABASE_VERSION = 1;
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // SANDBOX_MANAGER_RDB_H