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

#ifndef SANDBOX_MANAGER_RDB_OPEN_CALLBACK_H
#define SANDBOX_MANAGER_RDB_OPEN_CALLBACK_H

#include "rdb_open_callback.h"
#include "rdb_store.h"
#include "generic_values.h"
#include "sandbox_manager_rdb_utils.h"
#include "rwlock.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

class SandboxManagerRdbOpenCallback : public NativeRdb::RdbOpenCallback {
public:
    /**
     * Called when the database associate with this RdbStore is created with the first time.
     * This is where the creation of tables and insert the initial data of tables should happen.
     *
     * param store The RdbStore object.
     */
    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;
    /**
     * Called when the database associate whit this RdbStore needs to be upgrade.
     *
     * param store The RdbStore object.
     * param oldVersion The old database version.
     * param newVersion The new database version.
     */
    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t currentVersion, int32_t targetVersion) override;

private:
    int32_t CreatePersistedPolicyTable(NativeRdb::RdbStore &rdbStore, const std::string &tableName) const;

    OHOS::Utils::RWLock rwLock_;
    inline static const std::string PERSISTED_POLICY_TABLE = "persisted_policy_table";

    inline static const std::string DATABASE_NAME = "sandbox_manager.db";
    inline static const std::string DATABASE_PATH = "/data/service/el1/public/sandbox_manager/";
    inline static const std::string BACK_UP_RDB_NAME = "sandbox_manager_slave.db";
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif  // SANDBOX_MANAGER_RDB_OPEN_CALLBACK_H