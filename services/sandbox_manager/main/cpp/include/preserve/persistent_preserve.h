/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef PERSISTENT_PRESERVE_H
#define PERSISTENT_PRESERVE_H

#include <string>
#include <vector>

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class GenericValues;
class PersistentPreserve {
public:
    /**
    * @brief Get persisted policy for a given tokenId
    * @param tokenId token id of the object
    * @param policies output vector of persisted policies
    * @return int32_t
    */
    static int32_t GetPersistedPoliciesByTokenId(const uint32_t tokenId,
        std::vector<GenericValues> &policies);

    /**
    * @brief Save bundle persistent policy when app is uninstalled
    * @param bundleName bundle name
    * @param userId user id
    * @param appIdentifier app identifier
    * @param tokenId original token id
    * @return int32_t
    */
    static int32_t SaveBundlePersistentPolicies(const std::string &bundleName, int32_t userId,
        const std::string &appIdentifier, uint32_t tokenId);

    /**
    * @brief Restore bundle persistent policies when app is installed
    * @param appIdentifier app identifier
    * @param userId user id
    * @param newTokenId new token id for the app
    * @param bundleName bundle name
    * @return int32_t
    */
    static int32_t RestoreBundlePersistentPolicies(const std::string &appIdentifier, int32_t userId,
        uint32_t newTokenId, const std::string &bundleName);

    /**
    * @brief Delete bundle persistent policies after restore
    * @param appIdentifier app identifier
    * @param userId user id
    * @return int32_t
    */
    static int32_t DeleteBundlePersistentPolicies(const std::string &appIdentifier, int32_t userId);
private:

    /**
    * @brief Find bundle record from database
    * @details If multiple records found with same appIdentifier and userId,
    *          uses the one with latest timestamp and deletes the old ones
    * @param appIdentifier app identifier
    * @param userId user id
    * @param bundleRecord output bundle record (latest one if multiple exist)
    * @return int32_t SANDBOX_MANAGER_OK if success, error code otherwise
    */
    static int32_t FindBundleRecord(const std::string &appIdentifier, int32_t userId,
        GenericValues &bundleRecord);

    /**
    * @brief Fetch bundle records by appIdentifier and userId
    * @param appIdentifier app identifier
    * @param userId user id
    * @param bundleRecords output bundle records
    * @return int32_t SANDBOX_MANAGER_OK if success, error code otherwise
    */
    static int32_t FetchBundleRecordsByIdentifier(const std::string &appIdentifier, int32_t userId,
        std::vector<GenericValues> &bundleRecords);

    /**
    * @brief Handle duplicate bundle records - use latest and delete old ones
    * @param appIdentifier app identifier
    * @param userId user id
    * @param bundleRecords input bundle records
    * @param bundleRecord output latest bundle record
    * @return int32_t SANDBOX_MANAGER_OK if success, error code otherwise
    */
    static int32_t HandleDuplicateBundleRecords(const std::string &appIdentifier, int32_t userId,
        const std::vector<GenericValues> &bundleRecords, GenericValues &bundleRecord);
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS

#endif // PERSISTENT_PRESERVE_H
