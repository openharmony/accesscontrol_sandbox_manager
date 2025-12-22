/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#ifndef SHARE_FILES_H
#define SHARE_FILES_H
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

#include "policy_info.h"
#include "cJSON.h"

/*
 * g_shareMap Example
 * ├── bundleName1
 * │ ├── User100
 * │ │ └── path1: r/w
 * │ └── User200
 * │ ├── path1: r/w
 * │ └── path2: r/w
 * └── bundleName2
 * └── User100
 *     ├── path1: r/w
 *     └── path2: r/w
 */
using PathPermissions = std::unordered_map<std::string, uint32_t>; //path and OperateMode
using UserPermissions = std::unordered_map<uint32_t, PathPermissions>; // userId and PathPermissions
using BundlePermissions = std::unordered_map<std::string, UserPermissions>; // bundle and UserPermissions

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

typedef enum ShareStatus {
    SHARE_START_MODE = OperateMode::MAX_MODE << 1,
    SHARE_PATH_UNSET = OperateMode::MAX_MODE << 2,
    SHARE_BUNDLE_UNSET = OperateMode::MAX_MODE << 3,
} ShareStatus;

class SandboxManagerShare {
public:
    static SandboxManagerShare &GetInstance();
    virtual ~SandboxManagerShare() = default;
    int32_t InitShareMap();

    int32_t GetAllShareCfg(int32_t userId);
    int32_t GetShareCfgByBundle(const std::string &bundleName, int32_t userId);
    uint32_t FindPermission(const std::string &bundleName, uint32_t userId, const std::string &path);
    void DeleteByBundleName(const std::string &bundleName);
    void DeleteByTokenid(uint32_t tokenId);
    void DeleteByUserId(uint32_t userId);
    void Refresh(const std::string &bundleName, int32_t userId);
    int32_t TransAndSetToMap(const std::string &profile, const std::string &bundleName, int32_t userId);
private:
    SandboxManagerShare();
    void AddToMap(const std::string &bundleName, uint32_t userId, const std::string &path, uint32_t mode);
    int32_t TransAndSetToMapInner(cJSON *root, const std::string &bundleName, int32_t userId);
    bool Exists(const std::string &bundleName, uint32_t userId);
    BundlePermissions g_shareMap;
    std::mutex mutex_;
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // SHARE_FILES_H