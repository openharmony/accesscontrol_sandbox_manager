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
#include "share_files.h"

#include <algorithm>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "accesstoken_kit.h"
#include "os_account_manager.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "policy_field_const.h"
#include "policy_info.h"
#include "sandbox_manager_const.h"
#include "sandbox_manager_dfx_helper.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerShare"
};
static std::mutex g_instanceMutex;
constexpr size_t MAX_JSON_SIZE = 5 * 1024 * 1024;
}

SandboxManagerShare &SandboxManagerShare::GetInstance()
{
    static SandboxManagerShare *instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new SandboxManagerShare();
        }
    }
    return *instance;
}

SandboxManagerShare::SandboxManagerShare()
{
    int32_t ret = InitShareMap();
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "InitShareMap failed, errno: %{public}d", ret);
    }
}

int32_t SandboxManagerShare::InitShareMap()
{
    int32_t userId = 0;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "InitShareMap get user id failed error=%{public}d", ret);
        userId = 0; // set default userId
    }
    return GetAllShareCfg(userId);
}

static uint32_t PermissionToMode(const std::string &permission)
{
    if (permission == "r") {
        return OperateMode::READ_MODE;
    } else if (permission == "r+w") {
        return OperateMode::READ_MODE | OperateMode::WRITE_MODE;
    } else {
        return 0;
    }
}

const std::string FULL_PATH_START = "/storage/Users/currentUser/appdata/el2/";
const std::vector<std::string> ALLOWED_PATHS = {"/base/files", "/base/preferences", "/base/haps"};
static std::string PathCompose(const std::string &path, const std::string &name)
{
    if (std::find(ALLOWED_PATHS.begin(), ALLOWED_PATHS.end(), path) == ALLOWED_PATHS.end()) {
        return "";
    }
    std::vector<std::string> parts;
    std::stringstream ss(path);
    std::string component;
    int comNum = 0;
    while (std::getline(ss, component, '/')) {
        if (!component.empty()) {
            parts.push_back(component);
        }
        comNum++;
    }

    std::string result = FULL_PATH_START + parts[0] + "/" + name + "/" + parts[1];
    return result;
}

int32_t SandboxManagerShare::TransAndSetToMapInner(cJSON *root, const std::string &bundleName, int32_t userId)
{
    cJSON *share_files = cJSON_GetObjectItemCaseSensitive(root, "share_files");
    if (!cJSON_IsObject(share_files)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "share_files not exit");
        return INVALID_PARAMTER;
    }

    cJSON *scopes = cJSON_GetObjectItemCaseSensitive(share_files, "scopes");
    if (!cJSON_IsArray(scopes)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Error: scopes is not an array.\n");
        return INVALID_PARAMTER;
    }

    cJSON *scope;
    cJSON_ArrayForEach(scope, scopes) {
        if (!cJSON_IsObject(scope)) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Error: scope is not an object");
            continue;
        }

        cJSON *path_item = cJSON_GetObjectItemCaseSensitive(scope, "path");
        if (!cJSON_IsString(path_item)) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "path is not a string.\n");
            continue;
        }
        const char *path = path_item->valuestring;

        cJSON *permission_item = cJSON_GetObjectItemCaseSensitive(scope, "permission");
        if (!cJSON_IsString(permission_item)) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Error: permission is not a string.\n");
            continue;
        }
        const char *permission = permission_item->valuestring;
        uint32_t mode = PermissionToMode(std::string(permission));

        std::string full_path = PathCompose(std::string(path), bundleName);
        AddToMap(bundleName, userId, full_path, mode);
    }
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerShare::TransAndSetToMap(const std::string &profile, const std::string &bundleName, int32_t userId)
{
    if (profile.size() > MAX_JSON_SIZE) {
        LOGE_WITH_REPORT(LABEL, "TransAndSetToMap, json size=%{public}zu exceeds the limit, bundleName=%{public}s",
            profile.size(), bundleName.c_str());
        return INVALID_PARAMTER;
    }

    cJSON *root = cJSON_Parse(profile.c_str());
    if (root == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "json parse error");
        return INVALID_PARAMTER;
    }

    int32_t ret = TransAndSetToMapInner(root, bundleName, userId);
    cJSON_Delete(root);
    return ret;
}

static sptr<AppExecFwk::IBundleMgr> GetBundleMgrsa()
{
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "GetBundleMgr GetSystemAbilityManager is null.");
        return nullptr;
    }
    auto bundleMgrSa = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bundleMgrSa == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "GetBundleMgr GetSystemAbility is null.");
        return nullptr;
    }

    return iface_cast<AppExecFwk::IBundleMgr>(bundleMgrSa);
}

int32_t SandboxManagerShare::GetAllShareCfg(int32_t userId)
{
    auto bundleMgr = GetBundleMgrsa();
    if (bundleMgr == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Get bundleMgr failed.");
        return PERMISSION_DENIED;
    }

    std::vector<AppExecFwk::JsonProfileInfo> profileInfos;
    ErrCode err = bundleMgr->GetAllJsonProfile(AppExecFwk::ProfileType::SHARE_FILES_PROFILE, userId, profileInfos);
    if (err != ERR_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "GetAllJsonProfile, err: %{public}d", err);
        return PERMISSION_DENIED;
    }

    for (const auto &info : profileInfos) {
        if (TransAndSetToMap(info.profile, info.bundleName, userId) != SANDBOX_MANAGER_OK) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "TransAndSetToMap error, bundleName=%{public}s, module=%{public}s",
                info.bundleName.c_str(), info.moduleName.c_str());
        }
    }
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerShare::GetShareCfgByBundle(const std::string &bundleName, int32_t userId)
{
    auto bundleMgr = GetBundleMgrsa();
    if (bundleMgr == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Get bundleMgr failed.");
        return PERMISSION_DENIED;
    }

    AppExecFwk::BundleInfo bundleInfo;
    auto flag = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE);
    ErrCode err = bundleMgr->GetBundleInfoV9(bundleName, flag, bundleInfo, userId);
    if (err != ERR_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "GetBundleInfo error %{public}s, err: %{public}d", bundleName.c_str(), err);
        return PERMISSION_DENIED;
    }

    std::string profile;
    err = bundleMgr->GetJsonProfile(AppExecFwk::ProfileType::SHARE_FILES_PROFILE, bundleName,
        bundleInfo.entryModuleName, profile, userId);
    if (err != ERR_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "GetJsonProfile error %{public}s, err: %{public}d", bundleName.c_str(), userId);
        return PERMISSION_DENIED;
    }
    return TransAndSetToMap(profile, bundleName, userId);
}

bool SandboxManagerShare::Exists(const std::string &bundleName, uint32_t userId)
{
    auto it1 = g_shareMap.find(bundleName);
    if (it1 != g_shareMap.end()) {
        auto it2 = it1->second.find(userId);
        if (it2 != it1->second.end()) {
            return true;
        }
    }
    return false;
}

uint32_t SandboxManagerShare::FindPermission(const std::string &bundleName, uint32_t userId, const std::string &path)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (Exists(bundleName, userId)) {
        auto &pathPermissions = g_shareMap[bundleName][userId];
        auto it = pathPermissions.find(path);
        if (it != pathPermissions.end()) {
            return it->second;
        }
        return SHARE_PATH_UNSET;
    }
    return SHARE_BUNDLE_UNSET;
}

void SandboxManagerShare::AddToMap(const std::string &bundleName, uint32_t userId,
    const std::string &path, uint32_t mode)
{
    if (bundleName.length() == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "AddToMap error, bundlename is empty");
        return;
    }

    if ((path.length() == 0) || (mode == 0)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "AddToMap error, bundlename %{public}s", bundleName.c_str());
        return;
    }
    std::string maskPath = SandboxManagerLog::MaskRealPath(path.c_str());
    std::string maskName = SandboxManagerLog::MaskRealPath(bundleName.c_str());
    SANDBOXMANAGER_LOG_INFO(LABEL, "AddToShareMap: %{public}s %{public}s\n", maskName.c_str(), maskPath.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    g_shareMap[bundleName][userId][path] = mode;
}

void SandboxManagerShare::DeleteByBundleName(const std::string &bundleName)
{
    std::string maskName = SandboxManagerLog::MaskRealPath(bundleName.c_str());
    SANDBOXMANAGER_LOG_INFO(LABEL, "DeleteByBundleName: %{public}s\n", maskName.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    g_shareMap.erase(bundleName);
}

void SandboxManagerShare::Refresh(const std::string &bundleName, int32_t userId)
{
    std::string maskName = SandboxManagerLog::MaskRealPath(bundleName.c_str());
    SANDBOXMANAGER_LOG_INFO(LABEL, "Refresh: %{public}s\n", maskName.c_str());
    DeleteByBundleName(bundleName);
    (void)GetShareCfgByBundle(bundleName, userId);
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS