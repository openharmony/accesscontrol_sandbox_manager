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
#include "generic_values.h"
#include "sandbox_manager_rdb.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerShare"
};
static std::mutex g_instanceMutex;
constexpr size_t MAX_JSON_SIZE = 5 * 1024 * 1024;
constexpr int32_t MAIN_USER_ID = 100;
constexpr size_t MAX_SHARED_OS_SUB_PATH_LENGTH = 32;
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
    int32_t userId = -1;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != 0) {
        LOGE_WITH_REPORT(LABEL, "InitShareMap get user id failed error=%{public}d", ret);
        userId = MAIN_USER_ID; // set default userId
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

static int32_t CheckShareFileInfoParams(const std::string &bundleName, uint32_t userId, uint32_t tokenId)
{
    if (bundleName.empty()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "bundleName is empty.");
        return INVALID_PARAMTER;
    }
    if (userId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "userId is invalid.");
        return INVALID_PARAMTER;
    }
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "tokenId is invalid.");
        return INVALID_PARAMTER;
    }
    return SANDBOX_MANAGER_OK;
}

static bool IsPathSafe(const char *path)
{
    if (memchr(path, '\0', strlen(path) + 1) != path + strlen(path)) {
        return false;
    }
    if (strstr(path, "/./") != NULL || strstr(path, "/../") != NULL) {
        return false;
    }
    return true;
}

static int32_t ValidateSharingOSPathAndPermission(cJSON *scopes, const char *sharingOSPath,
    const char *sharingOSPermission)
{
    std::string scopePermission;
    bool found = false;
    cJSON *scope = nullptr;
    cJSON_ArrayForEach(scope, scopes) {
        if (!cJSON_IsObject(scope)) {
            continue;
        }
        cJSON *path_item = cJSON_GetObjectItemCaseSensitive(scope, "path");
        if (!cJSON_IsString(path_item) || path_item->valuestring == nullptr) {
            continue;
        }
        if (strcmp(path_item->valuestring, sharingOSPath) == 0) {
            cJSON *permission_item = cJSON_GetObjectItemCaseSensitive(scope, "permission");
            if (!cJSON_IsString(permission_item) || permission_item->valuestring == nullptr) {
                SANDBOXMANAGER_LOG_ERROR(LABEL, "permission field is invalid for path: %{public}s.", sharingOSPath);
                return INVALID_PARAMTER;
            }
            scopePermission = std::string(permission_item->valuestring);
            found = true;
            break;
        }
    }
    if (!found) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "sharingOSPath %{public}s not found in scopes.", sharingOSPath);
        return INVALID_PARAMTER;
    }

    bool isPermissionValid = (strcmp(scopePermission.c_str(), sharingOSPermission) == 0) ||
        (strcmp(scopePermission.c_str(), "r+w") == 0 && strcmp(sharingOSPermission, "r") == 0);
    if (!isPermissionValid) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "sharingOSPermission %{public}s exceeds scope permission %{public}s.",
            sharingOSPermission, scopePermission.c_str());
        return INVALID_PARAMTER;
    }
    return SANDBOX_MANAGER_OK;
}

static int32_t ValidateSharingOSSubPath(const char *sharingOSSubPath)
{
    if (sharingOSSubPath == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "sharingOSSubPath cannot be null.");
        return INVALID_PARAMTER;
    }
    if (strlen(sharingOSSubPath) == 0) {
        return SANDBOX_MANAGER_OK;
    }
    size_t length = strlen(sharingOSSubPath);
    if (length > MAX_SHARED_OS_SUB_PATH_LENGTH) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "sharingOSSubPath length exceeds 32, length=%{public}zu.", length);
        return INVALID_PARAMTER;
    }
    if (!IsPathSafe(sharingOSSubPath)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "sharingOSSubPath contains invalid path components: %{public}s.",
            sharingOSSubPath);
        return INVALID_PARAMTER;
    }
    return SANDBOX_MANAGER_OK;
}

static int32_t WriteShareFileToDb(cJSON *share_files, const std::string &bundleName, uint32_t userId, uint32_t tokenId)
{
    cJSON *sharingOSSubpath_item = cJSON_GetObjectItemCaseSensitive(share_files, "sharingOSSubpath");
    if (!cJSON_IsString(sharingOSSubpath_item)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "sharingOSSubPath is not a valid string.");
        return INVALID_PARAMTER;
    }
    const char *sharingOSSubPath = sharingOSSubpath_item->valuestring;

    cJSON *sharingOSPath_item = cJSON_GetObjectItemCaseSensitive(share_files, "sharingOSPath");
    if (!cJSON_IsString(sharingOSPath_item) || strlen(sharingOSPath_item->valuestring) == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "sharingOSPath is not a valid string.");
        return INVALID_PARAMTER;
    }
    const char *sharingOSPath = sharingOSPath_item->valuestring;
    std::string composedPath = PathCompose(std::string(sharingOSPath), bundleName);
    if (composedPath.empty()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "PathCompose failed, invalid sharingOSPath: %s", sharingOSPath);
        return INVALID_PARAMTER;
    }
    std::string sharedFilePath = composedPath + std::string(sharingOSSubPath);

    cJSON *sharingOSPermission_item = cJSON_GetObjectItemCaseSensitive(share_files, "sharingOSPermission");
    if (!cJSON_IsString(sharingOSPermission_item)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "sharingOSPermission is not a valid string.");
        return INVALID_PARAMTER;
    }
    const char *sharingOSPermission = sharingOSPermission_item->valuestring;
    uint32_t sharedFileMode = PermissionToMode(std::string(sharingOSPermission));

    GenericValues values;
    values.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int32_t>(tokenId));
    values.Put(PolicyFiledConst::FIELD_BUNDLE_NAME, bundleName);
    values.Put(PolicyFiledConst::FIELD_USER_ID, static_cast<int32_t>(userId));
    values.Put(PolicyFiledConst::FIELD_SHARED_OS_PATH, sharedFilePath);
    values.Put(PolicyFiledConst::FIELD_SHARED_MODE, static_cast<int32_t>(sharedFileMode));

    std::vector<GenericValues> valuesList = {values};
    std::string duplicateMode = SandboxManagerRdb::REPLACE;

    int32_t ret = SandboxManagerRdb::GetInstance().Add(
        SANDBOX_MANAGER_SHARED_FILE_INFO,
        valuesList,
        duplicateMode);
    if (ret != SandboxManagerRdb::SUCCESS) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "WriteShareFileToDb add to db failed, tokenId: %{public}d", tokenId);
        return SANDBOX_MANAGER_DB_ERR;
    }
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerShare::SetShareFileInfoInner(cJSON *root, const std::string &bundleName, uint32_t userId,
    uint32_t tokenId)
{
    cJSON *share_files = cJSON_GetObjectItemCaseSensitive(root, "share_files");
    if (!cJSON_IsObject(share_files)) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "No share_files object, skip writing to db.");
        return SANDBOX_MANAGER_OK;
    }

    cJSON *scopes = cJSON_GetObjectItemCaseSensitive(share_files, "scopes");
    if (!cJSON_IsArray(scopes)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "scopes is not an array.");
        return INVALID_PARAMTER;
    }

    cJSON *sharingOSPath_item = cJSON_GetObjectItemCaseSensitive(share_files, "sharingOSPath");
    if (sharingOSPath_item == nullptr) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "No sharingOSPath field, skip writing to db.");
        return SANDBOX_MANAGER_OK;
    }
    if (!cJSON_IsString(sharingOSPath_item) || sharingOSPath_item->valuestring == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "sharingOSPath field is invalid.");
        return INVALID_PARAMTER;
    }
    const char *sharingOSPath = sharingOSPath_item->valuestring;
    if (!IsPathSafe(sharingOSPath)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "sharingOSPath contains invalid path components: %{public}s.", sharingOSPath);
        return INVALID_PARAMTER;
    }

    cJSON *sharingOSPermission_item = cJSON_GetObjectItemCaseSensitive(share_files, "sharingOSPermission");
    if (!cJSON_IsString(sharingOSPermission_item) || sharingOSPermission_item->valuestring == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "sharingOSPermission is not a valid string.");
        return INVALID_PARAMTER;
    }
    const char *sharingOSPermission = sharingOSPermission_item->valuestring;

    int32_t ret = ValidateSharingOSPathAndPermission(scopes, sharingOSPath, sharingOSPermission);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "ValidateSharingOSPathAndPermission failed.");
        return ret;
    }

    cJSON *sharingOSSubpath_item = cJSON_GetObjectItemCaseSensitive(share_files, "sharingOSSubpath");
    if (!cJSON_IsString(sharingOSSubpath_item) || sharingOSSubpath_item->valuestring == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "sharingOSSubpath field is invalid.");
        return INVALID_PARAMTER;
    }
    const char *sharingOSSubPath = sharingOSSubpath_item->valuestring;
    ret = ValidateSharingOSSubPath(sharingOSSubPath);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "ValidateSharingOSSubPath failed.");
        return ret;
    }

    return WriteShareFileToDb(share_files, bundleName, userId, tokenId);
}

int32_t SandboxManagerShare::UpdateShareFileInfoInner(cJSON *root, const std::string &bundleName, uint32_t userId,
    uint32_t tokenId)
{
    cJSON *share_files = cJSON_GetObjectItemCaseSensitive(root, "share_files");
    if (!cJSON_IsObject(share_files)) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "No share_files object, call UnsetShareFileInfo.");
        return UnsetShareFileInfo(tokenId, bundleName, userId);
    }

    cJSON *scopes = cJSON_GetObjectItemCaseSensitive(share_files, "scopes");
    if (!cJSON_IsArray(scopes)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "scopes is not an array.");
        return INVALID_PARAMTER;
    }

    cJSON *sharingOSPath_item = cJSON_GetObjectItemCaseSensitive(share_files, "sharingOSPath");
    if (sharingOSPath_item == nullptr) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "No sharingOSPath field, call UnsetShareFileInfo.");
        return UnsetShareFileInfo(tokenId, bundleName, userId);
    }
    if (!cJSON_IsString(sharingOSPath_item) || sharingOSPath_item->valuestring == nullptr) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "No sharingOSPath field, call UnsetShareFileInfo.");
        return UnsetShareFileInfo(tokenId, bundleName, userId);
    }

    const char *sharingOSPath = sharingOSPath_item->valuestring;
    if (!IsPathSafe(sharingOSPath)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "sharingOSPath contains invalid path components: %{public}s.", sharingOSPath);
        return INVALID_PARAMTER;
    }

    cJSON *sharingOSPermission_item = cJSON_GetObjectItemCaseSensitive(share_files, "sharingOSPermission");
    if (!cJSON_IsString(sharingOSPermission_item) || sharingOSPermission_item->valuestring == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "sharingOSPermission is not a valid string.");
        return INVALID_PARAMTER;
    }
    const char *sharingOSPermission = sharingOSPermission_item->valuestring;

    int32_t ret = ValidateSharingOSPathAndPermission(scopes, sharingOSPath, sharingOSPermission);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "ValidateSharingOSPathAndPermission failed.");
        return ret;
    }

    cJSON *sharingOSSubpath_item = cJSON_GetObjectItemCaseSensitive(share_files, "sharingOSSubpath");
    if (!cJSON_IsString(sharingOSSubpath_item) || sharingOSSubpath_item->valuestring == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "sharingOSSubpath field is invalid.");
        return INVALID_PARAMTER;
    }
    const char *sharingOSSubPath = sharingOSSubpath_item->valuestring;
    ret = ValidateSharingOSSubPath(sharingOSSubPath);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "ValidateSharingOSSubPath failed.");
        return ret;
    }

    return WriteShareFileToDb(share_files, bundleName, userId, tokenId);
}

int32_t SandboxManagerShare::SetShareFileInfo(
    const std::string &cfginfo, const std::string &bundleName, uint32_t userId, uint32_t tokenId)
{
    int32_t ret = CheckShareFileInfoParams(bundleName, userId, tokenId);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "SetShareFileInfo param invalid.");
        return ret;
    }
    if (cfginfo.empty()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "cfginfo is empty, return success.");
        return SANDBOX_MANAGER_OK;
    }
    if (cfginfo.size() > MAX_JSON_SIZE) {
        LOGE_WITH_REPORT(LABEL, "json size exceeds limit, bundleName=%{public}s", bundleName.c_str());
        return INVALID_PARAMTER;
    }

    cJSON *root = cJSON_Parse(cfginfo.c_str());
    if (root == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "json parse error");
        return INVALID_PARAMTER;
    }

    ret = SetShareFileInfoInner(root, bundleName, userId, tokenId);
    cJSON_Delete(root);
    return ret;
}

int32_t SandboxManagerShare::UpdateShareFileInfo(
    const std::string &cfginfo, const std::string &bundleName, uint32_t userId, uint32_t tokenId)
{
    int32_t ret = CheckShareFileInfoParams(bundleName, userId, tokenId);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "UpdateShareFileInfo param invalid.");
        return ret;
    }
    if (cfginfo.empty()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "cfginfo is empty, call UnsetShareFileInfo.");
        return UnsetShareFileInfo(tokenId, bundleName, userId);
    }
    if (cfginfo.size() > MAX_JSON_SIZE) {
        LOGE_WITH_REPORT(LABEL, "json size exceeds limit, bundleName=%{public}s", bundleName.c_str());
        return INVALID_PARAMTER;
    }

    cJSON *root = cJSON_Parse(cfginfo.c_str());
    if (root == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "json parse error");
        return INVALID_PARAMTER;
    }

    ret = UpdateShareFileInfoInner(root, bundleName, userId, tokenId);
    cJSON_Delete(root);
    return ret;
}

int32_t SandboxManagerShare::UnsetShareFileInfo(uint32_t tokenId, const std::string &bundleName, uint32_t userId)
{
    int32_t ret = CheckShareFileInfoParams(bundleName, userId, tokenId);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "UnsetShareFileInfo param invalid.");
        return ret;
    }

    GenericValues unsetShareValues;
    unsetShareValues.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int32_t>(tokenId));
    ret = SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_SHARED_FILE_INFO, unsetShareValues);
    if (ret != SandboxManagerRdb::SUCCESS) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "UnsetShareFileInfo delete from db failed, tokenId: %{public}d", tokenId);
        return SANDBOX_MANAGER_DB_ERR;
    }

    SANDBOXMANAGER_LOG_INFO(LABEL, "UnsetShareFileInfo success, tokenId: %{public}d", tokenId);
    return SANDBOX_MANAGER_OK;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS