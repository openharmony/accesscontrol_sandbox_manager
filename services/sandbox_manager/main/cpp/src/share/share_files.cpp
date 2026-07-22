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
#include <filesystem>
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
constexpr size_t MAX_JSON_SIZE = 5 * 1024 * 1024;
constexpr int32_t MAIN_USER_ID = 100;
constexpr size_t MAX_SHARED_OS_SUB_PATH_LENGTH = 32;
}

SandboxManagerShare &SandboxManagerShare::GetInstance()
{
    static SandboxManagerShare instance;
    return instance;
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

namespace {
    // Constants for path composition
    const std::string FULL_PATH_START = "/storage/Users/currentUser/appdata/";
    const std::string DEFAULT_EL = "el2";

    // EL format constants
    const size_t MIN_PARTS_FORMAT = 2;   // Minimum parts for /elx/xxx or /base/xxx
    const size_t MAX_PARTS_FORMAT = 10;  // max parts for /elx/1/2/3/4/5..

    // Valid EL numbers (el1-el5)
    const std::vector<std::string> VALID_EL_NUMBERS = {
        "el1",
        "el2",
        "el3",
        "el4",
        "el5"
    };
}

static bool IsValidElNumber(const std::string &elStr)
{
    return std::find(VALID_EL_NUMBERS.begin(), VALID_EL_NUMBERS.end(), elStr)
           != VALID_EL_NUMBERS.end();
}

static bool IsPathSecure(const std::string &path)
{
    if (path.empty() || path[0] != '/' || path.back() == '/') {
        return false;
    }

    // Reject double leading slash (reject: "//base/a")
    if (path.find("//") == 0) {
        return false;
    }

    // Use std::filesystem to normalize and check for path traversal
    // lexically_normal() resolves ".." and "." components
    // If normalized path differs from original, path had traversal components
    namespace fs = std::filesystem;
    fs::path fsPath(path);
    std::string normalized = fsPath.lexically_normal().string();

    // If normalized differs from original, path had /.. or /.
    return normalized == path;
}

static std::string PathCompose(const std::string &path, const std::string &name)
{
    if (path.empty() || name.empty()) {
        return "";
    }

    if (!IsPathSecure(path)) {
        return "";
    }

    // Parse path into components
    std::vector<std::string> parts;
    std::stringstream ss(path);
    std::string component;
    while (std::getline(ss, component, '/')) {
        if (!component.empty()) {
            parts.push_back(component);
        }
    }

    if (parts.empty()) {
        return "";
    }

    if ((parts.size() < MIN_PARTS_FORMAT) || (parts.size() > MAX_PARTS_FORMAT)) {
        return "";
    }

    std::string result;

    // Handle new format: /elx/y
    if (IsValidElNumber(parts[0])) {
        result = FULL_PATH_START + parts[0] + "/" + parts[1] + "/" + name;
    } else if (parts[0] == "base") {
        result = FULL_PATH_START + DEFAULT_EL + "/" + parts[0] + "/" + name + "/" + parts[1];
    } else {
        return "";
    }

    for (size_t i = MIN_PARTS_FORMAT; i < parts.size(); ++i) {
        result += "/" + parts[i];
    }

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

    constexpr size_t MAX_SHARE_CONFIG_COUNT = 20;
    size_t configCount = 0;

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
        // Check if AddToMap succeeded (returns false means invalid path, rollback performed)
        if (!AddToMap(bundleName, userId, full_path, mode)) {
            LOGE_WITH_REPORT(LABEL, "TransAndSetToMapInner failed for bundle %{public}s, invalid path: %{public}s",
                bundleName.c_str(), path);
            return INVALID_PARAMTER;
        }

        configCount++;
        if (configCount > MAX_SHARE_CONFIG_COUNT) {
            LOGE_WITH_REPORT(LABEL, "TransAndSetToMapInner failed for bundle %{public}s, exceeds limit",
                bundleName.c_str());
            DeleteByBundleName(bundleName);
            return INVALID_PARAMTER;
        }
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
    if (!Exists(bundleName, userId)) {
        return SHARE_BUNDLE_UNSET;
    }

    auto &pathPermissions = g_shareMap[bundleName][userId];
    for (const auto &entry : pathPermissions) {
        const std::string &configPath = entry.first;

        if (path.compare(0, configPath.size(), configPath) != 0) {
            continue;
        }

        if (path.size() == configPath.size()) {
            return entry.second;
        }

        if ((path.size() > configPath.size()) && path[configPath.size()] == '/') {
            return entry.second;
        }
    }

    return SHARE_PATH_UNSET;
}

bool SandboxManagerShare::AddToMap(const std::string &bundleName, uint32_t userId,
    const std::string &path, uint32_t mode)
{
    if (bundleName.length() == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "AddToMap error, bundlename is empty");
        return false;
    }

    if ((path.length() == 0) || (mode == 0)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "AddToMap error, invalid path or mode %{public}u for bundle %{public}s",
            mode, bundleName.c_str());
        // Rollback: remove all configurations for this bundle to maintain atomicity
        DeleteByBundleName(bundleName);
        return false;
    }
    std::string maskPath = SandboxManagerLog::MaskRealPath(path);
    std::string maskName = SandboxManagerLog::MaskRealPath(bundleName);
    SANDBOXMANAGER_LOG_INFO(LABEL, "AddToShareMap: %{public}s %{public}s\n", maskName.c_str(), maskPath.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    g_shareMap[bundleName][userId][path] = mode;
    return true;
}

void SandboxManagerShare::DeleteByBundleName(const std::string &bundleName)
{
    std::string maskName = SandboxManagerLog::MaskRealPath(bundleName);
    SANDBOXMANAGER_LOG_INFO(LABEL, "DeleteByBundleName: %{public}s\n", maskName.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    g_shareMap.erase(bundleName);
}

void SandboxManagerShare::Refresh(const std::string &bundleName, int32_t userId)
{
    std::string maskName = SandboxManagerLog::MaskRealPath(bundleName);
    SANDBOXMANAGER_LOG_INFO(LABEL, "Refresh: %{public}s\n", maskName.c_str());
    DeleteByBundleName(bundleName);
    (void)GetShareCfgByBundle(bundleName, userId);
}

static int32_t CheckShareFileInfoParams(const std::string &bundleName, uint32_t tokenId)
{
    if (bundleName.empty()) {
        LOGE_WITH_REPORT(LABEL, "bundleName is empty.");
        return INVALID_PARAMTER;
    }
    if (tokenId == 0) {
        LOGE_WITH_REPORT(LABEL, "tokenId is invalid.");
        return INVALID_PARAMTER;
    }
    return SANDBOX_MANAGER_OK;
}

static int32_t CheckParamsAndCfginfo(const std::string &bundleName, uint32_t tokenId, const std::string &cfginfo)
{
    int32_t ret = CheckShareFileInfoParams(bundleName, tokenId);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "SetShareFileInfo param invalid.");
        return ret;
    }

    if (cfginfo.size() > MAX_JSON_SIZE) {
        LOGE_WITH_REPORT(LABEL, "json size exceeds limit, bundleName=%{public}s", bundleName.c_str());
        return INVALID_PARAMTER;
    }

    return SANDBOX_MANAGER_OK;
}

struct ShareFileFields {
    std::string sharingOSPath;
    std::string sharingOSPermission;
    std::string sharingOSSubPath;
};

static int32_t GetCStringFromJson(cJSON *object, const char *key, std::string &result)
{
    if (object == nullptr) {
        return INVALID_PARAMTER;
    }

    cJSON *item = cJSON_GetObjectItemCaseSensitive(object, key);
    if (!cJSON_IsString(item) || item->valuestring == nullptr) {
        return INVALID_PARAMTER;
    }

    result = std::string(item->valuestring);
    return SANDBOX_MANAGER_OK;
}

static std::string NormalizeBasePath(const std::string &path)
{
    // Normalize /base/ paths to /el2/base/ for comparison
    // /base/test and /el2/base/test are considered equivalent
    if (path.find("/base/") == 0) {  // starts with /base/
        return "/el2" + path;
    }
    return path;
}

static int32_t ValidateSharingOSPathAndPermission(cJSON *scopes, const std::string &sharingOSPath,
    const std::string &sharingOSPermission)
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

        std::string scopePath = std::string(path_item->valuestring);
        if (NormalizeBasePath(scopePath) == NormalizeBasePath(sharingOSPath)) {
            cJSON *permission_item = cJSON_GetObjectItemCaseSensitive(scope, "permission");
            if (!cJSON_IsString(permission_item) || permission_item->valuestring == nullptr) {
                LOGE_WITH_REPORT(LABEL, "permission field is invalid for path: %{public}s.", sharingOSPath.c_str());
                return INVALID_PARAMTER;
            }
            scopePermission = std::string(permission_item->valuestring);
            found = true;
            break;
        }
    }
    if (!found) {
        LOGE_WITH_REPORT(LABEL, "sharingOSPath %{public}s not found in scopes.", sharingOSPath.c_str());
        return INVALID_PARAMTER;
    }

    bool isPermissionValid = (scopePermission == sharingOSPermission) ||
        (scopePermission == "r+w" && sharingOSPermission == "r");
    if (!isPermissionValid) {
        LOGE_WITH_REPORT(LABEL, "sharingOSPermission %{public}s exceeds scope permission %{public}s.",
            sharingOSPermission.c_str(), scopePermission.c_str());
        return INVALID_PARAMTER;
    }
    return SANDBOX_MANAGER_OK;
}

static int32_t ValidateSharingOSSubPath(const std::string &sharingOSSubPath)
{
    if (sharingOSSubPath.length() > MAX_SHARED_OS_SUB_PATH_LENGTH) {
        LOGE_WITH_REPORT(LABEL, "sharingOSSubPath length exceeds 32, length=%{public}zu.", sharingOSSubPath.length());
        return INVALID_PARAMTER;
    }

    if (sharingOSSubPath.empty()) {
        return SANDBOX_MANAGER_OK;
    }

    if (!IsPathSecure(sharingOSSubPath)) {
        LOGE_WITH_REPORT(LABEL, "sharingOSSubPath contains invalid path components: %{public}s.",
            sharingOSSubPath.c_str());
        return INVALID_PARAMTER;
    }

    return SANDBOX_MANAGER_OK;
}

static int32_t WriteShareFileToDb(const ShareFileFields &fields, const std::string &bundleName,
    uint32_t userId, uint32_t tokenId)
{
    std::string composedPath = PathCompose(fields.sharingOSPath, bundleName);
    if (composedPath.empty()) {
        LOGE_WITH_REPORT(LABEL, "PathCompose failed, invalid sharingOSPath: %{public}s",
            fields.sharingOSPath.c_str());
        return INVALID_PARAMTER;
    }

    std::string sharedFilePath = composedPath + fields.sharingOSSubPath;
    uint32_t sharedFileMode = PermissionToMode(fields.sharingOSPermission);

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
        LOGE_WITH_REPORT(LABEL, "WriteShareFileToDb add to db failed, tokenId: %{public}d", tokenId);
        return SANDBOX_MANAGER_DB_ERR;
    }
    SANDBOXMANAGER_LOG_INFO(LABEL, "ShareFile set success, %{public}s:%{public}s",
        bundleName.c_str(), sharedFilePath.c_str());
    return SANDBOX_MANAGER_OK;
}

static int32_t ProcessShareFileInfo(cJSON *root, const std::string &bundleName, uint32_t userId, uint32_t tokenId)
{
    cJSON *shareFiles = cJSON_GetObjectItemCaseSensitive(root, "share_files");
    if (shareFiles == nullptr || !cJSON_IsObject(shareFiles)) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "No share_files object, skip writing to db.");
        return SANDBOX_MANAGER_OK;
    }

    ShareFileFields fields;
    cJSON *scopes = cJSON_GetObjectItemCaseSensitive(shareFiles, "scopes");
    if (!cJSON_IsArray(scopes)) {
        LOGE_WITH_REPORT(LABEL, "scopes is not an array.");
        return INVALID_PARAMTER;
    }

    if (GetCStringFromJson(shareFiles, "sharingOSPath", fields.sharingOSPath) != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "No sharingOSPath field, skip writing to db.");
        return SANDBOX_MANAGER_OK;
    }

    if (GetCStringFromJson(shareFiles, "sharingOSPermission", fields.sharingOSPermission) != SANDBOX_MANAGER_OK) {
        LOGE_WITH_REPORT(LABEL, "sharingOSPermission field is invalid.");
        return INVALID_PARAMTER;
    }

    if (GetCStringFromJson(shareFiles, "sharingOSSubpath", fields.sharingOSSubPath) != SANDBOX_MANAGER_OK) {
        LOGE_WITH_REPORT(LABEL, "sharingOSSubpath field is invalid.");
        return INVALID_PARAMTER;
    }

    int32_t ret = ValidateSharingOSSubPath(fields.sharingOSSubPath);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "ValidateSharingOSSubPath failed.");
        return ret;
    }

    ret = ValidateSharingOSPathAndPermission(scopes, fields.sharingOSPath, fields.sharingOSPermission);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "ValidateSharingOSPathAndPermission failed.");
        return ret;
    }

    return WriteShareFileToDb(fields, bundleName, userId, tokenId);
}

int32_t SandboxManagerShare::SetShareFileInfo(
    const std::string &cfginfo, const std::string &bundleName, uint32_t userId, uint32_t tokenId)
{
    if (cfginfo.empty()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "cfginfo is empty, return success.");
        return SANDBOX_MANAGER_OK;
    }

    int32_t ret = CheckParamsAndCfginfo(bundleName, tokenId, cfginfo);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }

    cJSON *root = cJSON_Parse(cfginfo.c_str());
    if (root == nullptr) {
        LOGE_WITH_REPORT(LABEL, "json parse error");
        return INVALID_PARAMTER;
    }

    ret = ProcessShareFileInfo(root, bundleName, userId, tokenId);
    cJSON_Delete(root);
    return ret;
}

int32_t SandboxManagerShare::UpdateShareFileInfo(
    const std::string &cfginfo, const std::string &bundleName, uint32_t userId, uint32_t tokenId)
{
    if (cfginfo.empty()) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "cfginfo is empty, call UnsetShareFileInfo.");
        return UnsetShareFileInfo(tokenId, bundleName, userId);
    }

    int32_t ret = CheckParamsAndCfginfo(bundleName, tokenId, cfginfo);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }

    cJSON *root = cJSON_Parse(cfginfo.c_str());
    if (root == nullptr) {
        LOGE_WITH_REPORT(LABEL, "json parse error");
        return INVALID_PARAMTER;
    }

    ret = ProcessShareFileInfo(root, bundleName, userId, tokenId);
    if (SANDBOX_MANAGER_OK != ret) {
        (void)UnsetShareFileInfo(tokenId, bundleName, userId);
    }
    cJSON_Delete(root);
    return ret;
}

int32_t SandboxManagerShare::UnsetShareFileInfo(uint32_t tokenId, const std::string &bundleName, uint32_t userId)
{
    int32_t ret = CheckShareFileInfoParams(bundleName, tokenId);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "UnsetShareFileInfo param invalid.");
        return ret;
    }

    GenericValues unsetShareValues;
    unsetShareValues.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int32_t>(tokenId));
    ret = SandboxManagerRdb::GetInstance().Remove(SANDBOX_MANAGER_SHARED_FILE_INFO, unsetShareValues);
    if (ret != SandboxManagerRdb::SUCCESS) {
        LOGE_WITH_REPORT(LABEL, "UnsetShareFileInfo delete from db failed, tokenId: %{public}d", tokenId);
        return SANDBOX_MANAGER_DB_ERR;
    }

    SANDBOXMANAGER_LOG_INFO(LABEL, "UnsetShareFileInfo success, tokenId: %{public}d", tokenId);
    return SANDBOX_MANAGER_OK;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS