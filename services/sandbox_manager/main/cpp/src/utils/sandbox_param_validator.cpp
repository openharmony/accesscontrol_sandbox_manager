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

#include "sandbox_param_validator.h"

#include <algorithm>
#include <filesystem>
#include <sstream>
#include <strings.h>

#include "policy_info.h"
#include "sandbox_manager_const.h"
#include "sandbox_manager_dfx_helper.h"
#include "sandbox_manager_err_code.h"
#include "share_files.h"
#include "media_path_support.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

namespace {
constexpr int32_t MAX_CHECK_COM_NUM = 6;
constexpr int32_t SECOND_PATH_SEGMENT = 2;
constexpr int32_t EL_LEVEL_SEGMENT = 4;
constexpr int32_t BASE_SEGMENT = 5;
constexpr int32_t SUB_PATH_SEGMENT = 7;
const std::string ROOT_PATH = "/storage";
const std::string APPDATA_PATH = "/storage/Users/currentUser/appdata";
const std::string ROOT_PATH_WITH_SLASH = "/storage/";
const std::string APPDATA_PATH_WITH_SLASH = "/storage/Users/currentUser/appdata/";
} // namespace

bool SandboxParamValidator::CheckShareMode(uint32_t permission, uint32_t mode, const std::string &path,
    const std::string &bundleName)
{
    std::string info;
    bool result = true;
    if (permission == SHARE_BUNDLE_UNSET) {
        info = "bundle_unset";
    } else if (permission == SHARE_PATH_UNSET) {
        info = "path_unset";
        result = false;
    } else if ((permission & mode) != mode) {
        info = "mode_mismatch";
        result = false;
    } else {
        info = "successful";
    }
    SandboxManagerDfxHelper::WriteShareConfigAudit(path, mode, info, bundleName);
    return result;
}

std::string SandboxParamValidator::RemoveClonePrefix(const std::string &bundleName)
{
    const std::string prefix = "+clone-";
    size_t prefixPos = bundleName.find(prefix);
    if (prefixPos == 0) {
        size_t endPos = bundleName.find('+', prefix.size());
        if (endPos != std::string::npos) {
            return bundleName.substr(endPos + 1);
        }
    }
    return bundleName;
}

std::string SandboxParamValidator::GenerateMaskedPath(const std::vector<std::string> &components)
{
    if (components.size() <= SUB_PATH_SEGMENT) {
        return "invalid_path";
    }
    std::string subMask = components[SUB_PATH_SEGMENT].substr(0, 3) + "*";
    std::string pathMask = "***" + components[EL_LEVEL_SEGMENT] + "/" + components[BASE_SEGMENT] + "/" +
        components[MAX_CHECK_COM_NUM] + "/" + subMask;
    return pathMask;
}

std::string SandboxParamValidator::NormalizePath(const std::string& path)
{
    std::string normalized = std::filesystem::path(path).lexically_normal().string();
    // Strip trailing '/' (lexically_normal may keep it on some implementations)
    // Preserve root "/" as-is
    while (normalized.size() > 1 && normalized.back() == '/') {
        normalized.pop_back();
    }
    return normalized;
}

bool SandboxParamValidator::CheckEmbeddedNull(const std::string& path)
{
    return path.find('\0') != std::string::npos;
}

int32_t SandboxParamValidator::ValidateGenericPath(const std::string& path)
{
    // Step 1: Check for embedded null bytes BEFORE lexically_normal (UB risk)
    if (CheckEmbeddedNull(path)) {
        return SandboxRetType::INVALID_PATH;
    }

    // Step 2: Normalize the path via std::filesystem
    std::string normalized = NormalizePath(path);
    if (normalized != path) {
        return SandboxRetType::INVALID_PATH;
    }

    // Step 4: Check normalized length
    if (normalized.empty() || normalized.length() > POLICY_PATH_LIMIT) {
        return SandboxRetType::INVALID_PATH;
    }

    // Step 5: Check that path is absolute (starts with '/')
    if (normalized[0] != '/') {
        return SandboxRetType::INVALID_PATH;
    }

    // Path starts with "//"
    if (normalized.length() > 1 && normalized[1] == '/') {
        return SandboxRetType::INVALID_PATH;
    }

    // Path ends with "/" but is not root
    if (normalized.length() > 1 && normalized.back() == '/') {
        return SandboxRetType::INVALID_PATH;
    }

    return SANDBOX_MANAGER_OK;
}

std::vector<std::string> SandboxParamValidator::SplitPath(const std::string& path)
{
    std::vector<std::string> components;
    std::stringstream ss(path);
    std::string component;
    int comNum = 0;
    while (std::getline(ss, component, '/')) {
        if (!component.empty()) {
            components.push_back(component);
        }
        comNum++;
        // For check bundleName, must split more than MAX_CHECK_COM_NUM length
        if (comNum > (MAX_CHECK_COM_NUM + 1)) {
            // Put the remaining path as a whole into the last element
            if (std::getline(ss, component) && !component.empty()) {
                components.push_back(component);
            }
            break;
        }
    }
    return components;
}

int32_t SandboxParamValidator::ValidateTempMode(uint64_t mode)
{
    constexpr uint64_t normalBits = OperateMode::READ_MODE | OperateMode::WRITE_MODE |
        OperateMode::CREATE_MODE | OperateMode::DELETE_MODE | OperateMode::RENAME_MODE;
    if ((mode & normalBits) == 0 || (mode & ~normalBits) != 0) {
        return SandboxRetType::INVALID_MODE;
    }
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxParamValidator::ValidateDenyMode(uint64_t mode)
{
    constexpr uint64_t denyBits = OperateMode::DENY_READ_MODE | OperateMode::DENY_WRITE_MODE;
    if ((mode & denyBits) == 0 || (mode & ~denyBits) != 0) {
        return SandboxRetType::INVALID_MODE;
    }
    return SANDBOX_MANAGER_OK;
}

bool SandboxParamValidator::CheckPathWithinBundleName(const std::vector<std::string>& components,
    const std::string& bundleName)
{
    if (bundleName.empty()) {
        return false;
    }
    if (components.size() <= MAX_CHECK_COM_NUM) {
        return false;
    }
    if (components[MAX_CHECK_COM_NUM] != bundleName) {
        return false;
    }
    return true;
}

bool SandboxParamValidator::CheckPathWithinShareMap(int32_t userID, const std::string& path,
    const PolicyInfo& policy)
{
    std::vector<std::string> components = SplitPath(path);
    constexpr size_t STORAGE_INDEX = 0;
    constexpr size_t USERS_INDEX = 1;
    constexpr size_t CURRENT_USER_INDEX = 2;
    constexpr size_t APPDATA_INDEX = 3;
    constexpr size_t MIN_APPDATA_COMPONENTS = APPDATA_INDEX + 1;
    bool isAppData = false;
    if (components.size() >= MIN_APPDATA_COMPONENTS) {
        isAppData = components[STORAGE_INDEX] == "storage" &&
                    components[USERS_INDEX] == "Users" &&
                    components[CURRENT_USER_INDEX] == "currentUser" &&
                    strcasecmp(components[APPDATA_INDEX].c_str(), "appdata") == 0;
    }
    if (!isAppData) {
        return true;
    }

    std::string bundleNameTmp = components[MAX_CHECK_COM_NUM];
    std::string bundleRemoveIndex = RemoveClonePrefix(bundleNameTmp);
    std::string pathTmp = APPDATA_PATH_WITH_SLASH;
    for (size_t i = EL_LEVEL_SEGMENT; i < components.size(); ++i) {
        if (i > EL_LEVEL_SEGMENT) {
            pathTmp += "/";
        }
        if (i == MAX_CHECK_COM_NUM) {
            pathTmp += bundleRemoveIndex;
        } else {
            pathTmp += components[i];
        }
    }
    std::string maskedPath = GenerateMaskedPath(components);
    uint32_t permission = SandboxManagerShare::GetInstance().FindPermission(bundleNameTmp, userID, pathTmp);
    return CheckShareMode(permission, policy.mode, maskedPath, bundleNameTmp);
}

int32_t SandboxParamValidator::ValidateBasicPathRules(const std::string& path)
{
    constexpr size_t APPDATA_INDEX = 3;
    constexpr size_t MIN_APPDATA_COMPONENTS = APPDATA_INDEX + 1;
    if (path == ROOT_PATH) {
        return SandboxRetType::INVALID_PATH;
    }

    size_t ROOT_PATH_SIZE = ROOT_PATH_WITH_SLASH.length();
    if (path.substr(0, ROOT_PATH_SIZE) != ROOT_PATH_WITH_SLASH) {
        return SANDBOX_MANAGER_OK;
    }

    std::vector<std::string> components = SplitPath(path);
    if (components.size() <= SECOND_PATH_SEGMENT) {
        return SandboxRetType::INVALID_PATH;
    }

    if (components[0] == "storage" && components[1] == "Users") {
        if (components[SECOND_PATH_SEGMENT] != "currentUser") {
            return SandboxRetType::INVALID_PATH;
        }
        // GAP #5: block appdata case-insensitively (Appdata, APPDATA, appdata, etc.)
        if (components.size() <= MAX_CHECK_COM_NUM && components.size() >= MIN_APPDATA_COMPONENTS &&
            strcasecmp(components[APPDATA_INDEX].c_str(), "appdata") == 0) {
            return SandboxRetType::INVALID_PATH;
        }
    }

    return SANDBOX_MANAGER_OK;
}

int32_t SandboxParamValidator::ValidateExtendedPathRules(int32_t userID, const std::string& path,
    const PolicyInfo& policy, const std::string& bundleName)
{
    std::vector<std::string> components = SplitPath(path);
    if (policy.type == PolicyType::SELF_PATH && !bundleName.empty() &&
        components.size() > MAX_CHECK_COM_NUM) {
        if (!CheckPathWithinBundleName(components, bundleName)) {
            return SandboxRetType::INVALID_PATH;
        }
    }

#ifdef NOT_RESIDENT
    if (components.size() > MAX_CHECK_COM_NUM) {
        if (policy.type != PolicyType::AUTHORIZATION_PATH) {
            if (!CheckPathWithinShareMap(userID, path, policy)) {
                return SandboxRetType::INVALID_PATH;
            }
        }
    }
#endif

    return SANDBOX_MANAGER_OK;
}

int32_t SandboxParamValidator::ValidateTempPolicy(const PolicyInfo& policy, const SetInfo& setInfo)
{
    int32_t result = ValidateGenericPath(policy.path);
    if (result != SANDBOX_MANAGER_OK) {
        return result;
    }

    result = ValidateTempMode(policy.mode);
    if (result != SANDBOX_MANAGER_OK) {
        return result;
    }

    result = ValidateBasicPathRules(policy.path);
    if (result != SANDBOX_MANAGER_OK) {
        return result;
    }

    return ValidateExtendedPathRules(setInfo.userId, policy.path, policy, setInfo.bundleName);
}

int32_t SandboxParamValidator::ValidateActivationPolicy(const PolicyInfo& policy, bool& isMediaPath)
{
    int32_t result = ValidateGenericPath(policy.path);
    if (result != SANDBOX_MANAGER_OK) {
        return result;
    }

    result = ValidateTempMode(policy.mode);
    if (result != SANDBOX_MANAGER_OK) {
        return result;
    }

    result = ValidateBasicPathRules(policy.path);
    if (result != SANDBOX_MANAGER_OK) {
        return result;
    }

    isMediaPath = SandboxManagerMedia::GetInstance().IsMediaPolicy(policy.path);
    return SANDBOX_MANAGER_OK;
}

} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
