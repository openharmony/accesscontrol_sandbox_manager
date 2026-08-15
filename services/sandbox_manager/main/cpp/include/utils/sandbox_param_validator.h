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

#ifndef SANDBOX_PARAM_VALIDATOR_H
#define SANDBOX_PARAM_VALIDATOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "policy_info_manager.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

// Forward declarations to avoid circular includes (used by later todos)
class SandboxManagerShare;
class SandboxManagerMedia;

/**
 * @brief Static utility class for validating and normalizing sandbox policy paths.
 *        Provides the foundation layer for the 3-layer validation refactor:
 *        Layer 1 (generic path), Layer 2 (share files), Layer 3 (MAC layer).
 */
class SandboxParamValidator {
public:
    /**
     * @brief Validate a generic file path for sandbox policies (strict mode).
     *
     * Performs the following checks in order:
     * 1. CheckEmbeddedNull - reject paths with embedded null bytes (before lexically_normal)
     * 2. NormalizePath - resolve . and .. components via std::filesystem
     * 3. Strict check - if normalized result differs from input path, reject (path must already be normalized)
     * 4. Length check - reject empty or paths exceeding POLICY_PATH_LIMIT (4095)
     * 5. Absolute path check - reject relative paths (must start with '/')
     *
     * @param path Input path to validate (must already be in normalized form).
     * @return SANDBOX_MANAGER_OK on success, SandboxRetType::INVALID_PATH on failure.
     */
    static int32_t ValidateGenericPath(const std::string& path);

    /**
     * @brief Normalize a path using std::filesystem::path::lexically_normal().
     *
     * Resolves "." and ".." components and removes trailing slashes.
     * Backslash '\' is preserved (legal filename character on Linux).
     *
     * @param path Input path.
     * @return Normalized path string.
     */
    static std::string NormalizePath(const std::string& path);

    /**
     * @brief Check for embedded null bytes in a path string.
     *
     * Must be called BEFORE lexically_normal to avoid std::filesystem undefined behavior.
     * Uses std::string::find('\0') to detect embedded null bytes.
     *
     * @param path Input path.
     * @return true if embedded null byte found, false otherwise.
     */
    static bool CheckEmbeddedNull(const std::string& path);

    /**
     * @brief Split a path into components by '/'.
     *
     * Maximum MAX_CHECK_COM_NUM+1 (7) segments. When the path exceeds this,
     * the remaining path is kept as a single segment in the last element.
     * Empty segments (from consecutive '/' or leading '/') are excluded.
     *
     * @param path Input path.
     * @return Vector of path components.
     */
    static std::vector<std::string> SplitPath(const std::string& path);

    /**
     * @brief Validate mode for temporary policies (SetPolicy).
     *
     * Mode must have at least one of bits 0-4 (READ|WRITE|CREATE|DELETE|RENAME)
     * AND no deny bits (bits 5-6). Valid range: 1-31 (any non-zero subset of bits 0-4).
     *
     * @param mode OperateMode bitmask.
     * @return SANDBOX_MANAGER_OK on success, SandboxRetType::INVALID_MODE on failure.
     */
    static int32_t ValidateTempMode(uint64_t mode);

    /**
     * @brief Validate mode for deny policies (SetDenyPolicy).
     *
     * Mode must have at least one of bits 5-6 (DENY_READ|DENY_WRITE)
     * AND no normal bits (bits 0-4). Valid values: 32, 64, 96.
     * This fixes GAP #3: reject mixed bits (e.g. mode=33 READ+DENY_READ).
     *
     * @param mode OperateMode bitmask.
     * @return SANDBOX_MANAGER_OK on success, SandboxRetType::INVALID_MODE on failure.
     */
    static int32_t ValidateDenyMode(uint64_t mode);

    /**
     * @brief Validate basic path rules (migrated from CheckPathWithinRule).
     *
     * Implements the first block of path rule checks: ROOT_PATH rejection,
     * whitelist for non-/storage/ paths, segment count check, currentUser
     * check, and appdata prefix blocking (case-insensitive, GAP #5).
     *
     * @param path Normalized path to validate.
     * @return SANDBOX_MANAGER_OK on pass, SandboxRetType::INVALID_PATH on fail.
     */
    static int32_t ValidateBasicPathRules(const std::string& path);

    /**
     * @brief Validate extended path rules (migrated from CheckPathWithinRule).
     *
     * Implements the second block of path rule checks: SELF_PATH bundleName
     * check (requires bundleName non-empty and components.size() >
     * MAX_CHECK_COM_NUM), and share map check under #ifdef NOT_RESIDENT.
     *
     * @param userID User ID for share map lookup.
     * @param path Normalized path to validate.
     * @param policy PolicyInfo with type and mode.
     * @param bundleName Caller bundle name for SELF_PATH check.
     * @return SANDBOX_MANAGER_OK on pass, SandboxRetType::INVALID_PATH on fail.
     */
    static int32_t ValidateExtendedPathRules(int32_t userID, const std::string& path,
        const PolicyInfo& policy, const std::string& bundleName);

    /**
     * @brief Check if SELF_PATH components match bundleName (migrated from L1643-1665).
     *
     * @param components Split path components.
     * @param bundleName Expected bundle name at position MAX_CHECK_COM_NUM.
     * @return true if valid, false otherwise.
     */
    static bool CheckPathWithinBundleName(const std::vector<std::string>& components,
        const std::string& bundleName);

    /**
     * @brief Check path against share map (migrated from L1714-1756).
     *
     * Active only under #ifdef NOT_RESIDENT. Splits path internally,
     * checks appdata prefix, queries SandboxManagerShare for permission.
     *
     * @param userID User ID for share map lookup.
     * @param path Path to check.
     * @param policy PolicyInfo with mode for permission matching.
     * @return true if allowed, false if blocked.
     */
    static bool CheckPathWithinShareMap(int32_t userID, const std::string& path,
        const PolicyInfo& policy);

    /**
     * @brief Scenario validator for temporary policies (SetPolicy).
     *
     * Combines: ValidateGenericPath → ValidateTempMode → ValidateBasicPathRules
     * → ValidateExtendedPathRules. No media split. userId and bundleName are
     * sourced from setInfo.
     *
     * @param policy PolicyInfo with path, mode, type.
     * @param setInfo SetInfo with bundleName, timestamp, userId.
     * @return SANDBOX_MANAGER_OK on success, SandboxRetType::INVALID_PATH or INVALID_MODE on failure.
     */
    static int32_t ValidateTempPolicy(const PolicyInfo& policy, const SetInfo& setInfo);

    /**
     * @brief Scenario validator for policy activation (StartAccessingPolicy).
     *
     * Combines: ValidateGenericPath → ValidateTempMode → ValidateBasicPathRules
     * → media split via SandboxManagerMedia::GetInstance().IsMediaPolicy().
     *
     * @param policy PolicyInfo with path, mode, type.
     * @param isMediaPath Output: true if path is a media path.
     * @return SANDBOX_MANAGER_OK on success, SandboxRetType::INVALID_PATH or INVALID_MODE on failure.
     */
    static int32_t ValidateActivationPolicy(const PolicyInfo& policy, bool& isMediaPath);

    /**
     * @brief Check share permission against requested mode (migrated from anonymous namespace).
     *
     * Compares the share permission returned by SandboxManagerShare::FindPermission
     * with the requested mode. SHARE_BUNDLE_UNSET allows the access; SHARE_PATH_UNSET
     * or a mode mismatch denies it. Always emits a share config audit log entry.
     *
     * @param permission Share permission value (or SHARE_BUNDLE_UNSET / SHARE_PATH_UNSET).
     * @param mode Requested OperateMode bitmask.
     * @param path Masked path for audit logging.
     * @param bundleName Bundle name for audit logging.
     * @return true if access is allowed, false otherwise.
     */
    static bool CheckShareMode(uint32_t permission, uint32_t mode, const std::string &path,
        const std::string &bundleName);

    /**
     * @brief Strip the "+clone-N+" prefix from a bundle name (migrated from anonymous namespace).
     *
     * If bundleName starts with "+clone-" and contains a terminating '+',
     * returns the substring after the terminating '+'. Otherwise returns the
     * input unchanged.
     *
     * @param bundleName Input bundle name, possibly with clone prefix.
     * @return Bundle name with clone prefix removed (if pattern matched).
     */
    static std::string RemoveClonePrefix(const std::string &bundleName);

    /**
     * @brief Build a masked path for audit logging (migrated from anonymous namespace).
     *
     * Returns "invalid_path" when the component count is too small (<= SUB_PATH_SEGMENT).
     * Otherwise builds "***<el>/<base>/<bundle>/<sub3>*" masking all but the first 3
     * characters of the sub-path segment.
     *
     * @param components Split path components (output of SplitPath).
     * @return Masked path string suitable for audit logs.
     */
    static std::string GenerateMaskedPath(const std::vector<std::string> &components);
};

} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // SANDBOX_PARAM_VALIDATOR_H
