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

#ifndef CLAW_SANDBOX_SANDBOX_ERROR_H
#define CLAW_SANDBOX_SANDBOX_ERROR_H

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

/**
 * @brief claw_sandbox error code definitions
 *
 * All internal functions return these error codes, and main() returns them
 * as the process exit code. Error descriptions are printed to hilog via
 * SANDBOX_LOGE and to stderr via std::cerr.
 */
enum SandboxError : int {
    SANDBOX_SUCCESS                = 0,    // Success
    SANDBOX_ERR_GENERIC            = -1,   // Generic error
    SANDBOX_ERR_BAD_PARAMETERS     = -2,   // Command line argument error
    SANDBOX_ERR_CMD_INVALID        = -3,   // --cmd argument invalid
    SANDBOX_ERR_CONFIG_INVALID     = -4,   // --config JSON invalid (format/field error)
    SANDBOX_ERR_TEMPLATE_INVALID   = -5,   // Built-in template config load or parse failed
    SANDBOX_ERR_PATH_EXISTS        = -6,   // Path already exists
    SANDBOX_ERR_PATH_CREATE_FAILED = -7,   // Directory creation failed
    SANDBOX_ERR_PATH_INVALID       = -8,   // Invalid path
    SANDBOX_ERR_NS_FAILED          = -9,   // Namespace operation failed (setns/unshare)
    SANDBOX_ERR_MOUNT_FAILED       = -10,  // Mount operation failed
    SANDBOX_ERR_UMOUNT_FAILED      = -11,  // Umount operation failed
    SANDBOX_ERR_CHDIR_FAILED       = -12,  // chdir failed
    SANDBOX_ERR_SET_TOKENID_FAILED = -13,  // SetSelfTokenId failed
    SANDBOX_ERR_SET_UGID_FAILED    = -14,  // Set UID/GID failed
    SANDBOX_ERR_SET_SECCOMP_FAILED = -15,  // Set Seccomp rules failed
    SANDBOX_ERR_SET_SELINUX_FAILED = -16,  // Set Selinux label failed
    SANDBOX_ERR_SET_CAP_FAILED     = -17,  // Drop Capability failed
    SANDBOX_ERR_SANDBOX_PATH_EXHAUSTED = -18,  // Sandbox path creation exhausted (all retries failed)
};

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS

#endif // CLAW_SANDBOX_SANDBOX_ERROR_H
