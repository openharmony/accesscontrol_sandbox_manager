/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef SANDBOX_MANAGER_ERR_CODE_H
#define SANDBOX_MANAGER_ERR_CODE_H
#include <cstdint>
namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
enum SandboxManagerErrCode : int32_t {
    SANDBOX_MANAGER_OK = 0,
    PERMISSION_DENIED = 1,
    INVALID_PARAMTER = 2,

    SANDBOX_MANAGER_SERVICE_NOT_EXIST,
    SANDBOX_MANAGER_SERVICE_PARCEL_ERR,
    SANDBOX_MANAGER_SERVICE_REMOTE_ERR,
    SANDBOX_MANAGER_DB_ERR,
    SANDBOX_MANAGER_DB_RETURN_EMPTY,
    SANDBOX_MANAGER_DB_RECORD_NOT_EXIST,

    SANDBOX_MANAGER_MAC_NOT_INIT,
    SANDBOX_MANAGER_MAC_IOCTL_ERR,
    SANDBOX_MANAGER_DENY_ERR,
    SANDBOX_MANAGER_MEDIA_CALL_ERR,
};
} // SandboxManager
} // AccessControl
} // OHOS
#endif // SANDBOX_MANAGER_ERR_CODE_H
