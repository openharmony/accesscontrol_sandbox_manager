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

#ifndef SANDBOXMANAGER_SERVICE_IPC_INTERFACE_CODE_H
#define SANDBOXMANAGER_SERVICE_IPC_INTERFACE_CODE_H

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
/* SAID:3508*/
enum class SandboxManagerInterfaceCode {
    PERSIST_PERMISSION = 0xffb0,
    UNPERSIST_PERMISSION,
    SET_POLICY,
    UNSET_POLICY,
    SET_POLICY_ASYNC,
    UNSET_POLICY_ASYNC,
    CHECK_POLICY,
    START_ACCESSING_URI,
    STOP_ACCESSING_URI,
    CHECK_PERSIST_PERMISSION,
    START_ACCESSING_BY_TOKEN,
    UNSET_ALL_POLICY_BY_TOKEN,
    PERSIST_PERMISSION_BY_TOKENID,
    UNPERSIST_PERMISSION_BY_TOKENID,
    CLEAN_PERSIST_POLICY_BY_PATH,
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS

#endif //SANDBOXMANAGER_SERVICE_IPC_INTERFACE_CODE_H