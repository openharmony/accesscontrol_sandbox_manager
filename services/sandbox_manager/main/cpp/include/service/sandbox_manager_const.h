/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SANDBOX_MANAGER_CONST_H
#define SANDBOX_MANAGER_CONST_H
#include <string>

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
#define SA_LIFE_TIME (1000 * 60 * 3)   // 3 min

const uint32_t POLICY_PATH_LIMIT = 4095;

const uint64_t MODE_FILTER = 0b11;
// 1bit-readbit 2bit- writebit, see OperateMode

const std::string SET_POLICY_PERMISSION_NAME = "ohos.permission.SET_SANDBOX_POLICY";
const std::string CHECK_POLICY_PERMISSION_NAME = "ohos.permission.CHECK_SANDBOX_POLICY";
const std::string ACCESS_PERSIST_PERMISSION_NAME = "ohos.permission.FILE_ACCESS_PERSIST";
const std::string FILE_ACCESS_PERMISSION_NAME = "ohos.permission.FILE_ACCESS_MANAGER";

const int32_t FOUNDATION_UID = 5523;
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // SANDBOX_MANAGER_CONST_H