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

#ifndef POLICY_FIELD_CONST_H
#define POLICY_FIELD_CONST_H

#include <string>
#include <cstdint>

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class PolicyFiledConst {
public:
    static constexpr const char *FIELD_TOKENID = "tokenId";
    static constexpr const char *FIELD_PATH = "path";
    static constexpr const char *FIELD_MODE = "mode";
    static constexpr const char *FIELD_DEPTH = "depth";
    static constexpr const char *FIELD_FLAG = "flag";
    // Field for persisted_policy_table: timestamp when volume was removed (0 = active)
    static constexpr const char *FIELD_VOLUME_UNMOUNT_TS = "volumeUnmountTs";
    // Fields for bundle persistent policy table
    static constexpr const char *FIELD_BUNDLENAME = "bundleName";
    static constexpr const char *FIELD_USERID = "userId";
    static constexpr const char *FIELD_TIMESTAMP = "timestamp";
    static constexpr const char *FIELD_APPIDENTIFIER = "appIdentifier";
    static constexpr const char *FIELD_ORIGINAL_TOKENID = "tokenId";
    // Fields for shared file info table
    static constexpr const char *FIELD_BUNDLE_NAME = "bundleName";
    static constexpr const char *FIELD_USER_ID = "userId";
    static constexpr const char *FIELD_SHARED_OS_PATH = "sharedOsPath";
    static constexpr const char *FIELD_SHARED_MODE = "sharedMode";
    // Fields for ugc permission table
    static constexpr const char *FIELD_STATUS = "status";
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // POLICY_FIELD_CONST_H