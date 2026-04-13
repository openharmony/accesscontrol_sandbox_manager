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
    const static std::string FIELD_TOKENID;
    const static std::string FIELD_PATH;
    const static std::string FIELD_MODE;
    const static std::string FIELD_DEPTH;
    const static std::string FIELD_FLAG;
    // Fields for bundle persistent policy table
    const static std::string FIELD_BUNDLENAME;
    const static std::string FIELD_USERID;
    const static std::string FIELD_TIMESTAMP;
    const static std::string FIELD_APPIDENTIFIER;
    const static std::string FIELD_ORIGINAL_TOKENID;
    // Fields for shared file info table
    const static std::string FIELD_BUNDLE_NAME;
    const static std::string FIELD_USER_ID;
    const static std::string FIELD_SHARED_OS_PATH;
    const static std::string FIELD_SHARED_MODE;
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // POLICY_FIELD_CONST_H