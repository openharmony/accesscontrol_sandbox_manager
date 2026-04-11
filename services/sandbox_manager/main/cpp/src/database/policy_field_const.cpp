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
#include "policy_field_const.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
const std::string PolicyFiledConst::FIELD_TOKENID = "tokenId";
const std::string PolicyFiledConst::FIELD_PATH = "path";
const std::string PolicyFiledConst::FIELD_MODE = "mode";
const std::string PolicyFiledConst::FIELD_DEPTH = "depth";
const std::string PolicyFiledConst::FIELD_FLAG = "flag";
// Fields for shared file info table
const std::string PolicyFiledConst::FIELD_BUNDLE_NAME = "bundleName";
const std::string PolicyFiledConst::FIELD_USER_ID = "userId";
const std::string PolicyFiledConst::FIELD_SHARED_OS_PATH = "sharedOsPath";
const std::string PolicyFiledConst::FIELD_SHARED_MODE = "sharedMode";
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS