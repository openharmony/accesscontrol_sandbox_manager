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

#include "accesstoken_kit.h"
#include "securec.h"
#include <string>
#include <cstring>
#include <cstdlib>

namespace OHOS {
namespace Security {
namespace AccessToken {
    ATokenTypeEnum AccessTokenKit::GetTokenTypeFlag(AccessTokenID tokenId)
    {
        // In test environment, return TOKEN_HAP for non-zero tokenId so that
        // ValidateConfig() can proceed past the token type check for valid tokens.
        // Return TOKEN_NATIVE for tokenId == 0 to allow ValidateConfig008 to test
        // the case where GetTokenTypeFlag(0) does not return TOKEN_HAP.
        // The SYSTEM_APP_MASK check is still performed on callerTokenId.
        if (tokenId == 0) {
            return TOKEN_NATIVE;
        }
        return TOKEN_HAP;
    }

    int32_t AccessTokenKit::VerifyAccessToken(AccessTokenID tokenId, const std::string &permissionName)
    {
        if (tokenId != 0 && permissionName.find("GRANTED") != std::string::npos) {
            return PermissionState::PERMISSION_GRANTED;
        }
        return -1;
    }
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS

