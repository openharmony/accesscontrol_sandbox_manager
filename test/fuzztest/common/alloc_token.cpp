/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "alloc_token.h"

#include <string>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "permission_def.h"
#include "permission_state_full.h"
#include "token_setproc.h"

namespace OHOS {
    const std::string SET_POLICY_PERMISSION = "ohos.permission.SET_SANDBOX_POLICY";
    const std::string ACCESS_PERSIST_PERMISSION = "ohos.permission.FILE_ACCESS_PERSIST";
    const std::string FILE_ACCESS_PERMISSION_NAME = "ohos.permission.FILE_ACCESS_MANAGER";
    uint64_t g_mockToken;
    Security::AccessToken::PermissionStateFull g_testState1 = {
        .permissionName = SET_POLICY_PERMISSION,
        .isGeneral = true,
        .resDeviceID = {"1"},
        .grantStatus = {0},
        .grantFlags = {0},
    };
    Security::AccessToken::PermissionStateFull g_testState2 = {
        .permissionName = ACCESS_PERSIST_PERMISSION,
        .isGeneral = true,
        .resDeviceID = {"1"},
        .grantStatus = {0},
        .grantFlags = {0},
    };
    Security::AccessToken::PermissionStateFull g_testState3 = {
        .permissionName = FILE_ACCESS_PERMISSION_NAME,
        .isGeneral = true,
        .resDeviceID = {"1"},
        .grantStatus = {0},
        .grantFlags = {0},
    };
    Security::AccessToken::HapInfoParams g_testInfoParms = {
        .userID = 1,
        .bundleName = "sandbox_manager_test",
        .instIndex = 0,
        .appIDDesc = "test"
    };

    Security::AccessToken::HapPolicyParams g_testPolicyPrams = {
        .apl = Security::AccessToken::APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = {g_testState1, g_testState2, g_testState3}
    };

    bool AllocTokenWithFuzz(const uint8_t *data, size_t size, bool(*func)(const uint8_t *, size_t))
    {
        AllocToken();
        bool ret = func(data, size);
        DeleteToken();
        return ret;
    }

    void AllocToken()
    {
        Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
        tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
        g_mockToken = tokenIdEx.tokenIdExStruct.tokenID;
        SetSelfTokenID(tokenIdEx.tokenIdExStruct.tokenID);
    }

    void DeleteToken()
    {
        Security::AccessToken::AccessTokenKit::DeleteToken(g_mockToken);
    }
}

