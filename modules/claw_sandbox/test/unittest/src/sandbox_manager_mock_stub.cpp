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
#include "spm_setproc.h"
#include "securec.h"
#include "sandbox_mock_state.h"
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

// ================== SPM mock stubs ==================
// These stubs override the real SpmGetEntry/SpmDataNew/SpmDataFree from
// libtokensetproc_shared to avoid kernel ioctl dependency in test environment.
// Tests control the mock behavior via g_spmMockState.

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {
SpmMockState g_spmMockState;
}  // namespace SANDBOX
}  // namespace AccessControl
}  // namespace OHOS

using namespace OHOS::AccessControl::SANDBOX;

extern "C" {
    SpmData *SpmDataNew(uint32_t permBufSize, uint32_t extendPermBufSize, uint32_t nameBufSize)
    {
        if (g_spmMockState.failDataNew) {
            return nullptr;
        }
        SpmData *data = (SpmData *)calloc(1, sizeof(SpmData));
        if (data == nullptr) {
            return nullptr;
        }
        if (permBufSize > 0) {
            data->perms.buf = (char *)calloc(1, permBufSize);
            if (data->perms.buf != nullptr) {
                data->perms.bufSize = permBufSize;
            }
        }
        if (extendPermBufSize > 0) {
            data->extendPerms.buf = (char *)calloc(1, extendPermBufSize);
            if (data->extendPerms.buf != nullptr) {
                data->extendPerms.bufSize = extendPermBufSize;
            }
        }
        if (nameBufSize > 0) {
            data->name.buf = (char *)calloc(1, nameBufSize);
            if (data->name.buf != nullptr) {
                data->name.bufSize = nameBufSize;
            }
        }
        return data;
    }

    void SpmDataFree(SpmData *data)
    {
        if (data == nullptr) {
            return;
        }
        free(data->name.buf);
        free(data->perms.buf);
        free(data->extendPerms.buf);
        free(data);
    }

    int SpmGetEntry(uint32_t tokenid, SpmData *entry)
    {
        (void)tokenid;
        if (g_spmMockState.failGetEntry || entry == nullptr) {
            return -1;
        }
        entry->uid = g_spmMockState.uid;
        entry->ownerid = g_spmMockState.ownerid;
        if (entry->name.buf != nullptr && entry->name.bufSize > 0) {
            size_t copyLen = g_spmMockState.name.size();
            if (copyLen >= static_cast<size_t>(entry->name.bufSize)) {
                copyLen = static_cast<size_t>(entry->name.bufSize) - 1;
            }
            if (copyLen > 0) {
                memcpy_s(entry->name.buf, entry->name.bufSize, g_spmMockState.name.c_str(), copyLen);
            }
            entry->name.buf[copyLen] = '\0';
        }
        return 0;
    }
}
