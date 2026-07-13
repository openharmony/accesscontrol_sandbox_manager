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

#include "policy_info_parcel.h"
#include "parcel_utils.h"
#include "sandbox_manager_log.h"
#include "sandbox_manager_dfx_helper.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
bool PolicyInfoParcel::Marshalling(Parcel &out) const
{
    RETURN_IF_FALSE(out.WriteString(policyInfo.path));
    RETURN_IF_FALSE(out.WriteUint64(policyInfo.mode));
    return true;
}

PolicyInfoParcel* PolicyInfoParcel::Unmarshalling(Parcel &in)
{
    PolicyInfoParcel* policyInfoParcel = new (std::nothrow) PolicyInfoParcel();
    if (policyInfoParcel == nullptr) {
        return nullptr;
    }

    policyInfoParcel->policyInfo.path = in.ReadString();
    size_t actualLen = strnlen(policyInfoParcel->policyInfo.path.c_str(),
        policyInfoParcel->policyInfo.path.length());
    if (actualLen != policyInfoParcel->policyInfo.path.length()) {
        std::string maskedPath = SandboxManagerLog::MaskRealPath(
            policyInfoParcel->policyInfo.path.substr(0, actualLen));
        std::string error = "path contains null byte, expected length: " +
            std::to_string(policyInfoParcel->policyInfo.path.length()) +
            ", actual length: " + std::to_string(actualLen) + ", maskedPath: " + maskedPath;
        SandboxManagerDfxHelper::WriteEmergencyReportData(error, 0);
        policyInfoParcel->policyInfo.path.resize(actualLen);
    }
    RELEASE_IF_FALSE(in.ReadUint64(policyInfoParcel->policyInfo.mode), policyInfoParcel);
    return policyInfoParcel;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS