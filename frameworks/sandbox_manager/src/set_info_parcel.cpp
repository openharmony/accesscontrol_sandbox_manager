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

#include "set_info_parcel.h"
#include "parcel_utils.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
bool SetInfoParcel::Marshalling(Parcel &out) const
{
    RETURN_IF_FALSE(out.WriteString(setInfo.bundleName));
    RETURN_IF_FALSE(out.WriteUint64(setInfo.timestamp));
    return true;
}

SetInfoParcel* SetInfoParcel::Unmarshalling(Parcel &in)
{
    SetInfoParcel* setInfoParcel = new (std::nothrow) SetInfoParcel();
    if (setInfoParcel == nullptr) {
        return nullptr;
    }

    setInfoParcel->setInfo.bundleName = in.ReadString();
    RELEASE_IF_FALSE(in.ReadUint64(setInfoParcel->setInfo.timestamp), setInfoParcel);
    return setInfoParcel;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS