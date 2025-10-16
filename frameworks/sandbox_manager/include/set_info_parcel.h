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

#ifndef SET_INFO_PARCEL_H
#define SET_INFO_PARCEL_H
#include "parcel.h"
#include "policy_info.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
struct SetInfoParcel final : public Parcelable {
    SetInfoParcel() = default;
    ~SetInfoParcel() override = default;
    bool Marshalling(Parcel &out) const override;
    static SetInfoParcel* Unmarshalling(Parcel &in);
    SetInfo setInfo;
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // SET_INFO_PARCEL_H