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

#include "policy_info_vector_parcel.h"
#include <cstdint>
#include "parcel_utils.h"
#include "policy_info_parcel.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
bool PolicyInfoVectorParcel::Marshalling(Parcel &out) const
{
    const std::vector<PolicyInfo> policy = this->policyVector;
    uint32_t vecSize = policy.size();
    RETURN_IF_FALSE(out.WriteUint32(vecSize));

    for (uint32_t i = 0; i < vecSize; i++) {
        sptr<PolicyInfoParcel> policyInfoParcel = new (std::nothrow) PolicyInfoParcel();
        if (policyInfoParcel == nullptr) {
            return false;
        }
        policyInfoParcel->policyInfo = policy[i];
        if (!out.WriteParcelable(policyInfoParcel)) {
            return false;
        }
    }

    return true;
}

PolicyInfoVectorParcel* PolicyInfoVectorParcel::Unmarshalling(Parcel &in)
{
    PolicyInfoVectorParcel* policyInfoVectorParcel = new (std::nothrow) PolicyInfoVectorParcel();
    if (policyInfoVectorParcel == nullptr) {
        return nullptr;
    }
    uint32_t vecSize;
    RELEASE_IF_FALSE(in.ReadUint32(vecSize), policyInfoVectorParcel);
    for (uint32_t i = 0; i < vecSize; i++) {
        sptr<PolicyInfoParcel> policyInfoParcel = in.ReadParcelable<PolicyInfoParcel>();
        if (policyInfoParcel == nullptr) {
            delete policyInfoVectorParcel;
            return nullptr;
        }
        policyInfoVectorParcel->policyVector.emplace_back(policyInfoParcel->policyInfo);
    }
    return policyInfoVectorParcel;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS