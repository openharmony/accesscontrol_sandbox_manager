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

#ifndef VOLUME_PRESERVE_MANAGER_H
#define VOLUME_PRESERVE_MANAGER_H

#include <cstdint>
#include <string>
#include <vector>
#include "generic_values.h"
#include "nocopyable.h"
#include "policy_info.h"
#include "sandbox_manager_const.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

enum class VolumeType {
    EXTERNAL,
    VOLDATA,
};

class VolumePreserveManager {
public:
    static VolumePreserveManager &GetInstance();
    int32_t DeactivePolicyByPath(const std::string &volumeMountPath);
    int32_t ActivePolicyByPath(const std::string &volumeMountPath);
    void SetAgingTtlMs(int64_t ttlMs);

private:
    VolumePreserveManager() = default;
    ~VolumePreserveManager() = default;
    DISALLOW_COPY_AND_MOVE(VolumePreserveManager);

    bool ValidatePath(const std::string &path, std::string &adjustedOut);
    int64_t CurrentTimeMs();
    int32_t DeactiveRecords(const std::vector<GenericValues> &records, int64_t now);
    int32_t ActivateRecords(const std::vector<GenericValues> &records);
    int32_t DeleteExpiredRecords(int64_t now);
    void FilterRestorableRecords(std::vector<GenericValues> &records, int64_t now);
    void BuildRecordConditions(const GenericValues &record, GenericValues &conditions);
    int32_t QuerySubPathRecords(const std::string &path, std::vector<GenericValues> &results);
    bool MatchVolumePrefix(const std::string &path, std::string &suffixOut);
    int32_t UnsetMacPolicy(uint32_t tokenId, const PolicyInfo &policy);
    int32_t ActivateMacPolicy(uint32_t tokenId, const PolicyInfo &policy, int32_t userId);

    int64_t agingTtlMs_ = VOLUME_POLICY_AGING_TTL_MS;
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // VOLUME_PRESERVE_MANAGER_H
