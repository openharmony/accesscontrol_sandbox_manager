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

#ifndef SANDBOX_MANAGER_MAC_ADAPTER_H
#define SANDBOX_MANAGER_MAC_ADAPTER_H

#include <string>
#include "policy_info.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

struct MacParams {
    uint32_t tokenId;
    uint64_t policyFlag;
    uint64_t timestamp;
    int32_t userId;
};
class MacAdapter {
public:
    explicit MacAdapter();
    virtual ~MacAdapter();
    void Init();
    bool IsMacSupport();

    int32_t SetSandboxPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result,
        MacParams &macParams);
    int32_t UnSetSandboxPolicy(uint32_t tokenId, const PolicyInfo &policy);
    int32_t UnSetSandboxPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result);
    int32_t QuerySandboxPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result);
    int32_t CheckSandboxPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result);
    int32_t DestroySandboxPolicy(uint32_t tokenId, uint64_t timestamp);
    int32_t UnSetSandboxPolicyByUser(int32_t userId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result);
    void CheckResult(std::vector<uint32_t> &result);
#ifndef NOT_RESIDENT
    int32_t ReadDenyFile(const char *jsonPath, std::string& rawData);
    int32_t SetDenyCfg(std::string& json);
    void DenyInit();
#endif
private:
    int32_t fd_ = -1;
    bool isMacSupport_ = false;
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // SANDBOX_MANAGER_MAC_ADAPTER_H