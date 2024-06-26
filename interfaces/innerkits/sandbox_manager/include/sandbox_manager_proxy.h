/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef SANDBOX_MANAGER_PROXY_H
#define SANDBOX_MANAGER_PROXY_H

#include "iremote_object.h"
#include "iremote_proxy.h"
#include "i_sandbox_manager.h"
#include "refbase.h"
#include "sandboxmanager_service_ipc_interface_code.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class SandboxManagerProxy : public IRemoteProxy<ISandboxManager> {
public:
    explicit SandboxManagerProxy(const sptr<IRemoteObject> &impl);
    ~SandboxManagerProxy() override;

    int32_t PersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) override;
    int32_t UnPersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) override;
    int32_t SetPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy, uint64_t policyFlag,
                      std::vector<uint32_t> &result) override;
    int32_t UnSetPolicy(uint32_t tokenId, const PolicyInfo &policy) override;
    int32_t SetPolicyAsync(uint32_t tokenId, const std::vector<PolicyInfo> &policy, uint64_t policyFlag) override;
    int32_t UnSetPolicyAsync(uint32_t tokenId, const PolicyInfo &policy) override;
    int32_t CheckPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result) override;
    int32_t StartAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) override;
    int32_t StopAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) override;
    int32_t CheckPersistPolicy(
        uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result) override;
    int32_t PersistPolicyByTokenId(
        uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) override;
    int32_t UnPersistPolicyByTokenId(
        uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) override;
    int32_t StartAccessingByTokenId(uint32_t tokenId) override;
    int32_t UnSetAllPolicyByToken(uint32_t tokenId) override;
private:
    int32_t SendRequest(SandboxManagerInterfaceCode code, MessageParcel &data, MessageParcel &reply);
    int32_t SendRequest(SandboxManagerInterfaceCode code, MessageParcel &data, MessageParcel &reply,
                        MessageOption &option);
    static inline BrokerDelegator<SandboxManagerProxy> delegator_;
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // SANDBOX_MANAGER_PROXY_H
