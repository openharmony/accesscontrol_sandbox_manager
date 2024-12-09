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

#ifndef I_SANDBOX_MANAGER_H
#define I_SANDBOX_MANAGER_H
#include <vector>
#include "errors.h"
#include "iremote_broker.h"
#include "policy_info.h"
#include "sandboxmanager_service_ipc_interface_code.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class ISandboxManager : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accesscontrol.sandbox_manager.ISandboxManager");

    static const int SA_ID_SANDBOX_MANAGER_SERVICE = SANDBOX_MANAGER_SERVICE_ID;

    virtual int32_t CleanPersistPolicyByPath(const std::vector<std::string>& filePathList) = 0;
    virtual int32_t PersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) = 0;
    virtual int32_t UnPersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) = 0;
    virtual int32_t PersistPolicyByTokenId(
        uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) = 0;
    virtual int32_t UnPersistPolicyByTokenId(
        uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) = 0;
    virtual int32_t SetPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy, uint64_t policyFlag,
                              std::vector<uint32_t> &result, uint64_t timestamp) = 0;
    virtual int32_t UnSetPolicy(uint32_t tokenId, const PolicyInfo &policy) = 0;
    virtual int32_t SetPolicyAsync(uint32_t tokenId, const std::vector<PolicyInfo> &policy, uint64_t policyFlag,
        uint64_t timestamp) = 0;
    virtual int32_t UnSetPolicyAsync(uint32_t tokenId, const PolicyInfo &policy) = 0;
    virtual int32_t CheckPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result) = 0;
    virtual int32_t StartAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result,
        bool useCallerToken, uint32_t tokenId, uint64_t timestamp) = 0;
    virtual int32_t StopAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) = 0;
    virtual int32_t CheckPersistPolicy(
        uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result) = 0;
    virtual int32_t StartAccessingByTokenId(uint32_t tokenId, uint64_t timestamp) = 0;
    virtual int32_t UnSetAllPolicyByToken(uint32_t tokenId, uint64_t timestamp) = 0;
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS

#endif // I_SANDBOX_MANAGER_H