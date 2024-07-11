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

/**
* @addtogroup
* @{
*
* @brief
*
* @since
* @version
*/

#ifndef SANDBOXMANAGER_CLIENT_H
#define SANDBOXMANAGER_CLIENT_H

#include "i_sandbox_manager.h"
#include "nocopyable.h"
#include "policy_info.h"
#include "refbase.h"
#include "sandbox_manager_death_recipient.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class SandboxManagerClient final {
public:
    static SandboxManagerClient &GetInstance();
    virtual ~SandboxManagerClient();

    int32_t CleanPersistPolicyByPath(const std::vector<std::string>& filePathList);
    int32_t PersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    int32_t UnPersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    int32_t SetPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy, uint64_t policyFlag,
                      std::vector<uint32_t> &result);
    int32_t UnSetPolicy(uint32_t tokenId, const PolicyInfo &policy);
    int32_t SetPolicyAsync(uint32_t tokenId, const std::vector<PolicyInfo> &policy, uint64_t policyFlag);
    int32_t UnSetPolicyAsync(uint32_t tokenId, const PolicyInfo &policy);
    int32_t CheckPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result);
    int32_t StartAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    int32_t StopAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    int32_t CheckPersistPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result);
    int32_t PersistPolicyByTokenId(
        uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    int32_t UnPersistPolicyByTokenId(
        uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    int32_t StartAccessingByTokenId(uint32_t tokenId);
    int32_t UnSetAllPolicyByToken(uint32_t tokenId);

    void FinishStartSASuccess(const sptr<IRemoteObject> &remoteObject);
    void FinishStartSAFail();
    void OnRemoteDiedHandle();

private:
    SandboxManagerClient();
    DISALLOW_COPY_AND_MOVE(SandboxManagerClient);
    sptr<ISandboxManager> proxy_ = nullptr;
    sptr<ISandboxManager> GetProxy(bool doLoadSa);
    void GetProxyFromRemoteObject(const sptr<IRemoteObject> &remoteObject);

    bool StartLoadSandboxManagerSa();
    void WaitForSandboxManagerSa();
    void LoadSandboxManagerSa();
    void GetSandboxManagerSa();

    std::mutex cvLock_;
    bool readyFlag_ = false;
    std::condition_variable sandboxManagerCon_;
    std::mutex proxyMutex_;
    sptr<SandboxManagerDeathRecipient> serviceDeathObserver_ = nullptr;
};
} // SandboxManager
} // AccessControl
} // OHOS
#endif //SANDBOXMANAGER_CLIENT_H