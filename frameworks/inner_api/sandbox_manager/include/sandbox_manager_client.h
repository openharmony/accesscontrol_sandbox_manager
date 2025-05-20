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

#include "isandbox_manager.h"
#include "nocopyable.h"
#include "policy_info.h"
#include "refbase.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class SandboxManagerClient final {
public:
    static SandboxManagerClient &GetInstance();
    virtual ~SandboxManagerClient();

    int32_t CleanPersistPolicyByPath(const std::vector<std::string> &filePathList);
    int32_t PersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    int32_t UnPersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    int32_t SetPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy, uint64_t policyFlag,
                      std::vector<uint32_t> &result, uint64_t timestamp);
    int32_t UnSetPolicy(uint32_t tokenId, const PolicyInfo &policy);
    int32_t SetPolicyAsync(uint32_t tokenId, const std::vector<PolicyInfo> &policy, uint64_t policyFlag,
        uint64_t timestamp);
    int32_t UnSetPolicyAsync(uint32_t tokenId, const PolicyInfo &policy);
    int32_t CheckPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result);
    int32_t StartAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result,
        bool useCallerToken, uint32_t tokenId, uint64_t timestamp);
    int32_t StopAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    int32_t CheckPersistPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result);
    int32_t PersistPolicyByTokenId(
        uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    int32_t UnPersistPolicyByTokenId(
        uint32_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    int32_t StartAccessingByTokenId(uint32_t tokenId, uint64_t timestamp);
    int32_t UnSetAllPolicyByToken(uint32_t tokenId, uint64_t timestamp);
    int32_t CleanPolicyByUserId(uint32_t userId, const std::vector<std::string> &filePathList);
    int32_t SetPolicyByBundleName(const std::string &bundleName, int32_t appCloneIndex,
        const std::vector<PolicyInfo> &policy, uint64_t policyFlag, std::vector<uint32_t> &result);

private:
    SandboxManagerClient();
    DISALLOW_COPY_AND_MOVE(SandboxManagerClient);

    std::mutex proxyMutex_;
    sptr<ISandboxManager> GetProxy();

    int32_t CallProxyWithRetry(const std::function<int32_t(sptr<ISandboxManager> &)> &func,
        const char *funcName);
    bool IsRequestNeedRetry(int32_t ret);
};
} // SandboxManager
} // AccessControl
} // OHOS
#endif // SANDBOXMANAGER_CLIENT_H