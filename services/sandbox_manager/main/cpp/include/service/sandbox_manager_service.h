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

#ifndef SANDBOX_MANAGER_SERVICE_H
#define SANDBOX_MANAGER_SERVICE_H
#include <cstdint>
#include <string>
#include <vector>
#include "event_handler.h"
#include "iremote_object.h"
#include <mutex>
#include "nocopyable.h"
#include "sandbox_manager_stub.h"
#include "singleton.h"
#include "system_ability.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
using namespace OHOS::AppExecFwk;
enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING };
class SandboxManagerService final : public SystemAbility, public SandboxManagerStub {
    DECLARE_DELAYED_SINGLETON(SandboxManagerService);
    DECLEAR_SYSTEM_ABILITY(SandboxManagerService);

public:
    SandboxManagerService(int saId, bool runOnCreate);
    void OnStart() override;
    void OnStop() override;
    void OnStart(const SystemAbilityOnDemandReason& startReason) override;
#ifdef MEMORY_MANAGER_ENABLE
    int32_t OnIdle(const SystemAbilityOnDemandReason &idleReason) override;
#endif

    int32_t CleanPersistPolicyByPath(const std::vector<std::string> &filePathList) override;
    int32_t CleanPolicyByUserId(uint32_t userId, const std::vector<std::string> &filePathList) override;
    int32_t PersistPolicy(const PolicyVecRawData &policyRawData, Uint32VecRawData &resultRawData) override;
    int32_t UnPersistPolicy(const PolicyVecRawData &policyRawData, Uint32VecRawData &resultRawData) override;
    int32_t PersistPolicyByTokenId(
        uint32_t tokenId, const PolicyVecRawData &policyRawData, Uint32VecRawData &resultRawData) override;
    int32_t UnPersistPolicyByTokenId(
        uint32_t tokenId, const PolicyVecRawData &policyRawData, Uint32VecRawData &resultRawData) override;
    int32_t SetPolicy(uint32_t tokenId, const PolicyVecRawData &policyRawData, uint64_t policyFlag,
        Uint32VecRawData &resultRawData, const SetInfoParcel &setInfoParcel = SetInfoParcel()) override;
    int32_t UnSetPolicy(uint32_t tokenId, const PolicyInfoParcel &policyParcel) override;
    int32_t SetPolicyAsync(uint32_t tokenId, const PolicyVecRawData &policyRawData, uint64_t policyFlag,
        uint64_t timestamp = 0) override;
    int32_t UnSetPolicyAsync(uint32_t tokenId, const PolicyInfoParcel &policyParcel) override;
    int32_t CheckPolicy(uint32_t tokenId, const PolicyVecRawData &policyRawData,
        BoolVecRawData &resultRawData) override;
    int32_t StartAccessingPolicy(const PolicyVecRawData &policyRawData, Uint32VecRawData &resultRawData,
        bool useCallerToken = true, uint32_t tokenId = 0, uint64_t timestamp = 0) override;
    int32_t StopAccessingPolicy(const PolicyVecRawData &policyRawData, Uint32VecRawData &resultRawData) override;
    int32_t CheckPersistPolicy(
        uint32_t tokenId, const PolicyVecRawData &policyRawData, BoolVecRawData &resultRawData) override;
    int32_t StartAccessingByTokenId(uint32_t tokenId, uint64_t timestamp = 0) override;
    int32_t UnSetAllPolicyByToken(uint32_t tokenId, uint64_t timestamp = 0) override;
    void onRemovePackage(uint32_t tokenId);
    bool CheckPermission(const uint32_t tokenId, const std::string &permission);
    void DelayUnloadService();
    int32_t SetPolicyByBundleName(const std::string &bundleName, int32_t appCloneIndex,
        const PolicyVecRawData &policyRawData, uint64_t policyFlag, Uint32VecRawData &resultRawData) override;
    int32_t CallbackEnter(uint32_t code) override;
    int32_t CallbackExit(uint32_t code, int32_t result) override;
private:
    bool Initialize();
    bool InitDelayUnloadHandler();
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    bool StartByEventAction(const SystemAbilityOnDemandReason& startReason);
    bool IsFileManagerCalling(uint32_t tokenCaller);
    bool PackageChangedEventAction(const SystemAbilityOnDemandReason &startReason);

    std::mutex stateMutex_;
    ServiceRunningState state_;
    static std::mutex unloadMutex_;
    static std::shared_ptr<EventHandler> unloadHandler_;
    static std::shared_ptr<EventRunner> unloadRunner_;
    uint32_t tokenFileManagerId_ = 0;
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // SANDBOX_MANAGER_SERVICE_H