/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sandbox_manager_event_subscriber.h"

#include <cinttypes>
#include <string>
#include "policy_info_manager.h"
#include "sandbox_manager_log.h"
#include "accesstoken_kit.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerEventSubscriber"
};
static bool g_isRegistered = false;
static std::shared_ptr<SandboxManagerCommonEventSubscriber> g_subscriber = nullptr;
}

bool SandboxManagerCommonEventSubscriber::RegisterEvent()
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "Regist event start.");
    if (g_isRegistered) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Common event subscriber already registered.");
        return true;
    }

    auto skill = std::make_shared<EventFwk::MatchingSkills>();
    skill->AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    skill->AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_FULLY_REMOVED);
    skill->AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED);
    skill->AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(*skill);
    auto info = std::make_shared<EventFwk::CommonEventSubscribeInfo>(*skill);
    g_subscriber = std::make_shared<SandboxManagerCommonEventSubscriber>(*info);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(g_subscriber)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Regist common event failed.");
        return false;
    }
    g_isRegistered = true;
    SANDBOXMANAGER_LOG_INFO(LABEL, "Regist event successful.");
    return true;
}

bool SandboxManagerCommonEventSubscriber::UnRegisterEvent()
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "Unregist event start.");
    if (!g_isRegistered) {
        return false;
    }
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(g_subscriber)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "UnregisterEvent result failed.");
        return false;
    }
    g_isRegistered = false;
    return true;
}

void SandboxManagerCommonEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData& data)
{
    const auto want = data.GetWant();
    std::string action = want.GetAction();
    SANDBOXMANAGER_LOG_INFO(LABEL, "Receive event = %{public}s.", action.c_str());
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_FULLY_REMOVED ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED) {
        uint32_t tokenId = static_cast<uint32_t>(want.GetParams().GetIntParam("accessTokenId", 0));
        if (tokenId == 0) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Error tokenid = %{public}u.", tokenId);
            return;
        }
        PolicyInfoManager::GetInstance().RemoveBundlePolicy(tokenId);
        SANDBOXMANAGER_LOG_INFO(LABEL, "RemovebundlePolicy, tokenid = %{public}u.", tokenId);
    }

    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED) {
        std::string bundleName = want.GetElement().GetBundleName();
        int32_t userID = want.GetParams().GetIntParam("userId", -1);
        if ((userID == -1) || (bundleName.empty())) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "On ReceivePackage changed failed by error input.");
            return;
        }
        SANDBOXMANAGER_LOG_INFO(LABEL, "OnReceive Package changed %{public}s, %{public}d", bundleName.c_str(), userID);
        (void)PolicyInfoManager::GetInstance().CleanPolicyByPackageChanged(bundleName, userID);
    }
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS