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
#include "share_files.h"

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
    skill->AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
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

void SandboxManagerCommonEventSubscriber::OnReceiveEventRemove(const EventFwk::Want &want)
{
    uint32_t tokenId = static_cast<uint32_t>(want.GetParams().GetIntParam("accessTokenId", 0));
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Error tokenid = %{public}u.", tokenId);
        return;
    }
    PolicyInfoManager::GetInstance().RemoveBundlePolicy(tokenId);
#ifdef NOT_RESIDENT
    int32_t appIndex = want.GetIntParam("appIndex", -1);
    if (appIndex != 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "ReceivePackage removed only clear main, this is %{public}d", appIndex);
        return;
    }
    std::string bundleName = want.GetElement().GetBundleName();
    if (bundleName.empty()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "On ReceivePackage removed failed by error input.");
        return;
    }
    std::string maskName = SandboxManagerLog::MaskRealPath(bundleName.c_str());
    SANDBOXMANAGER_LOG_INFO(LABEL, "OnReceiveEventRemove %{public}s", maskName.c_str());
    SandboxManagerShare::GetInstance().DeleteByBundleName(bundleName);
#endif
    SANDBOXMANAGER_LOG_INFO(LABEL, "RemovebundlePolicy, tokenid = %{public}u.", tokenId);
}

void SandboxManagerCommonEventSubscriber::OnReceiveEventAdd(const EventFwk::Want &want)
{
    std::string bundleName = want.GetElement().GetBundleName();
    SANDBOXMANAGER_LOG_INFO(LABEL, "On receive package:%{private}s added", bundleName.c_str());

#ifdef NOT_RESIDENT
    int32_t userID = want.GetParams().GetIntParam("userId", -1);
    if ((userID == -1) || (bundleName.empty())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "On ReceivePackage changed failed by error input.");
        return;
    }
    std::string maskName = SandboxManagerLog::MaskRealPath(bundleName.c_str());
    SANDBOXMANAGER_LOG_INFO(LABEL, "OnReceiveEventAdd %{public}s, %{public}d", maskName.c_str(), userID);
    SandboxManagerShare::GetInstance().GetShareCfgByBundle(bundleName, userID);
#endif
    return;
}

void SandboxManagerCommonEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData& data)
{
    const auto want = data.GetWant();
    std::string action = want.GetAction();
    SANDBOXMANAGER_LOG_INFO(LABEL, "Receive event = %{public}s.", action.c_str());
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_FULLY_REMOVED ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED) {
        return OnReceiveEventRemove(want);
    }

    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED) {
        std::string bundleName = want.GetElement().GetBundleName();
        int32_t userID = want.GetParams().GetIntParam("userId", -1);
        if ((userID == -1) || (bundleName.empty())) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "OnReceive Package changed failed by error input.");
            return;
        }
        (void)PolicyInfoManager::GetInstance().CleanPolicyByPackageChanged(bundleName, userID);
#ifdef NOT_RESIDENT
        std::string maskName = SandboxManagerLog::MaskRealPath(bundleName.c_str());
        SANDBOXMANAGER_LOG_INFO(LABEL, "OnReceive Package changed %{public}s, %{public}d", maskName.c_str(), userID);
        SandboxManagerShare::GetInstance().Refresh(bundleName, userID);
#endif
    }
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED) {
        return OnReceiveEventAdd(want);
    }
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS