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
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"
#include "accesstoken_kit.h"
#include "share_files.h"
#include "persistent_preserve.h"

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

static int32_t OnReceiveEventGetParam(const EventFwk::Want &want,
    std::string &bundleName, int32_t &userId, uint32_t &tokenId)
{
    bundleName = want.GetElement().GetBundleName();
    if (bundleName.empty()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "OnReceiveEvent get bundleName empty.");
        return INVALID_PARAMTER;
    }

    tokenId = static_cast<uint32_t>(want.GetParams().GetIntParam("accessTokenId", 0));
    if (tokenId == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "OnReceiveEvent get error tokenid = %{public}u of %{public}s.",
            tokenId, bundleName.c_str());
        return INVALID_PARAMTER;
    }

    userId = want.GetParams().GetIntParam("userId", -1);
    if (userId == -1) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "OnReceiveEvent get error userId of %{public}s.", bundleName.c_str());
        return INVALID_PARAMTER;
    }

    return SANDBOX_MANAGER_OK;
}

void SandboxManagerCommonEventSubscriber::OnReceiveEventRemove(const EventFwk::Want &want)
{
    std::string bundleName;
    int32_t userId = -1;
    uint32_t tokenId = 0;
    int32_t ret = OnReceiveEventGetParam(want, bundleName, userId, tokenId);
    if (ret != SANDBOX_MANAGER_OK) {
        return;
    }

    SANDBOXMANAGER_LOG_INFO(LABEL, "OnReceiveEventRemove %{public}s, tokenId=%{public}u, userId=%{public}d",
        bundleName.c_str(), tokenId, userId);

    int32_t appIndex = want.GetIntParam("appIndex", -1);
    std::string shouldPreserve;
    if (appIndex == 0) {
        shouldPreserve = want.GetStringParam("ohos.fileshare.supportPreservePersistentPermission");
        if (shouldPreserve.empty()) {
            LOGE_WITH_REPORT(LABEL, "OnReceiveEventRemove get shouldPreserve empty.");
            return;
        }
        SANDBOXMANAGER_LOG_INFO(LABEL, "main package removed, PreserveConfig=%{public}s", shouldPreserve.c_str());
        if (shouldPreserve == "true") {
            std::string appIdentifier = want.GetStringParam("appIdentifier");
            ret = PersistentPreserve::SaveBundlePersistentPolicies(bundleName, userId, appIdentifier, tokenId);
            if (ret != SANDBOX_MANAGER_OK) {
                LOGE_WITH_REPORT(LABEL, "SaveBundlePersistentPolicies failed for %{public}s", bundleName.c_str());
            }
        }
    }

    if (shouldPreserve != "true") {
        // Remove bundle policy
        PolicyInfoManager::GetInstance().RemoveBundlePolicy(tokenId);
    }
#ifdef NOT_RESIDENT
    if (appIndex != 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "ReceivePackage removed only clear main, this is %{public}d", appIndex);
        return;
    }
    SandboxManagerShare::GetInstance().DeleteByBundleName(bundleName);
#endif
    SANDBOXMANAGER_LOG_INFO(LABEL, "OnReceiveEventRemove Finish");
    return;
}

void SandboxManagerCommonEventSubscriber::OnReceiveEventAdd(const EventFwk::Want &want)
{
    std::string bundleName;
    int32_t userId = -1;
    uint32_t tokenId = 0;
    int32_t ret = OnReceiveEventGetParam(want, bundleName, userId, tokenId);
    if (ret != SANDBOX_MANAGER_OK) {
        return;
    }
    std::string appIdentifier = want.GetStringParam("appIdentifier");
    SANDBOXMANAGER_LOG_INFO(LABEL, "OnReceiveEventAdd %{public}s, %{public}s, tokenId=%{public}u, userId=%{public}d",
        bundleName.c_str(), appIdentifier.c_str(), tokenId, userId);

    ret = PersistentPreserve::RestoreBundlePersistentPolicies(appIdentifier, userId, tokenId, bundleName);
    if (ret != SANDBOX_MANAGER_OK) {
        return;
    }
    ret = PersistentPreserve::DeleteBundlePersistentPolicies(appIdentifier, userId);
    if (ret != SANDBOX_MANAGER_OK) {
        return;
    }

#ifdef NOT_RESIDENT
    SandboxManagerShare::GetInstance().GetShareCfgByBundle(bundleName, userId);
#endif
    SANDBOXMANAGER_LOG_INFO(LABEL, "OnReceiveEventAdd Finish");
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
        bool isModuleUpdate = want.GetBoolParam("isModuleUpdate", false);
        if (isModuleUpdate != true) {
            SANDBOXMANAGER_LOG_INFO(LABEL, "OnReceive Package changed is not ModuleUpdate.");
            return;
        }
        std::string bundleName = want.GetElement().GetBundleName();
        int32_t userID = want.GetParams().GetIntParam("userId", -1);
        if ((userID == -1) || (bundleName.empty())) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "OnReceive Package changed failed by error input.");
            return;
        }
        (void)PolicyInfoManager::GetInstance().CleanPolicyByPackageChanged(bundleName, userID);
#ifdef NOT_RESIDENT
        SANDBOXMANAGER_LOG_INFO(LABEL, "OnReceive Package changed %{public}s, %{public}d", bundleName.c_str(), userID);
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