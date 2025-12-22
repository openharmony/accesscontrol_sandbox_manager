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

#ifndef SANDBOX_MANAGER_EVENT_SUBSCRIBER_H
#define SANDBOX_MANAGER_EVENT_SUBSCRIBER_H
#include "common_event_manager.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class SandboxManagerCommonEventSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    SandboxManagerCommonEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo& info)
        : CommonEventSubscriber(info)
    {}

    ~SandboxManagerCommonEventSubscriber() = default;

    static bool RegisterEvent();
    static bool UnRegisterEvent();

    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData& data) override;
    void OnReceiveEventRemove(const EventFwk::Want &want);
    void OnReceiveEventAdd(const EventFwk::Want &want);
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // SANDBOX_MANAGER_EVENT_SUBSCRIBER_H