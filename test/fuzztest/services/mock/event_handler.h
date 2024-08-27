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

#ifndef SANDBOX_MANAGER_EVENT_HANDLER_MOCK_H
#define SANDBOX_MANAGER_EVENT_HANDLER_MOCK_H
#include <cstdint>
#include <string>

namespace OHOS {
namespace AppExecFwk {
enum class ThreadMode: uint32_t {
    NEW_THREAD = 0,    // for new thread mode, event handler create thread
    FFRT,           // for new thread mode, use ffrt
};

class EventRunner final {
public:
    EventRunner() = default;
    ~EventRunner() = default;

    static std::shared_ptr<EventRunner> Create(bool inNewThread, ThreadMode mode)
    {
        return std::make_shared<EventRunner>();
    }
};

class EventHandler {
public:
    using Callback = std::function<void()>;

    explicit EventHandler(const std::shared_ptr<EventRunner> &runner = nullptr) : runner_(runner) {};

    void RemoveTask(const std::string &name) {};

    bool PostTask(const Callback &callback, const std::string &name = std::string(),
        int64_t delayTime = 0)
    {
        return true;
    };

private:
    std::shared_ptr<EventRunner> runner_;
};
} // AppExecFwk
} // OHOS
#endif // SANDBOX_MANAGER_EVENT_HANDLER_MOCK_H