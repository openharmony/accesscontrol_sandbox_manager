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

#include "startbyeventaction_fuzzer.h"

#include <vector>
#include <cstdint>
#include <string>
#include <map>
#include "alloc_token.h"
#include "fuzz_common.h"
#include "isandbox_manager.h"
#include "policy_info_parcel.h"
#define private public
#include "sandbox_manager_service.h"
#undef private
#include "accesstoken_kit.h"
#include "sandbox_manager_kit.h"
#include "token_setproc.h"

using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
namespace {
enum EventType {
    EVENT_PACKAGE_REMOVED = 0,
    EVENT_PACKAGE_CHANGED,
    EVENT_PACKAGE_ADDED,
    EVENT_RANDOM,
    EVENT_MAX
};
const uint8_t EVENT_TYPE_MAX = EVENT_MAX;
    bool TestPackageRemoveEvent(const uint8_t *data, size_t size)
    {
        SystemAbilityOnDemandReason startReason;

        // Test with valid event name
        startReason.SetName("usual.event.PACKAGE_REMOVED");

        // Prepare extra data
        PolicyInfoRandomGenerator gen(data, size);
        std::string bundleName;
        std::string userIdStr;
        std::string tokenIdStr;
        std::string appIndexStr;
        std::string shouldPreserve;

        gen.GenerateString(bundleName);
        gen.GenerateString(shouldPreserve);

        uint32_t userId = gen.GetData<uint32_t>() % 1000;
        uint32_t tokenId = gen.GetData<uint32_t>() % 1000000 + 100000;
        int32_t appIndex = gen.GetData<int32_t>() % 10;

        userIdStr = std::to_string(userId);
        tokenIdStr = std::to_string(tokenId);
        appIndexStr = std::to_string(appIndex);

        std::map<std::string, std::string> want;
        want["bundleName"] = bundleName;
        want["userId"] = userIdStr;
        want["accessTokenId"] = tokenIdStr;
        want["appIndex"] = appIndexStr;
        want["ohos.fileshare.supportPreservePersistentPermission"] = shouldPreserve;

        OnDemandReasonExtraData extraData(0, "fuzz_test", want);
        startReason.SetExtraData(extraData);

        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        return DelayedSingleton<SandboxManagerService>::GetInstance()->StartByEventAction(startReason);
    }

    bool TestPackageChangedEvent(const uint8_t *data, size_t size)
    {
        SystemAbilityOnDemandReason startReason;

        // Test with valid event name
        startReason.SetName("usual.event.PACKAGE_CHANGED");

        // Prepare extra data with isModuleUpdate = "true"
        PolicyInfoRandomGenerator gen(data, size);
        std::string bundleName;
        std::string userIdStr;
        std::string tokenIdStr;

        gen.GenerateString(bundleName);

        uint32_t userId = gen.GetData<uint32_t>() % 1000;
        uint32_t tokenId = gen.GetData<uint32_t>() % 1000000 + 100000;

        userIdStr = std::to_string(userId);
        tokenIdStr = std::to_string(tokenId);

        std::map<std::string, std::string> want;
        want["bundleName"] = bundleName;
        want["userId"] = userIdStr;
        want["accessTokenId"] = tokenIdStr;
        want["isModuleUpdate"] = "true";  // Required for this event

        OnDemandReasonExtraData extraData(0, "fuzz_test", want);
        startReason.SetExtraData(extraData);

        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        return DelayedSingleton<SandboxManagerService>::GetInstance()->StartByEventAction(startReason);
    }

    bool TestPackageAddEvent(const uint8_t *data, size_t size)
    {
        SystemAbilityOnDemandReason startReason;

        // Test with valid event name
        startReason.SetName("usual.event.PACKAGE_ADDED");

        // Prepare extra data
        PolicyInfoRandomGenerator gen(data, size);
        std::string bundleName;
        std::string appIdentifier;
        std::string userIdStr;
        std::string tokenIdStr;

        gen.GenerateString(bundleName);
        gen.GenerateString(appIdentifier);

        uint32_t userId = gen.GetData<uint32_t>() % 1000;
        uint32_t tokenId = gen.GetData<uint32_t>() % 1000000 + 100000;

        userIdStr = std::to_string(userId);
        tokenIdStr = std::to_string(tokenId);

        std::map<std::string, std::string> want;
        want["bundleName"] = bundleName;
        want["userId"] = userIdStr;
        want["accessTokenId"] = tokenIdStr;
        want["appIdentifier"] = appIdentifier;

        OnDemandReasonExtraData extraData(0, "fuzz_test", want);
        startReason.SetExtraData(extraData);

        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        return DelayedSingleton<SandboxManagerService>::GetInstance()->StartByEventAction(startReason);
    }
}

    bool StartByEventActionFuzzTest(const uint8_t *data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(uint8_t))) {
            return false;
        }

        // Use first byte to select which event to test
        uint8_t eventType = data[0] % EVENT_TYPE_MAX;

        bool result = false;
        switch (eventType) {
            case EVENT_PACKAGE_REMOVED:
                // Test PACKAGE_REMOVED event
                result = TestPackageRemoveEvent(data + 1, size - 1);
                break;
            case EVENT_PACKAGE_CHANGED:
                // Test PACKAGE_CHANGED event
                result = TestPackageChangedEvent(data + 1, size - 1);
                break;
            case EVENT_PACKAGE_ADDED:
                // Test PACKAGE_ADDED event
                result = TestPackageAddEvent(data + 1, size - 1);
                break;
            case EVENT_RANDOM:
                // Test with random event name (original behavior)
                {
                    PolicyInfoRandomGenerator gen(data + 1, size - 1);
                    std::string name;
                    std::string name1;
                    std::string name2;
                    gen.GenerateString(name);
                    gen.GenerateString(name1);
                    gen.GenerateString(name2);

                    SystemAbilityOnDemandReason startReason;
                    startReason.SetName(name.c_str());

                    DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
                    DelayedSingleton<SandboxManagerService>::GetInstance()->StartByEventAction(startReason);

                    std::map<std::string, std::string> want = {{name1.c_str(), name2.c_str()}};
                    OnDemandReasonExtraData extraData2(0, "test", want);
                    startReason.SetExtraData(extraData2);
                    DelayedSingleton<SandboxManagerService>::GetInstance()->StartByEventAction(startReason);
                    result = true;
                }
                break;
            default:
                result = false;
                break;
        }

        return result;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::StartByEventActionFuzzTest(data, size);
    return 0;
}
