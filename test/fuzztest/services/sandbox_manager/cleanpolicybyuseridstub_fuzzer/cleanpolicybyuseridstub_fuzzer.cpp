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

#include "cleanpolicybyuseridstub_fuzzer.h"

#include <vector>
#include <cstdint>
#include <string>
#include "accesstoken_kit.h"
#include "fuzz_common.h"
#include "isandbox_manager.h"
#include "policy_info_vector_parcel.h"
#define private public
#include "sandbox_manager_service.h"
#undef private
#include "sandbox_manager_kit.h"
#include "token_setproc.h"

using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
namespace {
static uint32_t SELF_TOKEN = 0;
static uint32_t FILE_MANAGER_TOKEN = 0;
};
    bool CleanPolicyByUserIdStubFuzzTest(const uint8_t *data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }
        FILE_MANAGER_TOKEN = Security::AccessToken::AccessTokenKit::GetNativeTokenId(
            "file_manager_service");
        SELF_TOKEN = GetSelfTokenID();
        SetSelfTokenID(FILE_MANAGER_TOKEN);

        std::vector<std::string> pathList;
        PolicyInfoRandomGenerator gen(data, size);
        uint32_t userId = gen.GetData<uint32_t>();
        gen.GenerateStringVec(pathList);

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }

        if (!datas.WriteUint32(userId)) {
            return false;
        }

        if (!datas.WriteStringVector(pathList)) {
            return false;
        }

        // for test all branch, need write something in rdb
        uint8_t isWriteRdb = gen.GetData<uint8_t>();
        if (isWriteRdb & 1) {
            std::vector<PolicyInfo> policy;
            uint64_t policyFlag = 1;
            std::vector<uint32_t> policyResult;
            PolicyInfo infoParent = {
                .path = "/A/B",
                .mode = OperateMode::READ_MODE
            };
            policy.emplace_back(infoParent);
            SandboxManagerKit::SetPolicy(GetSelfTokenID(), policy, policyFlag, policyResult);
            SandboxManagerKit::PersistPolicy(policy, policyResult);
        }
        uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_CLEAN_POLICY_BY_USER_ID);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();
        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        SetSelfTokenID(SELF_TOKEN);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::CleanPolicyByUserIdStubFuzzTest(data, size);
    return 0;
}