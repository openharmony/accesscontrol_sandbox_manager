/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "persist_activate_appdata_fuzzer.h"

#include <vector>
#include <cstdint>
#include <string>
#include "alloc_token.h"
#include "fuzz_common.h"
#include "isandbox_manager.h"
#include "policy_vec_raw_data.h"
#include "uint32_vec_raw_data.h"
#include "bool_vec_raw_data.h"
#define private public
#include "sandbox_manager_service.h"
#undef private
#include "accesstoken_kit.h"
#include "token_setproc.h"

using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
namespace {
const std::string PERSIST_PARENT_PATH = "/storage/Users/currentUser";
const uint64_t PERSIST_PARENT_MODE = OperateMode::READ_MODE;
}

static bool PersistParentPolicy()
{
    std::vector<PolicyInfo> policyVec;
    PolicyInfo policy;
    policy.path = PERSIST_PARENT_PATH;
    policy.mode = PERSIST_PARENT_MODE;
    policyVec.push_back(policy);

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        return false;
    }

    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policyVec);
    if (!datas.WriteUint32(policyRawData.size)) {
        return false;
    }
    if (!datas.WriteRawData(policyRawData.data, policyRawData.size)) {
        return false;
    }

    uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_PERSIST_POLICY);
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
    return true;
}

static bool StartAccessingAppdataPath(const std::string &activatePath, uint32_t tokenId)
{
    std::vector<PolicyInfo> policyVec;
    PolicyInfo policy;
    policy.path = activatePath;
    policy.mode = PERSIST_PARENT_MODE;
    policyVec.push_back(policy);

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        return false;
    }

    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policyVec);
    if (!datas.WriteUint32(policyRawData.size)) {
        return false;
    }
    if (!datas.WriteRawData(policyRawData.data, policyRawData.size)) {
        return false;
    }

    uint32_t useCallerToken = 1; // use provided tokenId
    if (!datas.WriteUint32(useCallerToken)) {
        return false;
    }
    if (!datas.WriteUint32(tokenId)) {
        return false;
    }
    uint64_t timestamp = 0;
    if (!datas.WriteUint64(timestamp)) {
        return false;
    }

    uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_START_ACCESSING_POLICY);
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
    return true;
}

static bool CheckPolicyAppDataStub(const PolicyInfo &policy, uint32_t tokenId)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        return false;
    }
    if (!datas.WriteUint32(tokenId)) {
        return false;
    }
    std::vector<PolicyInfo> policyVec = {policy};
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policyVec);
    if (!datas.WriteUint32(policyRawData.size)) {
        return false;
    }
    if (!datas.WriteRawData(policyRawData.data, policyRawData.size)) {
        return false;
    }
    uint32_t code = static_cast<uint32_t>(ISandboxManagerIpcCode::COMMAND_CHECK_POLICY);
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

    int32_t errCode = 0;
    if (!reply.ReadInt32(errCode)) {
        return false;
    }
    if (errCode != SANDBOX_MANAGER_OK) {
        return false;
    }
    uint32_t resultSize = 0;
    if (!reply.ReadUint32(resultSize)) {
        return false;
    }
    const void* rawData = reply.ReadRawData(resultSize);
    if (rawData == nullptr) {
        return false;
    }
    BoolVecRawData resultRawData;
    resultRawData.size = resultSize;
    resultRawData.RawDataCpy(rawData);
    std::vector<bool> results;
    resultRawData.Unmarshalling(results);
    if (results.empty()) {
        return false;
    }
    return results[0];
}

bool PersistActivateAppdataFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    PolicyInfoRandomGenerator gen(data, size);
    uint32_t tokenId = GetSelfTokenID();

    DelayedSingleton<SandboxManagerService>::GetInstance()->Initialize();

    // Step 1: Persist parent path /storage/Users/currentUser with READ_MODE.
    PersistParentPolicy();

    std::string suffix;
    uint32_t suffixLen = gen.GetData<uint8_t>() % 64; // 0-63 chars
    for (uint32_t i = 0; i < suffixLen; ++i) {
        suffix += gen.GetData<char>();
    }
    std::string activatePath = "/storage/Users/currentUser/" + suffix;

    StartAccessingAppdataPath(activatePath, tokenId);

    // Step 4: CheckPolicy on appdata path — must always return false
    PolicyInfo appdataPolicy;
    appdataPolicy.path = "/storage/Users/currentUser/appdata";
    appdataPolicy.mode = PERSIST_PARENT_MODE;
    bool appdataHasPermission = CheckPolicyAppDataStub(appdataPolicy, tokenId);
    if (appdataHasPermission) {
        return false;
    }

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::AllocTokenWithFuzz(data, size, OHOS::PersistActivateAppdataFuzzTest);
    return 0;
}
