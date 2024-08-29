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

#include "sandbox_manager_dfx_helper.h"

#include "hisysevent.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

static std::string GetOperateString(const OperateTypeEnum operateType)
{
    auto it = OPERATE_TYPE_MAP.find(operateType);
    if (it == OPERATE_TYPE_MAP.end()) {
        return "unknown_type";
    }
    return it->second;
}

PolicyOperateInfo::PolicyOperateInfo(uint32_t totalNum, uint32_t successNum,
    uint32_t failNum, uint32_t invalidNum) : policyNum(totalNum),
    successNum(successNum), failNum(failNum), invalidNum(invalidNum)
{
    callerPid = static_cast<uint32_t>(IPCSkeleton::GetCallingRealPid());
    callerTokenid = IPCSkeleton::GetCallingTokenID();
}

void SandboxManagerDfxHelper::WritePermissionCheckFailEvent(const std::string &permission,
    const uint32_t callerTokenid, const uint32_t callerPid)
{
    uint32_t inputPid = callerPid;
    if (inputPid == 0) {
        inputPid = static_cast<uint32_t>(IPCSkeleton::GetCallingRealPid());
    }
    uint32_t inputTokenid = callerTokenid;
    if (inputTokenid == 0) {
        inputTokenid = IPCSkeleton::GetCallingTokenID();
    }
    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::SANDBOX_MANAGER, "CALLER_PERMISSION_CHECK_FAILED",
        HiviewDFX::HiSysEvent::EventType::FAULT, "CALLER_PID", inputPid,
        "CALLER_TOKENID", inputTokenid, "PERMISSION_NAME", permission);
}

void SandboxManagerDfxHelper::WritePersistPolicyOperateSucc(
    const OperateTypeEnum operateType, const PolicyOperateInfo &info)
{
    std::string type = GetOperateString(operateType);
    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::SANDBOX_MANAGER, "PERSIST_POLICY_OPERATE_SUCCESS",
        HiviewDFX::HiSysEvent::EventType::FAULT, "OPERATE_TYPE", type,
        "CALLER_PID", info.callerPid, "CALLER_TOKENID", info.callerTokenid,
        "TOTAL_NUM", info.policyNum, "SUCCESS_NUM", info.successNum,
        "FAIL_NUM", info.failNum, "INVALID_NUM", info.invalidNum);
}

void SandboxManagerDfxHelper::WriteTempPolicyOperateSucc(
    const OperateTypeEnum operateType, const PolicyOperateInfo &info)
{
    uint32_t type = static_cast<uint32_t>(operateType);
    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::SANDBOX_MANAGER, "TEMPORARY_POLICY_OPERATE_SUCCESS",
        HiviewDFX::HiSysEvent::EventType::FAULT, "OPERATE_TYPE", type,
        "CALLER_PID", info.callerPid, "CALLER_TOKENID", info.callerTokenid,
        "TOTAL_NUM", info.policyNum, "SUCCESS_NUM", info.successNum,
        "FAIL_NUM", info.failNum, "INVALID_NUM", info.invalidNum);
}
}
}
}