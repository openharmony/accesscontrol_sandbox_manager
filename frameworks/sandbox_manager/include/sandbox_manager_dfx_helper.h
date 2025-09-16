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

#ifndef SANDBOX_MANAGER_DFX_HELPER_H
#define SANDBOX_MANAGER_DFX_HELPER_H
#include <cstdint>
#include <map>
#include <string>

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
enum OperateTypeEnum: int32_t {
    // temporary policy
    SET_POLICY,
    UNSET_ALL_POLICY_BY_TOKEN,
    UNSET_POLICY,
    // persist policy
    CLEAN_PERSIST_POLICY_BY_PATH,
    PERSIST_POLICY,
    REMOVE_BUNDLE_POLICY_BY_EVENT,
    START_ACCESSING_POLICY,
    START_ACCESSING_POLICY_BY_TOKEN,
    STOP_ACCESSING_POLICY,
    UNPERSIST_POLICY,
};

const static std::map<int32_t, std::string> OPERATE_TYPE_MAP = {
    // temporary policy
    {OperateTypeEnum::SET_POLICY, "set_policy"},
    {OperateTypeEnum::UNSET_ALL_POLICY_BY_TOKEN, "unset_all_policy_by_token"},
    {OperateTypeEnum::UNSET_POLICY, "unset_policy"},
    // persist policy
    {OperateTypeEnum::CLEAN_PERSIST_POLICY_BY_PATH, "clean_persist_policy_by_path"},
    {OperateTypeEnum::PERSIST_POLICY, "persist_policy"},
    {OperateTypeEnum::REMOVE_BUNDLE_POLICY_BY_EVENT, "remove_bundle_policy_by_event"},
    {OperateTypeEnum::START_ACCESSING_POLICY, "start_accessing_policy"},
    {OperateTypeEnum::START_ACCESSING_POLICY_BY_TOKEN, "start_accessing_policy_by_token"},
    {OperateTypeEnum::STOP_ACCESSING_POLICY, "stop_accessing_policy"},
    {OperateTypeEnum::UNPERSIST_POLICY, "unpersist_policy"},
};

enum OperateDomainEnum: int32_t {
    GENERIC,
    MEDIA,
};

const static std::map<int32_t, std::string> OPERATE_DOMAIN_MAP = {
    // temporary policy
    {OperateDomainEnum::GENERIC, "[g]"},
    {OperateDomainEnum::MEDIA, "[m]"},
};

class PolicyOperateInfo {
public:
    PolicyOperateInfo(
        uint32_t totalNum, uint32_t successNum,
        uint32_t failNum, uint32_t invalidNum);

    uint32_t callerPid;
    uint32_t callerTokenid;
    uint32_t policyNum;
    uint32_t successNum;
    uint32_t failNum;
    uint32_t invalidNum;
    uint32_t rModeNum;
    uint32_t wModeNum;
    uint32_t rwModeNum;
    OperateDomainEnum domain;
};

class SandboxManagerDfxHelper {
public:
    static void WritePermissionCheckFailEvent(const std::string &permission,
        const uint32_t callerTokenid = 0, const uint32_t callerPid = 0);
    static void WritePersistPolicyOperateSucc(const OperateTypeEnum operateType, const PolicyOperateInfo &info);
    static void WriteTempPolicyOperateSucc(const OperateTypeEnum operateType, const PolicyOperateInfo &info);
    static void OperateInfoSetByMode(PolicyOperateInfo &info, uint32_t mode);
};
} // SandboxManager
} // AccessControl
} // OHOS
#endif // SANDBOX_MANAGER_DFX_HELPER_H
