/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef SANDBOX_MANAGER_STUB_H
#define SANDBOX_MANAGER_STUB_H

#include <cstdint>
#include <map>
#include "iremote_stub.h"
#include "i_sandbox_manager.h"
#include "message_parcel.h"
#include "nocopyable.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class SandboxManagerStub : public IRemoteStub<ISandboxManager> {
public:
    SandboxManagerStub();
    virtual ~SandboxManagerStub();

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &options) override;

#ifdef NOT_RESIDENT
    virtual void DelayUnloadService() = 0;
#endif

private:
    int32_t CleanPersistPolicyByPathInner(MessageParcel &data, MessageParcel &reply);
    int32_t PersistPolicyInner(MessageParcel &data, MessageParcel &reply);
    int32_t UnPersistPolicyInner(MessageParcel &data, MessageParcel &reply);
    int32_t PersistPolicyByTokenIdInner(MessageParcel &data, MessageParcel &reply);
    int32_t UnPersistPolicyByTokenIdInner(MessageParcel &data, MessageParcel &reply);
    int32_t SetPolicyInner(MessageParcel &data, MessageParcel &reply);
    int32_t UnSetPolicyInner(MessageParcel &data, MessageParcel &reply);
    int32_t SetPolicyAsyncInner(MessageParcel &data, MessageParcel &reply);
    int32_t UnSetPolicyAsyncInner(MessageParcel &data, MessageParcel &reply);
    int32_t CheckPolicyInner(MessageParcel &data, MessageParcel &reply);
    int32_t StartAccessingPolicyInner(MessageParcel &data, MessageParcel &reply);
    int32_t StopAccessingPolicyInner(MessageParcel &data, MessageParcel &reply);
    int32_t CheckPersistPolicyInner(MessageParcel &data, MessageParcel &reply);
    int32_t StartAccessingByTokenIdInner(MessageParcel &data, MessageParcel &reply);
    int32_t UnSetAllPolicyByTokenInner(MessageParcel &data, MessageParcel &reply);
    void SetPolicyOpFuncInMap();
    bool IsFileManagerCalling(uint32_t tokenCaller);
    using RequestFuncType = int32_t (SandboxManagerStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, RequestFuncType> requestFuncMap_;
    uint32_t tokenFileManagerId_ = 0;
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // SANDBOX_MANAGER_STUB_H