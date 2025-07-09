/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef POLICY_VEC_RAW_DATA_H
#define POLICY_VEC_RAW_DATA_H
#include <sstream>
#include "policy_info.h"
#include "sandbox_manager_err_code.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
const uint32_t POLICY_VEC_MAX_NUM = 300000;
struct PolicyVecRawData {
    uint32_t size;
    const void* data;
    std::string serializedData;

    int32_t Marshalling(const std::vector<PolicyInfo> &in)
    {
        std::stringstream ss;
        uint32_t policyNum = in.size();
        ss.write(reinterpret_cast<const char *>(&policyNum), sizeof(policyNum));
        for (uint32_t i = 0; i < policyNum; i++) {
            uint32_t pathLen = in[i].path.length();
            ss.write(reinterpret_cast<const char *>(&pathLen), sizeof(pathLen));
            ss.write(in[i].path.c_str(), pathLen);
            ss.write(reinterpret_cast<const char *>(&in[i].mode), sizeof(in[i].mode));
        }
        serializedData = ss.str();
        data = reinterpret_cast<const void *>(serializedData.data());
        size = serializedData.length();
        return SANDBOX_MANAGER_OK;
    }

    int32_t Unmarshalling(std::vector<PolicyInfo> &out) const
    {
        std::stringstream ss;
        ss.write(reinterpret_cast<const char *>(data), size);
        uint32_t ssLength = static_cast<uint32_t>(ss.tellp());
        uint32_t policyNum = 0;
        ss.read(reinterpret_cast<char *>(&policyNum), sizeof(policyNum));
        if (ss.fail() || ss.eof() || (policyNum > POLICY_VEC_MAX_NUM)) {
            return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
        }
        for (uint32_t i = 0; i < policyNum; i++) {
            uint32_t pathLen = 0;
            ss.read(reinterpret_cast<char *>(&pathLen), sizeof(pathLen));
            if (ss.fail() || ss.eof()) {
                return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
            }
            if (pathLen > ssLength - static_cast<uint32_t>(ss.tellg())) {
                return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
            }
            PolicyInfo info;
            info.path.resize(pathLen);
            ss.read(info.path.data(), pathLen);
            if (ss.fail() || ss.eof()) {
                return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
            }
            ss.read(reinterpret_cast<char *>(&info.mode), sizeof(info.mode));
            if (ss.fail() || ss.eof()) {
                return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
            }
            out.push_back(info);
        }
        return SANDBOX_MANAGER_OK;
    }

    int32_t RawDataCpy(const void* inData)
    {
        std::stringstream ss;
        ss.write(reinterpret_cast<const char *>(inData), size);
        serializedData = ss.str();
        data = reinterpret_cast<const void *>(serializedData.data());
        return SANDBOX_MANAGER_OK;
    }
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // POLICY_VEC_RAW_DATA_H