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

#ifndef PERMISSION_STATUS_INFO_VEC_RAW_DATA_H
#define PERMISSION_STATUS_INFO_VEC_RAW_DATA_H

#include <cstdint>
#include <sstream>
#include "securec.h"
#include "policy_info.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_dfx_helper.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

const uint32_t PERMISSION_STATUS_INFO_VEC_MAX_NUM = 10000;

struct PermissionStatusInfoVecRawData {
    uint32_t size = 0;
    const void* data = nullptr;
    std::string serializedData;

    static void ReportError(const std::string &msg)
    {
        std::string error = msg;
        SandboxManagerDfxHelper::WriteExceptionBranch(error);
    }

    static void WriteSingleInfo(std::stringstream &ss, const PermissionStatusInfo &info)
    {
        ss.write(reinterpret_cast<const char *>(&info.tokenId), sizeof(info.tokenId));
        uint32_t pathLen = static_cast<uint32_t>(info.policyInfo.path.length());
        ss.write(reinterpret_cast<const char *>(&pathLen), sizeof(pathLen));
        ss.write(info.policyInfo.path.c_str(), pathLen);
        ss.write(reinterpret_cast<const char *>(&info.policyInfo.mode), sizeof(info.policyInfo.mode));
        ss.write(reinterpret_cast<const char *>(&info.policyInfo.type), sizeof(info.policyInfo.type));
        ss.write(reinterpret_cast<const char *>(&info.grantStatus), sizeof(info.grantStatus));
    }

    static int32_t ReadSingleInfo(std::stringstream &ss, uint32_t ssLength, PermissionStatusInfo &info)
    {
        ss.read(reinterpret_cast<char *>(&info.tokenId), sizeof(info.tokenId));
        if (ss.fail() || ss.eof()) {
            return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
        }
        uint32_t pathLen = 0;
        ss.read(reinterpret_cast<char *>(&pathLen), sizeof(pathLen));
        if (ss.fail() || ss.eof() || pathLen > ssLength - static_cast<uint32_t>(ss.tellg())) {
            return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
        }
        info.policyInfo.path.resize(pathLen);
        ss.read(info.policyInfo.path.data(), pathLen);
        if (ss.fail() || ss.eof()) {
            return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
        }
        ss.read(reinterpret_cast<char *>(&info.policyInfo.mode), sizeof(info.policyInfo.mode));
        if (ss.fail() || ss.eof()) {
            return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
        }
        ss.read(reinterpret_cast<char *>(&info.policyInfo.type), sizeof(info.policyInfo.type));
        if (ss.fail() || ss.eof()) {
            return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
        }
        ss.read(reinterpret_cast<char *>(&info.grantStatus), sizeof(info.grantStatus));
        if (ss.fail() || ss.eof()) {
            return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
        }
        return SANDBOX_MANAGER_OK;
    }

    int32_t Marshalling(const std::vector<PermissionStatusInfo> &in)
    {
        uint32_t infoNum = static_cast<uint32_t>(in.size());
        if (infoNum > PERMISSION_STATUS_INFO_VEC_MAX_NUM) {
            ReportError("Marshalling PermissionStatusInfo: too large.");
            return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
        }
        std::stringstream ss;
        ss.write(reinterpret_cast<const char *>(&infoNum), sizeof(infoNum));
        for (uint32_t i = 0; i < infoNum; i++) {
            WriteSingleInfo(ss, in[i]);
        }
        if (ss.fail()) {
            ReportError("Marshalling PermissionStatusInfo: write failed.");
            return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
        }
        serializedData = ss.str();
        data = reinterpret_cast<const void *>(serializedData.data());
        size = static_cast<uint32_t>(serializedData.length());
        return SANDBOX_MANAGER_OK;
    }

    int32_t Unmarshalling(std::vector<PermissionStatusInfo> &out) const
    {
        std::stringstream ss;
        ss.write(reinterpret_cast<const char *>(data), size);
        uint32_t ssLength = static_cast<uint32_t>(ss.tellp());
        uint32_t infoNum = 0;
        ss.read(reinterpret_cast<char *>(&infoNum), sizeof(infoNum));
        if (ss.fail() || ss.eof() || infoNum > PERMISSION_STATUS_INFO_VEC_MAX_NUM) {
            ReportError("Unmarshalling PermissionStatusInfo: invalid count");
            return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
        }
        for (uint32_t i = 0; i < infoNum; i++) {
            PermissionStatusInfo info;
            if (ReadSingleInfo(ss, ssLength, info) != SANDBOX_MANAGER_OK) {
                ReportError("Unmarshalling PermissionStatusInfo error");
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
#endif // PERMISSION_STATUS_INFO_VEC_RAW_DATA_H
