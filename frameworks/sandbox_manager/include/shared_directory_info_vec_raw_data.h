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

#ifndef SHARED_DIRECTORY_INFO_VEC_RAW_DATA_H
#define SHARED_DIRECTORY_INFO_VEC_RAW_DATA_H

#include <cstdint>
#include <sstream>
#include <vector>
#include "securec.h"
#include "policy_info.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_dfx_helper.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

const uint32_t SHARED_DIRECTORY_VEC_MAX_NUM = 10000;

struct SharedDirectoryInfoVecRawData {
    uint32_t size = 0;
    const void* data = nullptr;
    std::string serializedData;

    int32_t Marshalling(const std::vector<SharedDirectoryInfo> &in)
    {
        std::stringstream ss;
        uint32_t infoNum = static_cast<uint32_t>(in.size());
        if (infoNum > SHARED_DIRECTORY_VEC_MAX_NUM) {
            std::string error = "Marshalling SharedDirectoryInfo: invalid count, too large.";
            SandboxManagerDfxHelper::WriteExceptionBranch(error);
            return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
        }
        ss.write(reinterpret_cast<const char *>(&infoNum), sizeof(infoNum));
        if (ss.fail()) {
            std::string error = "Marshalling SharedDirectoryInfo: write infoNum failed.";
            SandboxManagerDfxHelper::WriteExceptionBranch(error);
            return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
        }

        for (uint32_t i = 0; i < infoNum; i++) {
            uint32_t bundleNameLen = static_cast<uint32_t>(in[i].bundleName.length());
            ss.write(reinterpret_cast<const char *>(&bundleNameLen), sizeof(bundleNameLen));
            ss.write(in[i].bundleName.c_str(), bundleNameLen);

            uint32_t pathLen = static_cast<uint32_t>(in[i].path.length());
            ss.write(reinterpret_cast<const char *>(&pathLen), sizeof(pathLen));
            ss.write(in[i].path.c_str(), pathLen);

            ss.write(reinterpret_cast<const char *>(&in[i].permissionMode), sizeof(in[i].permissionMode));
            if (ss.fail()) {
                std::string error = "Marshalling SharedDirectoryInfo: write data failed.";
                SandboxManagerDfxHelper::WriteExceptionBranch(error);
                return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
            }
        }
        
        serializedData = ss.str();
        data = reinterpret_cast<const void *>(serializedData.data());
        size = static_cast<uint32_t>(serializedData.length());
        return SANDBOX_MANAGER_OK;
    }

    int32_t Unmarshalling(std::vector<SharedDirectoryInfo> &out) const
    {
        int32_t ret = SANDBOX_MANAGER_OK;
        std::stringstream ss;
        ss.write(reinterpret_cast<const char *>(data), size);

        uint32_t infoNum = 0;
        ss.read(reinterpret_cast<char *>(&infoNum), sizeof(infoNum));
        if (ss.fail() || ss.eof() || (infoNum > SHARED_DIRECTORY_VEC_MAX_NUM)) {
            std::string error = "Unmarshalling SharedDirectoryInfo: invalid count";
            SandboxManagerDfxHelper::WriteExceptionBranch(error);
            return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
        }

        for (uint32_t i = 0; i < infoNum; i++) {
            SharedDirectoryInfo info;

            uint32_t bundleNameLen = 0;
            ss.read(reinterpret_cast<char *>(&bundleNameLen), sizeof(bundleNameLen));
            if (ss.fail() || ss.eof() || bundleNameLen > size) {
                ret = SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
                break;
            }
            info.bundleName.resize(bundleNameLen);
            ss.read(info.bundleName.data(), bundleNameLen);
            if (ss.fail() || ss.eof()) {
                ret = SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
                break;
            }

            uint32_t pathLen = 0;
            ss.read(reinterpret_cast<char *>(&pathLen), sizeof(pathLen));
            if (ss.fail() || ss.eof() || pathLen > size) {
                ret = SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
                break;
            }
            info.path.resize(pathLen);
            ss.read(info.path.data(), pathLen);
            if (ss.fail() || ss.eof()) {
                ret = SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
                break;
            }
            ss.read(reinterpret_cast<char *>(&info.permissionMode), sizeof(info.permissionMode));
            if (ss.fail() || ss.eof()) {
                ret = SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
                break;
            }
            
            out.push_back(info);
        }

        if (ret != SANDBOX_MANAGER_OK) {
            std::string error = "Unmarshalling SharedDirectoryInfo error";
            SandboxManagerDfxHelper::WriteExceptionBranch(error);
        }
        return ret;
    }

    int32_t RawDataCpy (const void* inData)
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
#endif // SHARED_DIRECTORY_INFO_VEC_RAW_DATA_H