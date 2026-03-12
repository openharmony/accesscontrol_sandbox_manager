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
#include <cstdint>
#include <sstream>
#include "securec.h"
#include "policy_info.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_dfx_helper.h"

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
            ss.write(reinterpret_cast<const char *>(&in[i].type), sizeof(in[i].type));
        }
        serializedData = ss.str();
        data = reinterpret_cast<const void *>(serializedData.data());
        size = serializedData.length();
        return SANDBOX_MANAGER_OK;
    }

    int32_t Unmarshalling(std::vector<PolicyInfo> &out) const
    {
        int32_t ret = SANDBOX_MANAGER_OK;
        std::stringstream ss;
        ss.write(reinterpret_cast<const char *>(data), size);
        uint32_t ssLength = static_cast<uint32_t>(ss.tellp());
        uint32_t policyNum = 0;
        ss.read(reinterpret_cast<char *>(&policyNum), sizeof(policyNum));
        if (ss.fail() || ss.eof() || (policyNum > POLICY_VEC_MAX_NUM)) {
            ret = SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
            std::string error = "Unmarshalling policy too big";
            SandboxManagerDfxHelper::WriteExceptionBranch(error);
        }
        for (uint32_t i = 0; i < policyNum; i++) {
            uint32_t pathLen = 0;
            ss.read(reinterpret_cast<char *>(&pathLen), sizeof(pathLen));
            if (ss.fail() || ss.eof()) {
                ret = SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
                break;
            }
            if (pathLen > ssLength - static_cast<uint32_t>(ss.tellg())) {
                ret = SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
                break;
            }
            PolicyInfo info;
            info.path.resize(pathLen);
            ss.read(info.path.data(), pathLen);
            if (ss.fail() || ss.eof()) {
                ret = SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
                break;
            }
            ss.read(reinterpret_cast<char *>(&info.mode), sizeof(info.mode));
            if (ss.fail() || ss.eof()) {
                ret = SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
                break;
            }
            ss.read(reinterpret_cast<char *>(&info.type), sizeof(info.type));
            if (ss.fail() || ss.eof()) {
                ret = SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
                break;
            }
            out.push_back(info);
        }

        if (ret != SANDBOX_MANAGER_OK) {
            std::string error = "Unmarshalling policy error";
            SandboxManagerDfxHelper::WriteExceptionBranch(error);
        }
        return ret;
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

// Helper class for batch unmarshalling - parses directly from raw data, no copy
class PolicyVecBatchReader {
public:
    explicit PolicyVecBatchReader(const PolicyVecRawData& rawData)
        : dataPtr_(static_cast<const char *>(rawData.data)),
          remainingSize_(rawData.size),
          policyCount_(0),
          isValid_(false)
    {
        // Read policy count
        if (ReadTo(&policyCount_, sizeof(policyCount_)) != SANDBOX_MANAGER_OK) {
            return;
        }

        if (policyCount_ > POLICY_VEC_MAX_NUM) {
            std::string error = "PolicyVecBatchReader: policy count too large";
            SandboxManagerDfxHelper::WriteExceptionBranch(error);
            return;
        }
        isValid_ = true;
    }

    ~PolicyVecBatchReader() = default;

    bool IsValid() const { return isValid_; }
    uint32_t GetPolicyCount() const { return policyCount_; }

    // Read next batch of policies directly from raw data - NO allocations except output
    int32_t ReadNextBatch(uint32_t count, std::vector<PolicyInfo> &out)
    {
        if (!isValid_) {
            return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
        }

        out.clear();
        out.reserve(count);
        return ReadPolicies(count, out);
    }

private:
    int32_t ReadTo(void *dest, size_t size)
    {
        if (remainingSize_ < size || memcpy_s(dest, size, dataPtr_, size) != 0) {
            std::string error = "Fail to read from data";
            SandboxManagerDfxHelper::WriteExceptionBranch(error);
            return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
        }
        dataPtr_ += size;
        remainingSize_ -= size;
        return SANDBOX_MANAGER_OK;
    }

    int32_t ReadPolicies(uint32_t count, std::vector<PolicyInfo> &out)
    {
        for (uint32_t i = 0; i < count; i++) {
            PolicyInfo info;
            uint32_t pathLen = 0;
            int32_t ret = ReadTo(&pathLen, sizeof(pathLen));
            if (ret != SANDBOX_MANAGER_OK) {
                return ret;
            }

            if (pathLen > remainingSize_) {
                std::string error = "ReadPolicies: pathLen exceeds remaining data";
                SandboxManagerDfxHelper::WriteExceptionBranch(error);
                return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
            }

            info.path.assign(dataPtr_, pathLen);
            dataPtr_ += pathLen;
            remainingSize_ -= pathLen;

            ret = ReadTo(&info.mode, sizeof(info.mode));
            if (ret != SANDBOX_MANAGER_OK) {
                return ret;
            }

            ret = ReadTo(&info.type, sizeof(info.type));
            if (ret != SANDBOX_MANAGER_OK) {
                return ret;
            }

            out.emplace_back(std::move(info));
        }

        return SANDBOX_MANAGER_OK;
    }

    const char *dataPtr_ = nullptr;
    uint32_t remainingSize_ = 0;
    uint32_t policyCount_ = 0;
    bool isValid_ = 0;
};

} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // POLICY_VEC_RAW_DATA_H
