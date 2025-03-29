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

#ifndef UINT32_VEC_RAW_DATA_H
#define UINT32_VEC_RAW_DATA_H
#include <sstream>
#include "sandbox_manager_err_code.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
struct Uint32VecRawData {
    uint32_t size;
    const void* data;
    std::string serializedData;

    int32_t Marshalling(const std::vector<uint32_t> &in)
    {
        std::stringstream ss;
        uint32_t valueNum = in.size();
        ss.write(reinterpret_cast<const char *>(&valueNum), sizeof(valueNum));
        for (uint32_t i = 0; i < valueNum; i++) {
            ss.write(reinterpret_cast<const char *>(&in[i]), sizeof(uint32_t));
        }
        serializedData = ss.str();
        data = reinterpret_cast<const void *>(serializedData.data());
        size = serializedData.length();
        return SANDBOX_MANAGER_OK;
    }

    int32_t Unmarshalling(std::vector<uint32_t> &out) const
    {
        std::stringstream ss;
        ss.write(reinterpret_cast<const char *>(data), size);
        uint32_t valueNum = 0;
        ss.read(reinterpret_cast<char *>(&valueNum), sizeof(valueNum));
        for (uint32_t i = 0; i < valueNum; i++) {
            uint32_t value;
            ss.read(reinterpret_cast<char *>(&value), sizeof(value));
            out.emplace_back(value);
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
#endif // UINT32_VEC_RAW_DATA_H