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

#ifndef SANDBOX_AIDS_H
#define SANDBOX_AIDS_H

#include <cstdint>
#include <string>

#include "sandbox_device_ioctl.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

class AidsClient {
public:
    explicit AidsClient(const std::string &devicePath = HKIDS_DEVICE_PATH);
    ~AidsClient();

    AidsClient(const AidsClient &) = delete;
    AidsClient &operator=(const AidsClient &) = delete;

    int SetLabel(uint32_t userid, uint64_t appIdentifier);
    int AddBlacklist(const std::string &cmd, const std::string &subcmd, uint32_t appid);
    int DelBlacklist(const std::string &cmd, const std::string &subcmd, uint32_t appid);
    int ClearBlacklist();
    bool IsOpen() const { return fd_ >= 0; }

private:
    int fd_;
};

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
#endif // SANDBOX_AIDS_H
