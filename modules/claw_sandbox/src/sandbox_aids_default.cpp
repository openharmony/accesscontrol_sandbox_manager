
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

#include "sandbox_aids.h"
#include "sandbox_log.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <cstdlib>
#include <sys/types.h>
#include <unistd.h>

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

AidsClient::AidsClient(const std::string& device_path): fd_(-1)
{
    (void) device_path;
}

AidsClient::~AidsClient()
{
}

int AidsClient::setLabel(const uint32_t appid)
{
    (void) appid;
    return 0;
}

int AidsClient::addBlacklist(const std::string& cmd, const std::string& subcmd, const uint32_t appid)
{
    (void) cmd;
    (void) subcmd;
    (void) appid;
    return 0;
}

int AidsClient::delBlacklist(const std::string& cmd, const std::string& subcmd, const uint32_t appid)
{
    (void) cmd;
    (void) subcmd;
    (void) appid;
    return 0;
}

int AidsClient::clrBlacklist(void)
{
    return 0;
}
} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
