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
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <sys/types.h>
#include <unistd.h>

#include "securec.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

AidsClient::AidsClient(const std::string &devicePath)
{
    fd_ = open(devicePath.c_str(), O_RDWR | O_CLOEXEC);
    if (fd_ < 0) {
        std::cerr << "Error: Failed to open " << devicePath << ", err: " << std::strerror(errno) << std::endl;
        SANDBOX_LOGE("AidsClient: open %{public}s failed, errno=%{public}s",
                     devicePath.c_str(), std::strerror(errno));
        return;
    }
    SANDBOX_FDSAN_MARK(fd_, SANDBOX_FDSAN_SITE_AIDS_DEVICE);

    // The device opened but will not label anything, so drop the fd and let
    // IsOpen() report it closed. Logged here because it is the only trace: the
    // caller only ever sees "device is not open".
    if (ioctl(fd_, HM_HKIDS_CMD_SEC_INIT_AIDS, nullptr) < 0) {
        SANDBOX_LOGE("AidsClient: HM_HKIDS_CMD_SEC_INIT_AIDS on %{public}s failed, errno=%{public}s",
                     devicePath.c_str(), std::strerror(errno));
        SANDBOX_FDSAN_CLOSE(fd_, SANDBOX_FDSAN_SITE_AIDS_DEVICE);
        fd_ = -1;
    }
}

AidsClient::~AidsClient()
{
    if (fd_ >= 0) {
        SANDBOX_FDSAN_CLOSE(fd_, SANDBOX_FDSAN_SITE_AIDS_DEVICE);
    }
}

int AidsClient::SetLabel(uint32_t userid, uint64_t appIdentifier)
{
    if (!IsOpen()) {
        SANDBOX_LOGE("SetLabel: device is not open");
        return -1;
    }

    struct aids_set_ainfo_arg aidsArg = {
        .userid = userid,
        .appIdentifier = appIdentifier
    };

    struct hkids_ioctl_arg arg = {
        .module_id = 0,
        .cmd_id = AGENTID_CMD_SET_AINFO,
        .cmd_args = &aidsArg,
        .cmd_args_size = sizeof(aidsArg)
    };

    return ioctl(fd_, HM_HKIDS_CMD_SEC_EXEC_CMD, &arg);
}

int AidsClient::AddBlacklist(const std::string &cmd, const std::string &subcmd, uint32_t appid)
{
    if (!IsOpen()) {
        SANDBOX_LOGE("AddBlacklist: device is not open");
        return -1;
    }

    struct hkids_blacklist_cmd_arg aidsArg;
    if (memset_s(&aidsArg, sizeof(aidsArg), 0, sizeof(aidsArg)) != 0) {
        SANDBOX_LOGE("AddBlacklist: memset blacklist arg failed");
        return -1;
    }
    if (strncpy_s(aidsArg.command, HKIDS_CMD_MAX_SIZE, cmd.c_str(), HKIDS_CMD_MAX_SIZE) != 0) {
        SANDBOX_LOGE("AddBlacklist: copy cmd failed, len=%{public}zu max=%{public}zu",
                     cmd.size(), HKIDS_CMD_MAX_SIZE);
        return -1;
    }
    if (strncpy_s(aidsArg.subcommand, HKIDS_CMD_MAX_SIZE, subcmd.c_str(), HKIDS_CMD_MAX_SIZE) != 0) {
        SANDBOX_LOGE("AddBlacklist: copy subcmd failed, len=%{public}zu max=%{public}zu",
                     subcmd.size(), HKIDS_CMD_MAX_SIZE);
        return -1;
    }
    aidsArg.appid = appid;

    struct hkids_ioctl_arg arg = {
        .module_id = 0,
        .cmd_id = BLACKLIST_CMD_ADD,
        .cmd_args = &aidsArg,
        .cmd_args_size = sizeof(aidsArg)
    };

    return ioctl(fd_, HM_HKIDS_CMD_SEC_EXEC_CMD, &arg);
}

int AidsClient::DelBlacklist(const std::string &cmd, const std::string &subcmd, uint32_t appid)
{
    if (!IsOpen()) {
        SANDBOX_LOGE("DelBlacklist: device is not open");
        return -1;
    }

    struct hkids_blacklist_cmd_arg aidsArg;
    if (memset_s(&aidsArg, sizeof(aidsArg), 0, sizeof(aidsArg)) != 0) {
        SANDBOX_LOGE("DelBlacklist: memset blacklist arg failed");
        return -1;
    }
    if (strncpy_s(aidsArg.command, HKIDS_CMD_MAX_SIZE, cmd.c_str(), HKIDS_CMD_MAX_SIZE) != 0) {
        SANDBOX_LOGE("DelBlacklist: copy cmd failed, len=%{public}zu max=%{public}zu",
                     cmd.size(), HKIDS_CMD_MAX_SIZE);
        return -1;
    }
    if (strncpy_s(aidsArg.subcommand, HKIDS_CMD_MAX_SIZE, subcmd.c_str(), HKIDS_CMD_MAX_SIZE) != 0) {
        SANDBOX_LOGE("DelBlacklist: copy subcmd failed, len=%{public}zu max=%{public}zu",
                     subcmd.size(), HKIDS_CMD_MAX_SIZE);
        return -1;
    }
    aidsArg.appid = appid;

    struct hkids_ioctl_arg arg = {
        .module_id = 0,
        .cmd_id = BLACKLIST_CMD_REMOVE,
        .cmd_args = &aidsArg,
        .cmd_args_size = sizeof(aidsArg)
    };

    return ioctl(fd_, HM_HKIDS_CMD_SEC_EXEC_CMD, &arg);
}

int AidsClient::ClearBlacklist()
{
    if (!IsOpen()) {
        SANDBOX_LOGE("ClearBlacklist: device is not open");
        return -1;
    }

    struct hkids_ioctl_arg arg = {
        .module_id = 0,
        .cmd_id = BLACKLIST_CMD_CLEAR,
        .cmd_args = nullptr,
        .cmd_args_size = 0
    };

    return ioctl(fd_, HM_HKIDS_CMD_SEC_EXEC_CMD, &arg);
}
} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
