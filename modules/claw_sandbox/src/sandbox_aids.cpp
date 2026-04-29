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
#include <cstring>
#include <sys/types.h>
#include <unistd.h>
#include "securec.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

AidsClient::AidsClient(const std::string& device_path)
{
    fd_ = open(device_path.c_str(), O_RDWR);
    if (fd_ < 0) {
        SANDBOX_LOGE("Failed to open device: %{public}s, error: %{public}s", device_path.c_str(), std::strerror(errno));
        return;
    }

    if (ioctl(fd_, HM_HKIDS_CMD_SEC_INIT_AIDS, NULL) < 0) {
        close(fd_);
        fd_ = -1;
    }
}

AidsClient::~AidsClient()
{
    if (fd_ >= 0) {
        close(fd_);
    }
}

int AidsClient::setLabel(const uint32_t appid)
{
    if (!isOpen()) {
        SANDBOX_LOGE("Device node is not open");
        return -1;
    }

    struct aids_set_ainfo_arg aidsArg = {
        .appid = appid
    };

    struct hkids_ioctl_arg arg = {
        .module_id = 0,
        .cmd_id = AGENTID_CMD_SET_AINFO,
        .cmd_args = &aidsArg,
        .cmd_args_size = sizeof(aidsArg)
    };

    return ioctl(fd_, HM_HKIDS_CMD_SEC_EXEC_CMD, &arg);
}

int AidsClient::addBlacklist(const std::string& cmd, const std::string& subcmd, const uint32_t appid)
{
    int ret;
    if (!isOpen()) {
        SANDBOX_LOGE("Device node is not open");
        return -1;
    }

    struct hkids_blacklist_cmd_arg aidsArg;
    memset_s(&aidsArg, sizeof(aidsArg), 0, sizeof(aidsArg));
    ret = strncpy_s(aidsArg.command, HKIDS_CMD_MAX_SIZE, cmd.c_str(), HKIDS_CMD_MAX_SIZE);
    if (ret != 0) {
        SANDBOX_LOGE("cmd copy failed\n");
        return -1;
    }
    ret = strncpy_s(aidsArg.subcommand, HKIDS_CMD_MAX_SIZE, subcmd.c_str(), HKIDS_CMD_MAX_SIZE);
    if (ret != 0) {
        SANDBOX_LOGE("subcmd copy failed\n");
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

int AidsClient::delBlacklist(const std::string& cmd, const std::string& subcmd, const uint32_t appid)
{
    int ret;
    if (!isOpen()) {
        SANDBOX_LOGE("Device node is not open");
        return -1;
    }

    struct hkids_blacklist_cmd_arg aidsArg;
    memset_s(&aidsArg, sizeof(aidsArg), 0, sizeof(aidsArg));
    ret = strncpy_s(aidsArg.command, HKIDS_CMD_MAX_SIZE, cmd.c_str(), HKIDS_CMD_MAX_SIZE);
    if (ret != 0) {
        SANDBOX_LOGE("cmd copy failed\n");
        return -1;
    }
    ret = strncpy_s(aidsArg.subcommand, HKIDS_CMD_MAX_SIZE, subcmd.c_str(), HKIDS_CMD_MAX_SIZE);
    if (ret != 0) {
        SANDBOX_LOGE("subcmd copy failed\n");
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

int AidsClient::clrBlacklist(void)
{
    if (!isOpen()) {
        SANDBOX_LOGE("Device node is not open");
        return -1;
    }

    struct hkids_ioctl_arg arg = {
        .module_id = 0,
        .cmd_id = BLACKLIST_CMD_CLEAR,
        .cmd_args = NULL,
        .cmd_args_size = 0
    };

    return ioctl(fd_, HM_HKIDS_CMD_SEC_EXEC_CMD, &arg);
}
} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
