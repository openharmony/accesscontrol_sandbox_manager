
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

#include <sys/ioctl.h>
#include <string>

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

#define DEFAULT_APPID 1001
#define HKIDS_CMD_MAX_SIZE 64
#define DEVICE_NODE "/dev/hkids"

#define HM_HKIDS_IOCTL_BASE             'h'
#define HM_HKIDS_CMD_SEC_EXEC_CMD_ID    0x04
#define HM_HKIDS_CMD_SEC_INIT_AIDS_ID   0x11

#define HM_HKIDS_CMD_SEC_EXEC_CMD \
    _IOW(HM_HKIDS_IOCTL_BASE, HM_HKIDS_CMD_SEC_EXEC_CMD_ID, struct hkids_ioctl_arg)
#define HM_HKIDS_CMD_SEC_INIT_AIDS \
    _IOW(HM_HKIDS_IOCTL_BASE, HM_HKIDS_CMD_SEC_INIT_AIDS_ID, struct hkids_ioctl_arg)

enum blacklist_cmd {
    AGENTID_CMD_SET_AINFO,
    BLACKLIST_CMD_ADD,
    BLACKLIST_CMD_REMOVE,
    BLACKLIST_CMD_CLEAR,
};

struct hkids_ioctl_arg {
    unsigned int module_id;
    unsigned int cmd_id;
    void *cmd_args;
    unsigned int cmd_args_size;
};


struct aids_set_ainfo_arg {
    uint32_t appid;
};

struct hkids_blacklist_cmd_arg {
    char command[HKIDS_CMD_MAX_SIZE];
    char subcommand[HKIDS_CMD_MAX_SIZE];
    uint32_t appid;
};


class AidsClient {
public:
    explicit AidsClient(const std::string& device_path = DEVICE_NODE);
    ~AidsClient();

    AidsClient(const AidsClient&) = delete;
    AidsClient& operator=(const AidsClient&) = delete;

    int setLabel(const uint32_t appid = DEFAULT_APPID);
    int addBlacklist(const std::string& cmd, const std::string& subcmd, const uint32_t appid);
    int delBlacklist(const std::string& cmd, const std::string& subcmd, const uint32_t appid);
    int clrBlacklist(void);
    bool isOpen() const { return fd_ >= 0; }

private:
    int fd_;
};

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
#endif // SANDBOX_AIDS_H
