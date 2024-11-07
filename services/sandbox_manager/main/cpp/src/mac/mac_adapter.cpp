/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "mac_adapter.h"
#include <cstdint>
#include <fcntl.h>
#include <cinttypes>
#include <string>
#include <sys/ioctl.h>
#include <unistd.h>
#include <vector>
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerMacAdapter"
};

constexpr const char* DEV_NODE = "/dev/dec";
const size_t MAX_POLICY_NUM = 8;
const int DEC_POLICY_HEADER_RESERVED = 64;

struct PathInfo {
    char *path = nullptr;
    uint32_t pathLen = 0;
    uint32_t mode = 0;
    bool result = false;
};

struct SandboxPolicyInfo {
    uint64_t tokenId = 0;
    uint64_t timestamp = 0;
    struct PathInfo pathInfos[MAX_POLICY_NUM];
    uint32_t pathNum = 0;
    int32_t userId = 0;
    uint64_t reserved[DEC_POLICY_HEADER_RESERVED];
    bool persist = false;
};

#define SANDBOX_IOCTL_BASE 's'
#define SET_POLICY 1
#define UN_SET_POLICY 2
#define QUERY_POLICY 3
#define CHECK_POLICY 4
#define DESTROY_POLICY 5
#define DEL_POLICY_BY_USER 7

#define SET_POLICY_CMD _IOWR(SANDBOX_IOCTL_BASE, SET_POLICY, struct SandboxPolicyInfo)
#define UN_SET_POLICY_CMD _IOWR(SANDBOX_IOCTL_BASE, UN_SET_POLICY, struct SandboxPolicyInfo)
#define QUERY_POLICY_CMD _IOWR(SANDBOX_IOCTL_BASE, QUERY_POLICY, struct SandboxPolicyInfo)
#define CHECK_POLICY_CMD _IOWR(SANDBOX_IOCTL_BASE, CHECK_POLICY, struct SandboxPolicyInfo)
#define DESTROY_POLICY_CMD _IOWR(SANDBOX_IOCTL_BASE, DESTROY_POLICY, struct SandboxPolicyInfo)
#define DEL_DEC_POLICY_BY_USER_CMD _IOWR(SANDBOX_IOCTL_BASE, DEL_POLICY_BY_USER, struct SandboxPolicyInfo)

MacAdapter::MacAdapter() {}

MacAdapter::~MacAdapter()
{
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
    isMacSupport_ = false;
}

void MacAdapter::Init()
{
    if (access(DEV_NODE, F_OK) == 0) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Node exists, mac is support.");
        isMacSupport_ = true;
    }
    fd_ = open(DEV_NODE, O_RDWR);
    if (fd_ < 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Open node failed, errno=%{public}d.", errno);
        return;
    }
    SANDBOXMANAGER_LOG_INFO(LABEL, "Open node success.", errno);
    return;
}

bool MacAdapter::IsMacSupport()
{
    return isMacSupport_;
}

int32_t MacAdapter::SetSandboxPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result,
    MacParams &macParams)
{
    SANDBOXMANAGER_LOG_INFO(LABEL,
        "Set sandbox policy target:%{public}u flag:%{public}" PRIu64 " timestamp:%{public}" PRIu64 " userId:%{public}d",
        macParams.tokenId, macParams.policyFlag, macParams.timestamp, macParams.userId);
    if (fd_ < 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Not init yet.");
        return SANDBOX_MANAGER_MAC_NOT_INIT;
    }

    size_t policyNum = policy.size();

    for (size_t offset = 0; offset < policyNum; offset += MAX_POLICY_NUM) {
        size_t curBatchSize = std::min(MAX_POLICY_NUM, policyNum - offset);

        struct SandboxPolicyInfo info;
        info.tokenId = macParams.tokenId;
        info.pathNum = curBatchSize;
        info.persist = macParams.policyFlag == 1 ? true : false;
        info.timestamp = macParams.timestamp;
        info.userId = macParams.userId;

        for (size_t i = 0; i < curBatchSize; ++i) {
            info.pathInfos[i].path = const_cast<char *>(policy[offset + i].path.c_str());
            info.pathInfos[i].pathLen = policy[offset + i].path.length();
            info.pathInfos[i].mode = policy[offset + i].mode;
            SANDBOXMANAGER_LOG_INFO(LABEL, "Set policy paths target:%{public}u path:%{private}s mode:%{public}d",
                macParams.tokenId, info.pathInfos[i].path, info.pathInfos[i].mode);
        }

        if (ioctl(fd_, SET_POLICY_CMD, &info) < 0) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Set policy failed at batch %{public}zu, errno=%{public}d.",
                                     offset / MAX_POLICY_NUM, errno);
            return SANDBOX_MANAGER_MAC_IOCTL_ERR;
        }
        for (size_t i = 0; i < curBatchSize; ++i) {
            result[offset + i] = info.pathInfos[i].result ? SANDBOX_MANAGER_OK : POLICY_MAC_FAIL;
        }
    }
    uint32_t failCount = static_cast<uint32_t>(
        std::count_if(result.begin(), result.end(), [](uint32_t res) { return res != SANDBOX_MANAGER_OK; }));
    if (failCount > 0) {
        SANDBOXMANAGER_LOG_WARN(LABEL, "Set policy has failed items, failCount=%{public}u.", failCount);
    }
    return SANDBOX_MANAGER_OK;
}

int32_t MacAdapter::QuerySandboxPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                       std::vector<bool> &result)
{
    if (fd_ < 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Not init yet.");
        return SANDBOX_MANAGER_MAC_NOT_INIT;
    }

    result.clear();

    size_t policyNum = policy.size();

    for (size_t offset = 0; offset < policyNum; offset += MAX_POLICY_NUM) {
        size_t curBatchSize = std::min(MAX_POLICY_NUM, policyNum - offset);

        struct SandboxPolicyInfo info;
        info.tokenId = tokenId;
        info.pathNum = curBatchSize;

        for (size_t i = 0; i < curBatchSize; ++i) {
            info.pathInfos[i].path = const_cast<char *>(policy[offset + i].path.c_str());
            info.pathInfos[i].pathLen = policy[offset + i].path.length();
            info.pathInfos[i].mode = policy[offset + i].mode;
        }

        if (ioctl(fd_, QUERY_POLICY_CMD, &info) < 0) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Query policy failed at batch %{public}zu, errno=%{public}d.",
                                     offset / MAX_POLICY_NUM, errno);
            return SANDBOX_MANAGER_MAC_IOCTL_ERR;
        }
        for (size_t i = 0; i < curBatchSize; ++i) {
            result[offset + i] = info.pathInfos[i].result;
        }
    }

    uint32_t failCount = static_cast<uint32_t>(std::count(result.begin(), result.end(), false));
    if (failCount > 0) {
        SANDBOXMANAGER_LOG_WARN(LABEL, "Query policy has failed items, failCount=%{public}u.", failCount);
    }
    return SANDBOX_MANAGER_OK;
}

int32_t MacAdapter::CheckSandboxPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                       std::vector<bool> &result)
{
    if (fd_ < 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Not init yet.");
        return SANDBOX_MANAGER_MAC_NOT_INIT;
    }

    result.clear();

    size_t policyNum = policy.size();

    for (size_t offset = 0; offset < policyNum; offset += MAX_POLICY_NUM) {
        size_t curBatchSize = std::min(MAX_POLICY_NUM, policyNum - offset);

        struct SandboxPolicyInfo info;
        info.tokenId = tokenId;
        info.pathNum = curBatchSize;

        for (size_t i = 0; i < curBatchSize; ++i) {
            info.pathInfos[i].path = const_cast<char *>(policy[offset + i].path.c_str());
            info.pathInfos[i].pathLen = policy[offset + i].path.length();
            info.pathInfos[i].mode = policy[offset + i].mode;
        }

        if (ioctl(fd_, CHECK_POLICY_CMD, &info) < 0) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Check policy failed at batch %{public}zu, errno=%{public}d.",
                                     offset / MAX_POLICY_NUM, errno);
            return SANDBOX_MANAGER_MAC_IOCTL_ERR;
        }
        for (size_t i = 0; i < curBatchSize; ++i) {
            result[offset + i] = info.pathInfos[i].result;
        }
    }

    uint32_t failCount = static_cast<uint32_t>(std::count(result.begin(), result.end(), false));
    if (failCount > 0) {
        SANDBOXMANAGER_LOG_WARN(LABEL, "Check policy has failed items, failCount=%{public}u.", failCount);
    }
    return SANDBOX_MANAGER_OK;
}

int32_t MacAdapter::UnSetSandboxPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                       std::vector<bool> &result)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "Unset sandbox policy target:%{public}u", tokenId);

    if (fd_ < 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Not init yet.");
        return SANDBOX_MANAGER_MAC_NOT_INIT;
    }

    result.clear();

    size_t policyNum = policy.size();

    for (size_t offset = 0; offset < policyNum; offset += MAX_POLICY_NUM) {
        size_t curBatchSize = std::min(MAX_POLICY_NUM, policyNum - offset);

        struct SandboxPolicyInfo info;
        info.tokenId = tokenId;
        info.pathNum = curBatchSize;

        for (size_t i = 0; i < curBatchSize; ++i) {
            info.pathInfos[i].path = const_cast<char *>(policy[offset + i].path.c_str());
            info.pathInfos[i].pathLen = policy[offset + i].path.length();
            info.pathInfos[i].mode = policy[offset + i].mode;
            SANDBOXMANAGER_LOG_INFO(LABEL, "Unset policy paths target:%{public}u path:%{private}s mode:%{public}d",
                tokenId, info.pathInfos[i].path, info.pathInfos[i].mode);
        }

        if (ioctl(fd_, UN_SET_POLICY_CMD, &info) < 0) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Unset policy failed at batch %{public}zu, errno=%{public}d.",
                                     offset / MAX_POLICY_NUM, errno);
            return SANDBOX_MANAGER_MAC_IOCTL_ERR;
        }
        for (size_t i = 0; i < curBatchSize; ++i) {
            result[offset + i] = info.pathInfos[i].result;
        }
    }

    uint32_t failCount = static_cast<uint32_t>(std::count(result.begin(), result.end(), false));
    if (failCount > 0) {
        SANDBOXMANAGER_LOG_WARN(LABEL, "Unset policy has failed items, failCount=%{public}u.", failCount);
    }
    return SANDBOX_MANAGER_OK;
}

int32_t MacAdapter::UnSetSandboxPolicyByUser(int32_t userId, const std::vector<PolicyInfo> &policy,
    std::vector<bool> &result)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "Unset sandbox policy by userId:%{private}d", userId);

    if (fd_ < 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Not init yet.");
        return SANDBOX_MANAGER_MAC_NOT_INIT;
    }

    result.clear();

    size_t policyNum = policy.size();

    for (size_t offset = 0; offset < policyNum; offset += MAX_POLICY_NUM) {
        size_t curBatchSize = std::min(MAX_POLICY_NUM, policyNum - offset);

        struct SandboxPolicyInfo info;
        info.userId = userId;
        info.pathNum = curBatchSize;

        for (size_t i = 0; i < curBatchSize; ++i) {
            info.pathInfos[i].path = const_cast<char *>(policy[offset + i].path.c_str());
            info.pathInfos[i].pathLen = policy[offset + i].path.length();
            info.pathInfos[i].mode = policy[offset + i].mode;
            SANDBOXMANAGER_LOG_INFO(LABEL, "Unset policy paths userId:%{private}d path:%{private}s mode:%{public}d",
                userId, info.pathInfos[i].path, info.pathInfos[i].mode);
        }

        if (ioctl(fd_, DEL_DEC_POLICY_BY_USER_CMD, &info) < 0) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Unset policy failed at batch %{public}zu, errno=%{public}d.",
                                     offset / MAX_POLICY_NUM, errno);
            return SANDBOX_MANAGER_MAC_IOCTL_ERR;
        }
        for (size_t i = 0; i < curBatchSize; ++i) {
            result[offset + i] = info.pathInfos[i].result;
        }
    }

    uint32_t failCount = static_cast<uint32_t>(std::count(result.begin(), result.end(), false));
    if (failCount > 0) {
        SANDBOXMANAGER_LOG_WARN(LABEL, "Unset policy has failed items, failCount=%{public}u.", failCount);
    }
    return SANDBOX_MANAGER_OK;
}

int32_t MacAdapter::UnSetSandboxPolicy(uint32_t tokenId, const PolicyInfo &policy)
{
    if (fd_ < 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Not init yet.");
        return SANDBOX_MANAGER_MAC_NOT_INIT;
    }

    struct SandboxPolicyInfo info;
    info.tokenId = tokenId;
    info.pathNum = 1;

    info.pathInfos[0].path = const_cast<char *>(policy.path.c_str());
    info.pathInfos[0].pathLen = policy.path.length();
    info.pathInfos[0].mode = policy.mode;
    SANDBOXMANAGER_LOG_INFO(LABEL, "Unset sandbox policy target:%{public}u path:%{private}s mode:%{public}d", tokenId,
        info.pathInfos[0].path, info.pathInfos[0].mode);

    if (ioctl(fd_, UN_SET_POLICY_CMD, &info) < 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Unset policy failed, errno=%{public}d.", errno);
        return SANDBOX_MANAGER_MAC_IOCTL_ERR;
    }

    return SANDBOX_MANAGER_OK;
}

int32_t MacAdapter::DestroySandboxPolicy(uint32_t tokenId, uint64_t timestamp)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "Destroy sandbox policy target:%{public}u timestamp:%{public}" PRIu64 ".", tokenId,
        timestamp);

    if (fd_ < 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Not init yet.");
        return SANDBOX_MANAGER_MAC_NOT_INIT;
    }

    struct SandboxPolicyInfo info;
    info.tokenId = tokenId;
    info.timestamp = timestamp;

    if (ioctl(fd_, DESTROY_POLICY_CMD, &info) < 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Destroy policy failed, errno=%{public}d.", errno);
        return SANDBOX_MANAGER_MAC_IOCTL_ERR;
    }

    return SANDBOX_MANAGER_OK;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS