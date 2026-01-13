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
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include "cJSON.h"
#include "config_policy_utils.h"
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
const int DEC_POLICY_HEADER_RESERVED = 60;

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
    int32_t failedReason[MAX_POLICY_NUM];
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
#define DENY_POLICY_ID 9
#define DEL_DENY_POLICY_ID 10

#define SET_POLICY_CMD _IOWR(SANDBOX_IOCTL_BASE, SET_POLICY, struct SandboxPolicyInfo)
#define UN_SET_POLICY_CMD _IOWR(SANDBOX_IOCTL_BASE, UN_SET_POLICY, struct SandboxPolicyInfo)
#define QUERY_POLICY_CMD _IOWR(SANDBOX_IOCTL_BASE, QUERY_POLICY, struct SandboxPolicyInfo)
#define CHECK_POLICY_CMD _IOWR(SANDBOX_IOCTL_BASE, CHECK_POLICY, struct SandboxPolicyInfo)
#define DESTROY_POLICY_CMD _IOWR(SANDBOX_IOCTL_BASE, DESTROY_POLICY, struct SandboxPolicyInfo)
#define DEL_DEC_POLICY_BY_USER_CMD _IOWR(SANDBOX_IOCTL_BASE, DEL_POLICY_BY_USER, struct SandboxPolicyInfo)
#define DENY_DEC_RULE_CMD _IOWR(SANDBOX_IOCTL_BASE, DENY_POLICY_ID, struct SandboxPolicyInfo)
#define DEL_DENY_DEC_RULE_CMD _IOWR(SANDBOX_IOCTL_BASE, DEL_DENY_POLICY_ID, struct SandboxPolicyInfo)
MacAdapter::MacAdapter() {}

MacAdapter::~MacAdapter()
{
    if (fd_ >= 0) {
        FDSAN_CLOSE(fd_);
        fd_ = -1;
    }
    isMacSupport_ = false;
}

#ifndef NOT_RESIDENT
const std::string DENY_CONFIG_FILE = "etc/sandbox_manager_service/file_deny_policy.json";
constexpr int MAX_DENY_CONFIG_FILE_SIZE = 5 * 1024 * 1024; // 5M
constexpr size_t BUFFER_SIZE = 1024;

#define DEC_DENY_RENAME   (1 << 7)
#define DEC_DENY_REMOVE   (1 << 8)
#define DEC_DENY_INHERIT  (1 << 9)

constexpr const char* JSON_ITEM_PATH = "path";
constexpr const char* JSON_ITEM_RENAME = "rename";
constexpr const char* JSON_ITEM_DELETE = "delete";
constexpr const char* JSON_ITEM_INHERIT = "inherit";

int32_t MacAdapter::ReadDenyFile(const char *jsonPath, std::string& rawData)
{
    char buf[BUFFER_SIZE] = { 0 };
    char *path = GetOneCfgFile(jsonPath, buf, BUFFER_SIZE);
    if (path == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "GetOneCfgFile failed, cannot find file with %{public}s", jsonPath);
        return SANDBOX_MANAGER_DENY_ERR;
    }
    int32_t fd = open(path, O_RDONLY);
    if (fd < 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Open failed errno %{public}d.", errno);
        return SANDBOX_MANAGER_DENY_ERR;
    }

    FDSAN_MARK(fd);
    struct stat statBuffer;
    if (fstat(fd, &statBuffer) != 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "fstat failed");
        FDSAN_CLOSE(fd);
        return SANDBOX_MANAGER_DENY_ERR;
    }

    if (statBuffer.st_size == 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Config file size is zero.");
        FDSAN_CLOSE(fd);
        return SANDBOX_MANAGER_DENY_ERR;
    }

    if (statBuffer.st_size > MAX_DENY_CONFIG_FILE_SIZE) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Config file size is too large");
        FDSAN_CLOSE(fd);
        return SANDBOX_MANAGER_DENY_ERR;
    }
    rawData.reserve(statBuffer.st_size);
    ssize_t readLen = 0;
    while ((readLen = read(fd, buf, BUFFER_SIZE)) > 0) {
        rawData.append(buf, readLen);
    }
    FDSAN_CLOSE(fd);
    if (readLen == 0) {
        return SANDBOX_MANAGER_OK;
    }
    return SANDBOX_MANAGER_DENY_ERR;
}

static uint32_t FillInfo(cJSON *root, struct SandboxPolicyInfo &info, int32_t start, int32_t curBatchSize)
{
    uint32_t mode = 0;

    for (int32_t i = 0; i < curBatchSize; i++) {
        cJSON *cjsonItem = cJSON_GetArrayItem(root, i + start);
        if (cjsonItem == nullptr) {
            return SANDBOX_MANAGER_DENY_ERR;
        }

        mode = 0;
        cJSON *pathNameJson = cJSON_GetObjectItemCaseSensitive(cjsonItem, JSON_ITEM_PATH);
        if ((pathNameJson == nullptr) || !cJSON_IsString(pathNameJson) || (pathNameJson->valuestring == nullptr)) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "pathname get error");
            return SANDBOX_MANAGER_DENY_ERR;
        }

        cJSON *reameJson = cJSON_GetObjectItemCaseSensitive(cjsonItem, JSON_ITEM_RENAME);
        if ((reameJson == nullptr) || !cJSON_IsNumber(reameJson)) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "rename info get error, path = %{public}s", pathNameJson->valuestring);
            return SANDBOX_MANAGER_DENY_ERR;
        }
        if (reameJson->valueint == 1) {
            mode |= DEC_DENY_RENAME;
        }

        cJSON *deleteJson = cJSON_GetObjectItemCaseSensitive(cjsonItem, JSON_ITEM_DELETE);
        if ((deleteJson == nullptr) || !cJSON_IsNumber(deleteJson)) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "delete info get error, path = %{public}s", pathNameJson->valuestring);
            return SANDBOX_MANAGER_DENY_ERR;
        }
        if (deleteJson->valueint == 1) {
            mode |= DEC_DENY_REMOVE;
        }

        cJSON *inheritJson = cJSON_GetObjectItemCaseSensitive(cjsonItem, JSON_ITEM_INHERIT);
        if ((inheritJson == nullptr) || !cJSON_IsNumber(inheritJson)) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "inherit info get error, path = %{public}s", pathNameJson->valuestring);
            return SANDBOX_MANAGER_DENY_ERR;
        }
        if (inheritJson->valueint == 1) {
            mode |= DEC_DENY_INHERIT;
        }

        info.pathInfos[i].path = pathNameJson->valuestring;
        info.pathInfos[i].pathLen = std::strlen(pathNameJson->valuestring);
        info.pathInfos[i].mode = mode;
        SANDBOXMANAGER_LOG_INFO(LABEL, "path = %{public}s, mode = %{public}x", pathNameJson->valuestring, mode);
    }
    return SANDBOX_MANAGER_OK;
}

int32_t MacAdapter::SetDenyCfg(std::string &rawData)
{
    cJSON *root = cJSON_Parse(rawData.c_str());
    if (root == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "json parse error");
        return SANDBOX_MANAGER_DENY_ERR;
    }
    int32_t arraySize = cJSON_GetArraySize(root);
    if (arraySize < 0) {
        cJSON_Delete(root);
        return SANDBOX_MANAGER_DENY_ERR;
    }
    int32_t succSet = 0;
    int32_t ret;
    for (int32_t i = 0; i < arraySize; i += MAX_POLICY_NUM) {
        struct SandboxPolicyInfo info;
        size_t curBatchSize = std::min(static_cast<int>(MAX_POLICY_NUM), arraySize - i);
        ret = FillInfo(root, info, i, curBatchSize);
        if (ret != SANDBOX_MANAGER_OK) {
            break;
        }
        info.pathNum = curBatchSize;
        if (ioctl(fd_, DENY_DEC_RULE_CMD, &info) < 0) {
            for (size_t j = 0; j < curBatchSize; j++) {
                LOGE_WITH_REPORT(LABEL,
                    "Set deny failed errno=%{public}d, path = %{public}s, mode = %{public}x, num = %{public}d",
                    errno, info.pathInfos[j].path, info.pathInfos[j].mode, info.pathNum);
            }
            break;
        }
        succSet += curBatchSize;
    }
    cJSON_Delete(root);

    if (arraySize != succSet) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "denyfile has %{public}d. failed from %{public}d", arraySize, succSet);
        return SANDBOX_MANAGER_DENY_ERR;
    }
    return SANDBOX_MANAGER_OK;
}

void MacAdapter::DenyInit()
{
    int32_t ret;
    std::string inputString;
    ret = ReadDenyFile(DENY_CONFIG_FILE.c_str(), inputString);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Json read error");
        return;
    }

    ret = SetDenyCfg(inputString);
    if (ret != SANDBOX_MANAGER_OK) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Json set error");
    }
    return;
}
#endif

void MacAdapter::Init()
{
    if (access(DEV_NODE, F_OK) == 0) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Node exists, mac is support.");
        isMacSupport_ = true;
    }
    if (fd_ > 0) {
        return;
    }
    fd_ = open(DEV_NODE, O_RDWR);
    if (fd_ < 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Open node failed, errno=%{public}d.", errno);
        return;
    }
    FDSAN_MARK(fd_);
    SANDBOXMANAGER_LOG_INFO(LABEL, "Open node success.");

#ifndef NOT_RESIDENT
    DenyInit();
#endif
    return;
}

bool MacAdapter::IsMacSupport()
{
    return isMacSupport_;
}

void MacAdapter::CheckResult(std::vector<uint32_t> &result)
{
    uint32_t failCount = static_cast<uint32_t>(
        std::count_if(result.begin(), result.end(), [](uint32_t res) { return res != SANDBOX_MANAGER_OK; }));
    if (failCount > 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Set policy has failed items, failCount=%{public}u.", failCount);
    }
}

int32_t MacAdapter::SetPolicyToMac(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result,
    MacParams &macParams, int32_t cmd)
{
    SANDBOXMANAGER_LOG_INFO(LABEL,
        "Set sandbox policy target:%{public}u flag:%{public}" PRIu64 " timestamp:%{public}" PRIu64 " userId:%{public}d"
        "cmd:%{public}d", macParams.tokenId, macParams.policyFlag, macParams.timestamp, macParams.userId, cmd);
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
            std::string maskPath = SandboxManagerLog::MaskRealPath(info.pathInfos[i].path);
            SANDBOXMANAGER_LOG_INFO(LABEL, "Set policy paths target:%{public}u path:%{public}s mode:%{public}d",
                macParams.tokenId, maskPath.c_str(), info.pathInfos[i].mode);
        }

        if (ioctl(fd_, cmd, &info) < 0) {
            LOGE_WITH_REPORT(LABEL, "Set policy failed at batch %{public}zu, errno=%{public}d, cmd=%{public}d.",
                offset / MAX_POLICY_NUM, errno, cmd);
            return SANDBOX_MANAGER_MAC_IOCTL_ERR;
        }
        for (size_t i = 0; i < curBatchSize; ++i) {
            if (info.pathInfos[i].result == 0) {
                std::string maskPath = SandboxManagerLog::MaskRealPath(info.pathInfos[i].path);
                SANDBOXMANAGER_LOG_ERROR(LABEL, "Set policy failed at %{public}s", maskPath.c_str());
                result[offset + i] = POLICY_MAC_FAIL;
            } else {
                result[offset + i] = SANDBOX_MANAGER_OK;
            }
        }
    }

    CheckResult(result);
    return SANDBOX_MANAGER_OK;
}

int32_t MacAdapter::SetSandboxPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result,
    MacParams &macParams)
{
    return SetPolicyToMac(policy, result, macParams, SET_POLICY_CMD);
}

int32_t MacAdapter::SetDenyPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result,
    MacParams &macParams)
{
    return SetPolicyToMac(policy, result, macParams, DENY_DEC_RULE_CMD);
}

#define DEC_ERR_QUERY_RULE_NOT_FOUND 1
#define DEC_ERR_QUERY_NON_PERSTST 2

void MacAdapter::SetQueryResult(struct SandboxPolicyInfo &info, size_t offset, size_t i, std::vector<uint32_t> &result)
{
    if (info.pathInfos[i].result == 0) {
        std::string maskPath = SandboxManagerLog::MaskRealPath(info.pathInfos[i].path);
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Query policy failed at %{public}s", maskPath.c_str());
        if (DEC_ERR_QUERY_NON_PERSTST == info.failedReason[i]) {
            result[offset + i] = FORBIDDEN_TO_BE_PERSISTED_BY_FLAG;
        } else {
            result[offset + i] = FORBIDDEN_TO_BE_PERSISTED;
        }
    } else {
        result[offset + i] = OPERATE_SUCCESSFULLY;
    }
}

int32_t MacAdapter::QuerySandboxPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
                                       std::vector<uint32_t> &result)
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
            LOGE_WITH_REPORT(LABEL, "Query policy failed at batch %{public}zu, errno=%{public}d.",
                offset / MAX_POLICY_NUM, errno);
            return SANDBOX_MANAGER_MAC_IOCTL_ERR;
        }
        for (size_t i = 0; i < curBatchSize; ++i) {
            SetQueryResult(info, offset, i, result);
        }
    }

    uint32_t failCount = static_cast<uint32_t>(std::count(result.begin(), result.end(), false));
    if (failCount > 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Query policy has failed items, failCount=%{public}u.", failCount);
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
            LOGE_WITH_REPORT(LABEL, "Check policy failed at batch %{public}zu, errno=%{public}d.",
                offset / MAX_POLICY_NUM, errno);
            return SANDBOX_MANAGER_MAC_IOCTL_ERR;
        }
        for (size_t i = 0; i < curBatchSize; ++i) {
            if (info.pathInfos[i].result == 0) {
                std::string maskPath = SandboxManagerLog::MaskRealPath(info.pathInfos[i].path);
                SANDBOXMANAGER_LOG_ERROR(LABEL, "check policy failed at %{public}s", maskPath.c_str());
            }
            result[offset + i] = info.pathInfos[i].result;
        }
    }

    uint32_t failCount = static_cast<uint32_t>(std::count(result.begin(), result.end(), false));
    if (failCount > 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Check policy has failed items, failCount=%{public}u.", failCount);
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
            LOGE_WITH_REPORT(LABEL, "Unset policy failed at batch %{public}zu, errno=%{public}d.",
                offset / MAX_POLICY_NUM, errno);
            return SANDBOX_MANAGER_MAC_IOCTL_ERR;
        }
        for (size_t i = 0; i < curBatchSize; ++i) {
            if (info.pathInfos[i].result == 0) {
                std::string maskPath = SandboxManagerLog::MaskRealPath(info.pathInfos[i].path);
                SANDBOXMANAGER_LOG_ERROR(LABEL, "Unset policy failed at %{public}s", maskPath.c_str());
            }
            result[offset + i] = info.pathInfos[i].result;
        }
    }

    uint32_t failCount = static_cast<uint32_t>(std::count(result.begin(), result.end(), false));
    if (failCount > 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Unset policy has failed items, failCount=%{public}u.", failCount);
    }
    return SANDBOX_MANAGER_OK;
}

int32_t MacAdapter::UnSetSandboxPolicyByUser(int32_t userId, const std::vector<PolicyInfo> &policy,
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
        info.userId = userId;
        info.pathNum = curBatchSize;

        for (size_t i = 0; i < curBatchSize; ++i) {
            info.pathInfos[i].path = const_cast<char *>(policy[offset + i].path.c_str());
            info.pathInfos[i].pathLen = policy[offset + i].path.length();
            info.pathInfos[i].mode = policy[offset + i].mode;
            SANDBOXMANAGER_LOG_DEBUG(LABEL, "Unset policy paths userId:%{private}d path:%{private}s mode:%{public}d",
                userId, info.pathInfos[i].path, info.pathInfos[i].mode);
        }

        if (ioctl(fd_, DEL_DEC_POLICY_BY_USER_CMD, &info) < 0) {
            LOGE_WITH_REPORT(LABEL, "Unset policy failed at batch %{public}zu, errno=%{public}d.",
                offset / MAX_POLICY_NUM, errno);
            return SANDBOX_MANAGER_MAC_IOCTL_ERR;
        }
        for (size_t i = 0; i < curBatchSize; ++i) {
            if (info.pathInfos[i].result == 0) {
                std::string maskPath = SandboxManagerLog::MaskRealPath(info.pathInfos[i].path);
                SANDBOXMANAGER_LOG_ERROR(LABEL, "Unset by user failed at %{public}s, mode:%{public}d",
                    maskPath.c_str(), info.pathInfos[i].mode);
            }
            result[offset + i] = info.pathInfos[i].result;
        }
    }

    uint32_t failCount = static_cast<uint32_t>(std::count(result.begin(), result.end(), false));
    if (failCount > 0) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Unset policy has failed items, failCount=%{public}u.", failCount);
    }
    return SANDBOX_MANAGER_OK;
}

int32_t MacAdapter::UnSetPolicyToMac(uint32_t tokenId, const PolicyInfo &policy, int32_t cmd)
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
    SANDBOXMANAGER_LOG_INFO(LABEL,
        "Unset sandbox policy target:%{public}u path:%{private}s mode:%{public}d, cmd=%{public}d",
        tokenId, info.pathInfos[0].path, info.pathInfos[0].mode, cmd);

    if (ioctl(fd_, cmd, &info) < 0) {
        std::string maskPath = SandboxManagerLog::MaskRealPath(info.pathInfos[0].path);
        LOGE_WITH_REPORT(LABEL, "Unset policy failed, errno=%{public}d. path = %{public}s, cmd=%{public}d",
            errno, maskPath.c_str(), cmd);
        return SANDBOX_MANAGER_MAC_IOCTL_ERR;
    }

    return SANDBOX_MANAGER_OK;
}

int32_t MacAdapter::UnSetSandboxPolicy(uint32_t tokenId, const PolicyInfo &policy)
{
    return UnSetPolicyToMac(tokenId, policy, UN_SET_POLICY_CMD);
}

int32_t MacAdapter::UnSetDenyPolicy(uint32_t tokenId, const PolicyInfo &policy)
{
    return UnSetPolicyToMac(tokenId, policy, DEL_DENY_DEC_RULE_CMD);
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
        LOGE_WITH_REPORT(LABEL, "Destroy policy failed, errno=%{public}d.", errno);
        return SANDBOX_MANAGER_MAC_IOCTL_ERR;
    }

    return SANDBOX_MANAGER_OK;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
