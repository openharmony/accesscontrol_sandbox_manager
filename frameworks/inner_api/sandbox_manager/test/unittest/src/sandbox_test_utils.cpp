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

#include "sandbox_test_utils.h"
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <cerrno>
#include <string>
#include <vector>
#include "cJSON.h"
#include "config_policy_utils.h"

static char *ReadFileContent(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return nullptr;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size == 0) {
        close(fd);
        return nullptr;
    }
    char *buf = static_cast<char *>(malloc(st.st_size + 1));
    if (buf == nullptr) {
        close(fd);
        return nullptr;
    }
    ssize_t readLen = read(fd, buf, st.st_size);
    close(fd);
    if (readLen <= 0) {
        free(buf);
        return nullptr;
    }
    buf[readLen] = '\0';
    return buf;
}

bool IsDenyPolicyForPath(const char *targetPath)
{
    char buf[1024] = { 0 };
    const char *denyFilePath = "etc/sandbox_manager_service/file_deny_policy.json";
    char *resolvedPath = GetOneCfgFile(denyFilePath, buf, sizeof(buf));
    if (resolvedPath == nullptr || access(resolvedPath, F_OK) != 0) {
        printf("[IsDenyPolicyForPath] file not found: %s\n", denyFilePath);
        return false;
    }
    printf("[IsDenyPolicyForPath] targetPath=%s resolvedPath=%s\n", targetPath, resolvedPath);
    char *readBuf = ReadFileContent(resolvedPath);
    if (readBuf == nullptr) {
        printf("[IsDenyPolicyForPath] read failed: %s\n", resolvedPath);
        return false;
    }
    cJSON *root = cJSON_Parse(readBuf);
    free(readBuf);
    if (root == nullptr) {
        printf("[IsDenyPolicyForPath] cJSON parse failed\n");
        return false;
    }
    bool result = false;
    cJSON *item = nullptr;
    cJSON_ArrayForEach(item, root)
    {
        cJSON *pathItem = cJSON_GetObjectItemCaseSensitive(item, "path");
        if (pathItem != nullptr && cJSON_IsString(pathItem) &&
            strcmp(pathItem->valuestring, targetPath) == 0) {
            cJSON *setPolicy = cJSON_GetObjectItemCaseSensitive(item, "set_policy");
            cJSON *setPolicyAll = cJSON_GetObjectItemCaseSensitive(item, "set_policy_all");
            if ((setPolicy != nullptr && cJSON_IsNumber(setPolicy) && setPolicy->valueint == 1) ||
                (setPolicyAll != nullptr && cJSON_IsNumber(setPolicyAll) && setPolicyAll->valueint == 1)) {
                result = true;
            }
            break;
        }
    }
    cJSON_Delete(root);
    printf("[IsDenyPolicyForPath] targetPath=%s result=%d\n", targetPath, result);
    return result;
}

bool IsDenyPolicyFileExists()
{
    char buf[1024] = { 0 };
    const char *denyFilePath = "etc/sandbox_manager_service/file_deny_policy.json";
    char *resolvedPath = GetOneCfgFile(denyFilePath, buf, sizeof(buf));
    return (resolvedPath != nullptr && access(resolvedPath, F_OK) == 0);
}

int GetTokenNum(uint64_t tokenid, int32_t &num, int32_t &denyNum)
{
    int fd = open("/dev/dec", O_RDWR);
    if (fd < 0) {
        printf("[GetTokenNum] open /dev/dec failed, errno=%d.\n", errno);
        return -1;
    }
    struct dec_token_num_arg arg;
    arg.tokenid = tokenid;
    arg.num = 0;
    arg.denyNum = 0;
    int ret = ioctl(fd, GET_TOKEN_NUM_CMD, &arg);
    if (ret < 0) {
        printf("[GetTokenNum] ioctl failed, errno=%d.\n", errno);
        close(fd);
        return -1;
    }
    num = arg.num;
    denyNum = arg.denyNum;
    close(fd);
    return 0;
}

namespace {
constexpr size_t DEC_MAX_POLICY_NUM = 8;
constexpr int DEC_POLICY_HEADER_RESERVED = 60;
struct PathInfo {
    char *path = nullptr;
    uint32_t pathLen = 0;
    uint32_t mode = 0;
    bool result = false;
};
struct SandboxPolicyInfo {
    uint64_t tokenId = 0;
    uint64_t timestamp = 0;
    struct PathInfo pathInfos[DEC_MAX_POLICY_NUM];
    uint32_t pathNum = 0;
    int32_t userId = 0;
    int32_t failedReason[DEC_MAX_POLICY_NUM];
    uint64_t reserved[DEC_POLICY_HEADER_RESERVED];
    bool persist = false;
};
} // namespace

#define DEL_POLICY_BY_USER_ID 7
#define DEL_DEC_POLICY_BY_USER_CMD _IOWR(HM_DEC_IOCTL_BASE, DEL_POLICY_BY_USER_ID, struct SandboxPolicyInfo)

int CleanPolicyByPathByUser(int32_t userId, const std::vector<std::string> &filePathList)
{
    int fd = open("/dev/dec", O_RDWR);
    if (fd < 0) {
        printf("[CleanPolicyByPathByUser] open /dev/dec failed, errno=%d.\n", errno);
        return -1;
    }
    for (size_t offset = 0; offset < filePathList.size(); offset += DEC_MAX_POLICY_NUM) {
        size_t curBatchSize = filePathList.size() - offset;
        if (curBatchSize > DEC_MAX_POLICY_NUM) {
            curBatchSize = DEC_MAX_POLICY_NUM;
        }
        struct SandboxPolicyInfo info;
        info.userId = userId;
        info.pathNum = curBatchSize;
        for (size_t i = 0; i < curBatchSize; ++i) {
            info.pathInfos[i].path = const_cast<char *>(filePathList[offset + i].c_str());
            info.pathInfos[i].pathLen = filePathList[offset + i].length();
        }
        int ret = ioctl(fd, DEL_DEC_POLICY_BY_USER_CMD, &info);
        if (ret < 0) {
            printf("[CleanPolicyByPathByUser] ioctl failed, errno=%d.\n", errno);
            close(fd);
            return -1;
        }
    }
    close(fd);
    return 0;
}