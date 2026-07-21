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