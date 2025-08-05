/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "dec_test.h"
#include "token_setproc.h"

#ifdef DEC_ENABLED
const int32_t DEC_CHAR_LEN = 256;
const int32_t DEC_BUF_LEN = 32;
const int32_t DEC_CNT_LEN = 5;

int g_fd;

std::string GetDir(const std::string &fileName)
{
    size_t lastSlashPos = fileName.find_last_of("/\\");
    if (lastSlashPos == std::string::npos) {
        return "";
    }
    std::string fileDir = fileName.substr(0, lastSlashPos);
    return fileDir;
}

int OpenDevDec()
{
    if (g_fd == 0) {
        g_fd = open("/dev/dec", O_RDWR);
        if (g_fd < 0) {
            return -1;
        }
    }
    return 0;
}

int ConstraintPath(const std::string &path)
{
    OpenDevDec();
    struct dec_rule_s info;
    info.addPath(path.c_str());
    int ret = ioctl(g_fd, CONSTRAINT_DEC_RULE_CMD, &info);
    if (ret != 0) {
        return -1;
    }
    if (info.path[0].ret_flag) {
        return 0;
    }
    return -1;
}

void DecTestClose()
{
    if (g_fd > 0) {
        close(g_fd);
    }
}

int SetProcessId(int32_t uid, int32_t gid)
{
    if (uid != 0) {
        if (setuid(uid) != 0) {
            return -1;
        }
    }
    if (gid != 0) {
        if (setgid(gid) != 0) {
            return -1;
        }
    }
    return 0;
}

int SetPath(uint64_t tokenid, const std::string &path, uint32_t mode, bool persistFlag,
    uint64_t timestamp, int32_t userId)
{
    OpenDevDec();
    struct dec_rule_s info;
    info.addPath(path.c_str(), mode);
    info.persistFlag = persistFlag;
    info.tokenId = tokenid;
    info.timeStamp = timestamp;
    info.userId = userId;
    int ret = ioctl(g_fd, SET_DEC_RULE_CMD, &info);
    if (ret != 0) {
        return -1;
    }
    if (info.path[0].ret_flag) {
        return 0;
    }
    return -1;
}

int CheckPath(uint64_t tokenid, const std::string &path, uint32_t mode)
{
    OpenDevDec();
    struct dec_rule_s info;
    info.addPath(path.c_str(), mode);
    info.tokenId = tokenid;
    int ret = ioctl(g_fd, CHECK_DEC_RULE_CMD, &info);
    if (ret != 0) {
        return -1;
    }
    if (info.path[0].ret_flag) {
        return 0;
    }
    return -1;
}

int TestWrite(uint64_t tokenid, const std::string &fileName, int32_t uid, int32_t gid)
{
    SetSelfTokenID(tokenid);
    if (SetProcessId(uid, gid) != 0) {
        return -1;
    }
    FILE *fp = fopen(fileName.c_str(), "w");
    if (fp == NULL) {
        printf("TestWrite open failed err:%s\n", strerror(errno));
        return -1;
    }
    const char *str = "Hello";
    int ret = fwrite(str, 1, strlen(str), fp);
    if (ret < 0) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0) {
        return -1;
    }
    return 0;
}

int TestRead(uint64_t tokenid, const std::string &fileName, int32_t uid, int32_t gid)
{
    SetSelfTokenID(tokenid);
    if (SetProcessId(uid, gid) != 0) {
        return -1;
    }
    FILE *fp = fopen(fileName.c_str(), "r");
    if (fp == NULL) {
        printf("TestRead open failed err:%s\n", strerror(errno));
        return -1;
    }
    char buf[DEC_BUF_LEN];
    int ret = fread(buf, 1, sizeof(buf), fp);
    if (ret < 0) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0) {
        return -1;
    }
    return 0;
}

int TestCopy(uint64_t tokenid, const std::string &srcPath, const std::string &dstPath, int32_t uid, int32_t gid)
{
    SetSelfTokenID(tokenid);
    if (SetProcessId(uid, gid) != 0) {
        return -1;
    }
    std::ifstream in(srcPath, std::ios::binary);
    std::ofstream out(dstPath, std::ios::binary);
    if (!in || !out) {
        return -1;
    }
    out << in.rdbuf();
    in.close();
    out.close();
    return 0;
}
int Mkdir(uint64_t tokenid, std::string path, int32_t uid, int32_t gid)
{
    SetSelfTokenID(tokenid);
    if (SetProcessId(uid, gid) != 0) {
        return -1;
    }
    if (path.empty()) {
        return -1;
    }
    const char lastChar = path.back();
    if (lastChar != '\\' && lastChar != '/') {
        path.append("/");
    }
    int len = path.length();
    char tmpDirPath[DEC_CHAR_LEN] = { 0 };
    int ret = -1;
    for (int i = 0; i < len; i++) {
        tmpDirPath[i] = path[i];
        if (tmpDirPath[i] == '\\' || tmpDirPath[i] == '/') {
            if (access(tmpDirPath, 0) == -1) {
                ret = mkdir(tmpDirPath, S_IRWXU);
            }
        }
    }
    if (ret == -1) {
        printf("mkdir failed %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

int TestRename(uint64_t tokenid, const std::string &fileName, int32_t uid, int32_t gid)
{
    SetSelfTokenID(tokenid);
    if (SetProcessId(uid, gid) != 0) {
        return -1;
    }
    std::__fs::filesystem::path filePath = fileName;
    std::string newName = GetDir(fileName);
    newName.append("/new");
    newName.append(filePath.filename());
    int ret = rename(fileName.c_str(), newName.c_str());
    if (ret != 0) {
        printf("rename failed err:%s\n", strerror(errno));
        return -1;
    }

    ret = rename(newName.c_str(), fileName.c_str());
    if (ret != 0) {
        printf("rename back failed err:%s\n", strerror(errno));
        return -1;
    }
    return 0;
}

int TestRemove(uint64_t tokenid, const std::string &fileName, int32_t uid, int32_t gid)
{
    SetSelfTokenID(tokenid);
    if (SetProcessId(uid, gid) != 0) {
        return -1;
    }
    int ret = unlink(fileName.c_str());
    if (ret != 0) {
        printf("remove file:%s failed %s\n", fileName.c_str(), strerror(errno));
        return -1;
    }
    return 0;
}

int DestroyByTokenid(uint64_t tokenid, uint64_t timestamp)
{
    OpenDevDec();
    struct dec_rule_s info;
    info.tokenId = tokenid;
    info.timeStamp = timestamp;
    int ret = ioctl(g_fd, DESTORY_DEC_RULE_CMD, &info);
    if (ret != 0) {
        return -1;
    }
    return 0;
}

int QueryPath(uint64_t tokenid, const std::string &path, uint32_t mode)
{
    OpenDevDec();
    struct dec_rule_s info;
    info.addPath(path.c_str(), mode);
    info.tokenId = tokenid;
    int ret = ioctl(g_fd, QUERY_DEC_RULE_CMD, &info);
    if (ret != 0) {
        return -1;
    }
    if (info.path[0].ret_flag) {
        return 0;
    }
    return -1;
}

int TestAccess(uint64_t tokenid, const std::string &fileName, uint32_t mode, int32_t uid, int32_t gid)
{
    SetSelfTokenID(tokenid);
    if (SetProcessId(uid, gid) != 0) {
        return -1;
    }
    int ret = access(fileName.c_str(), F_OK);
    if (ret != 0) {
        return -1;
    }
    if (mode & DEC_MODE_READ) {
        ret = access(fileName.c_str(), R_OK);
        if (ret != 0) {
            return -1;
        }
    }
    if (mode & DEC_MODE_WRITE) {
        ret = access(fileName.c_str(), W_OK);
        if (ret != 0) {
            return -1;
        }
    }
    return 0;
}

int DeletePath(uint64_t tokenid, const std::string &path, uint64_t timestamp)
{
    OpenDevDec();
    struct dec_rule_s info;
    info.addPath(path.c_str());
    info.tokenId = tokenid;
    info.timeStamp = timestamp;
    int ret = ioctl(g_fd, DEL_DEC_RULE_CMD, &info);
    if (ret != 0) {
        return -1;
    }
    if (info.path[0].ret_flag) {
        return 0;
    }
    return -1;
}

int TestReadDir(uint64_t tokenid, const std::string &dirName, int32_t uid, int32_t gid)
{
    SetSelfTokenID(tokenid);
    if (SetProcessId(uid, gid) != 0) {
        return -1;
    }
    DIR *dir;
    struct dirent *ent;
    if ((dir = opendir(dirName.c_str())) != NULL) {
        int cnt = 0;
        while ((ent = readdir(dir)) != NULL) {
            std::cout << ent->d_name << std::endl;
            cnt++;
            if (cnt > DEC_CNT_LEN) {
                break;
            }
        }
        closedir(dir);
    } else {
        printf("open dir:%s failed %s\n", dirName.c_str(), strerror(errno));
        return -1;
    }
    return 0;
}

int TestRemoveDir(uint64_t tokenid, const std::string &fileName, int32_t uid, int32_t gid)
{
    SetSelfTokenID(tokenid);
    if (SetProcessId(uid, gid) != 0) {
        return -1;
    }
    int ret = rmdir(fileName.c_str());
    if (ret != 0) {
        printf("TestRemoveDir file:%s failed %s\n", fileName.c_str(), strerror(errno));
        return -1;
    }
    return 0;
}

int DeletePathByUser(int32_t user_id, const std::string &path)
{
    OpenDevDec();
    struct dec_rule_s info;
    info.addPath(path.c_str());
    info.userId = user_id;
    int ret = ioctl(g_fd, DEL_DEC_RULE_BY_USER_CMD, &info);
    if (ret != 0) {
        return -1;
    }
    if (info.path[0].ret_flag) {
        return 0;
    }
    return -1;
}
#endif