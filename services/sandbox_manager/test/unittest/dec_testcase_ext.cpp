/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef DEC_ENABLED
const uint64_t TOKEN_ID = 123;
const uint64_t TOKEN_ID1 = 222;
const int32_t USER_ID = 100;
const int32_t normal_user1 = 114514;
const mode_t CMASK = 066;

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class DecTestCaseExt : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DecTestCaseExt::SetUpTestCase(void)
{
    umask(CMASK);
}

void DecTestCaseExt::TearDownTestCase(void)
{
    DecTestClose();
}

void DecTestCaseExt::SetUp(void)
{}

void DecTestCaseExt::TearDown(void)
{}

/**
 * @tc.name: DecTestCaseExt001
 * @tc.desc: Test DecTestCaseExt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCaseExt, DecTestCaseExt001, TestSize.Level0)
{
    system("rm -rf /data/dec");
    system("mkdir -p /data/dec/dir1/dir11");
    system("mkdir -p /data/mntdec");
    system("touch /data/dec/dir1/dir11/dir11test.txt");
    system("touch /data/dec/dir1/dir1test.txt");
    system("touch /data/dec/dir1/dir1test2.txt");
    system("touch /data/dec/test.txt");
    system("mount -t sharefs /data/dec /data/mntdec -o override_support_delete -o user_id=100");
    EXPECT_EQ(ConstraintPath("/data/mntdec"), 0);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntdec", DEC_MODE_RW, true, 0, USER_ID), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec", DEC_MODE_RW), 0);
    EXPECT_EQ(QueryPath(TOKEN_ID, "/data/mntdec", DEC_MODE_RW), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/newtest.txt"), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/dir1/dir11/newtest.txt"), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt"), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/test.txt"), 0);
    EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt"), 0);
    EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/test.txt"), 0);
    EXPECT_EQ(TestCopy(TOKEN_ID, "/data/mntdec/test.txt", "/data/mntdec/dstTest1.txt"), 0);
    EXPECT_EQ(TestCopy(TOKEN_ID, "/data/mntdec/test.txt", "/data/dec/dstTest11.txt"), 0);
    EXPECT_EQ(Mkdir(TOKEN_ID, "/data/mntdec/dir2"), 0);
    EXPECT_EQ(Mkdir(TOKEN_ID, "/data/mntdec/dir1/dir12"), 0);
    EXPECT_EQ(TestRename(TOKEN_ID, "/data/mntdec/test.txt"), 0);
    EXPECT_EQ(TestRename(TOKEN_ID, "/data/mntdec/dir1/dir1test.txt"), 0);
    EXPECT_EQ(TestRename(TOKEN_ID, "/data/mntdec/dir1/dir1test2.txt"), 0);
    EXPECT_EQ(TestRename(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt"), 0);
    EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntdec/test.txt"), 0);
    EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntdec/dir1/dir1test.txt"), 0);
    EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt"), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID, 0), 0);
    system("umount /data/mntdec -l");
    system("rm -rf /data/dec");
}

/**
 * @tc.name: DecTestCaseExt002
 * @tc.desc: Test DecTestCaseExt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCaseExt, DecTestCaseExt002, TestSize.Level0)
{
    system("rm -rf /data/dec");
    system("mkdir -p /data/dec/dir1/dir11");
    system("mkdir -p /data/mntdec");
    system("touch /data/dec/dir1/dir11/test.txt");
    system("touch /data/dec/dir1/dir1test.txt");
    system("touch /data/dec/test.txt");
    system("mount -t sharefs /data/dec /data/mntdec -o override_support_delete -o user_id=100");
    pid_t pid = fork();
    if (pid == 0) {
        EXPECT_EQ(ConstraintPath("/data/mntdec"), 0);
        EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntdec", DEC_MODE_WRITE, true, 0, USER_ID), 0);
        EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec", DEC_MODE_WRITE), 0);
        EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/test.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/testA.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/dir1/dir11/newtest.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt", normal_user1, normal_user1), -1);
        EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/test.txt", normal_user1, normal_user1), -1);
        EXPECT_EQ(
            TestCopy(TOKEN_ID, "/data/mntdec/test.txt", "/data/mntdec/dstTest1.txt", normal_user1, normal_user1), -1);
        EXPECT_EQ(
            TestCopy(TOKEN_ID, "/data/mntdec/test.txt", "/data/dec/dstTest11.txt", normal_user1, normal_user1), -1);
        EXPECT_EQ(Mkdir(TOKEN_ID, "/data/mntdec/dir2", normal_user1, normal_user1), 0);
        EXPECT_EQ(Mkdir(TOKEN_ID, "/data/mntdec/dir1/dir12", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestRename(TOKEN_ID, "/data/mntdec/test.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestRename(TOKEN_ID, "/data/mntdec/dir1/dir11/test.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntdec/test.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntdec/dir1/dir1test.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt", normal_user1, normal_user1), 0);
        exit(0);
    } else {
        wait(NULL);
    }
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID, 0), 0);
    system("umount /data/mntdec -l");
    system("rm -rf /data/dec");
}

/**
 * @tc.name: DecTestCaseExt003
 * @tc.desc: Test DecTestCaseExt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCaseExt, DecTestCaseExt003, TestSize.Level0)
{
    system("rm -rf /data/dec");
    system("mkdir -p /data/dec/dir1/dir11");
    system("mkdir -p /data/mntdec");
    system("touch /data/dec/dir1/dir11/dir11test.txt");
    system("touch /data/dec/test.txt");
    system("mount -t sharefs /data/dec /data/mntdec -o override_support_delete -o user_id=100");
    pid_t pid = fork();
    if (pid == 0) {
        EXPECT_EQ(ConstraintPath("/data/mntdec"), 0);
        EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntdec", DEC_MODE_READ, true, 0, USER_ID), 0);
        EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec", DEC_MODE_READ), 0);
        EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec", DEC_MODE_WRITE), -1);
        EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec", DEC_MODE_RW), -1);
        EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/testnew.txt", normal_user1, normal_user1), -1);
        EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt", normal_user1, normal_user1), -1);
        EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/test.txt", normal_user1, normal_user1), -1);
        EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/test.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(
            TestCopy(TOKEN_ID, "/data/mntdec/test.txt", "/data/mntdec/dstTest.txt", normal_user1, normal_user1), -1);
        EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntdec/test.txt", normal_user1, normal_user1), -1);
        EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt", normal_user1, normal_user1), -1);
        EXPECT_EQ(TestRename(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt", normal_user1, normal_user1), -1);
        EXPECT_EQ(Mkdir(TOKEN_ID, "/data/mntdec/dir2", normal_user1, normal_user1), -1);
        EXPECT_EQ(Mkdir(TOKEN_ID, "/data/mntdec/dir1/dir12", normal_user1, normal_user1), -1);
        exit(0);
    } else {
        wait(NULL);
    }
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID, 0), 0);
    system("umount /data/mntdec -l");
    system("rm -rf /data/dec");
}

/**
 * @tc.name: DecTestCaseExt004
 * @tc.desc: Test DecTestCaseExt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCaseExt, DecTestCaseExt004, TestSize.Level0)
{
    system("rm -rf /data/dec");
    system("mkdir -p /data/dec/dir1/dir11");
    system("mkdir -p /data/dec/dir2/dir21");
    system("mkdir -p /data/mntdec");
    system("touch /data/dec/dir1/dir1test.txt");
    system("touch /data/dec/test.txt");
    system("touch /data/dec/dir2/dir21/dir21test.txt");
    system("mount -t sharefs /data/dec /data/mntdec -o override_support_delete -o user_id=100");
    pid_t pid = fork();
    if (pid == 0) {
        EXPECT_EQ(ConstraintPath("/data/mntdec"), 0);
        EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntdec", DEC_MODE_RW, true, 0, USER_ID), 0);
        EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec", DEC_MODE_RW), 0);
        EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec/dir2", DEC_MODE_RW), 0);
        EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec/dir2/dir21", DEC_MODE_RW), 0);
        EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/testnew.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec//dir2/testnew.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/dir2/dir21/testnew.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/test.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/test.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(
            TestCopy(TOKEN_ID, "/data/mntdec/test.txt", "/data/mntdec/dstTest.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntdec/test.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestRename(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(Mkdir(TOKEN_ID, "/data/mntdec/dir1/dir12", normal_user1, normal_user1), 0);
        EXPECT_EQ(DestroyByTokenid(TOKEN_ID, 0), 0);
        exit(0);
    } else {
        wait(NULL);
    }
    system("umount /data/mntdec -l");
    system("rm -rf /data/dec");
}

/**
 * @tc.name: DecTestCaseExt005
 * @tc.desc: Test DecTestCaseExt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCaseExt, DecTestCaseExt005, TestSize.Level0)
{
    system("rm -rf /data/dec");
    system("mkdir -p /data/dec/dir1");
    system("mkdir -p /data/mntdec");
    system("touch /data/dec/dir1/dir1test.txt");
    system("touch /data/dec/dir1/dir1test2.txt");
    system("touch /data/dec/test.txt");
    system("touch /data/dec/test2.txt");
    system("mount -t sharefs /data/dec /data/mntdec -o override_support_delete -o user_id=100");
    pid_t pid = fork();
    if (pid == 0) {
        EXPECT_EQ(ConstraintPath("/data/mntdec"), 0);
        EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntdec/test.txt", DEC_MODE_RW, true, 0, USER_ID), 0);
        EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntdec/test2.txt", DEC_MODE_READ, true, 0, USER_ID), 0);
        EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntdec/dir1/dir1test.txt", DEC_MODE_RW, true, 0, USER_ID), 0);
        EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntdec/dir1/dir1test2.txt", DEC_MODE_READ, true, 0, USER_ID), 0);
        EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec/test.txt", DEC_MODE_RW), 0);
        EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec/test2.txt", DEC_MODE_READ), 0);
        EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec/test2.txt", DEC_MODE_RW), -1);
        EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec/dir1/dir1test.txt", DEC_MODE_RW), 0);
        EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec/dir1/dir1test2.txt", DEC_MODE_READ), 0);
        EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec/dir1/dir1test2.txt", DEC_MODE_RW), -1);
        EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/test.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/test2.txt", normal_user1, normal_user1), -1);
        EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/dir1/dir1test.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/dir1/dir1test2.txt", normal_user1, normal_user1), -1);
        EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/test.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/test2.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/dir1/dir1test.txt", normal_user1, normal_user1), 0);
        EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/dir1/dir1test2.txt", normal_user1, normal_user1), 0);
        exit(0);
    } else {
        wait(NULL);
    }
    system("umount /data/mntdec -l");
    system("rm -rf /data/dec");
}

/**
 * @tc.name: testaccess006
 * @tc.desc: Test testaccess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCaseExt, testaccess006, TestSize.Level0)
{
    system("rm -rf /data/dec");
    system("mkdir -p /data/dec/dir1/dir11");
    system("mkdir -p /data/mntdecaccess");
    system("touch /data/dec/dir1/dir11/dir11test.txt");
    system("touch /data/dec/dir1/dir1test.txt");
    system("touch /data/dec/dir1/dir1test2.txt");
    system("touch /data/dec/test.txt");
    system("mount -t sharefs /data/dec /data/mntdecaccess -o override_support_delete -o user_id=100");
    pid_t pid = fork();
    if (pid == 0) {
        EXPECT_EQ(ConstraintPath("/data/mntdecaccess/dir1"), 0);
        EXPECT_EQ(DestroyByTokenid(TOKEN_ID1, 0), 0);
        EXPECT_EQ(TestAccess(TOKEN_ID1,
            "/data/mntdecaccess/dir1/dir11/dir11test.txt", 0, normal_user1, normal_user1), 0);
        EXPECT_EQ(TestAccess(TOKEN_ID1,
            "/data/mntdecaccess/dir1/dir11/dir11test.txt", DEC_MODE_READ, normal_user1, normal_user1), -1);
        EXPECT_EQ(TestAccess(TOKEN_ID1,
            "/data/mntdecaccess/dir1/dir11/dir11test.txt", DEC_MODE_WRITE, normal_user1, normal_user1), -1);
        EXPECT_EQ(SetPath(TOKEN_ID1, "/data/mntdecaccess/dir1", DEC_MODE_READ, true, 0, USER_ID), 0);
        EXPECT_EQ(TestAccess(TOKEN_ID1,
            "/data/mntdecaccess/dir1/dir11/dir11test.txt", 0, normal_user1, normal_user1), 0);
        EXPECT_EQ(TestAccess(TOKEN_ID1,
            "/data/mntdecaccess/dir1/dir11/dir11test.txt", DEC_MODE_READ, normal_user1, normal_user1), 0);
        EXPECT_EQ(TestAccess(TOKEN_ID1,
            "/data/mntdecaccess/dir1/dir11/dir11test.txt", DEC_MODE_WRITE, normal_user1, normal_user1), -1);
        EXPECT_EQ(DestroyByTokenid(TOKEN_ID1, 0), 0);
        EXPECT_EQ(SetPath(TOKEN_ID1, "/data/mntdecaccess/dir1", DEC_MODE_WRITE, true, 0, USER_ID), 0);
        EXPECT_EQ(TestAccess(TOKEN_ID1,
            "/data/mntdecaccess/dir1/dir11/dir11test.txt", 0, normal_user1, normal_user1), 0);
        EXPECT_EQ(TestAccess(TOKEN_ID1,
            "/data/mntdecaccess/dir1/dir11/dir11test.txt", DEC_MODE_READ, normal_user1, normal_user1), -1);
        EXPECT_EQ(TestAccess(TOKEN_ID1,
            "/data/mntdecaccess/dir1/dir11/dir11test.txt", DEC_MODE_WRITE, normal_user1, normal_user1), 0);
        EXPECT_EQ(DestroyByTokenid(TOKEN_ID1, 0), 0);
        exit(0);
    } else {
        wait(NULL);
    }
    system("umount /data/mntdecaccess -l");
    system("rm -rf /data/dec");
}

/**
 * @tc.name: testaccess1007
 * @tc.desc: Test testaccess1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCaseExt, testaccess007, TestSize.Level0)
{
    system("rm -rf /data/dec");
    system("mkdir -p /data/dec/dir1/dir11");
    system("mkdir -p /data/mntdecaccess");
    system("touch /data/dec/dir1/dir11/dir11test.txt");
    system("touch /data/dec/dir1/dir1test.txt");
    system("touch /data/dec/dir1/dir1test2.txt");
    system("touch /data/dec/test.txt");
    system("mount -t sharefs /data/dec /data/mntdecaccess -o override_support_delete -o user_id=100");
    pid_t pid = fork();
    if (pid == 0) {
        EXPECT_EQ(ConstraintPath("/data/mntdecaccess/dir1"), 0);
        EXPECT_EQ(DestroyByTokenid(TOKEN_ID1, 0), 0);
        EXPECT_EQ(SetPath(TOKEN_ID1, "/data/mntdecaccess/dir1", DEC_MODE_RW, true, 0, USER_ID), 0);
        EXPECT_EQ(TestAccess(TOKEN_ID1,
            "/data/mntdecaccess/dir1/dir11/dir11test.txt", 0, normal_user1, normal_user1), 0);
        EXPECT_EQ(TestAccess(TOKEN_ID1,
            "/data/mntdecaccess/dir1/dir11/dir11test.txt", DEC_MODE_READ, normal_user1, normal_user1), 0);
        EXPECT_EQ(TestAccess(TOKEN_ID1,
            "/data/mntdecaccess/dir1/dir11/dir11test.txt", DEC_MODE_WRITE, normal_user1, normal_user1), 0);
        EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/test.txt", 0, normal_user1, normal_user1), 0);
        EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/test.txt", DEC_MODE_READ, normal_user1, normal_user1), -1);
        EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/test.txt", DEC_MODE_WRITE, normal_user1, normal_user1), -1);
        EXPECT_EQ(DestroyByTokenid(TOKEN_ID1, 0), 0);
        EXPECT_EQ(TestAccess(TOKEN_ID1,
            "/data/mntdecaccess/dir1/dir11/dir11test.txt", 0, normal_user1, normal_user1), 0);
        EXPECT_EQ(TestAccess(TOKEN_ID1,
            "/data/mntdecaccess/dir1/dir11/dir11test.txt", DEC_MODE_READ, normal_user1, normal_user1), -1);
        EXPECT_EQ(TestAccess(TOKEN_ID1,
            "/data/mntdecaccess/dir1/dir11/dir11test.txt", DEC_MODE_WRITE, normal_user1, normal_user1), -1);
        EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/dec/test.txt", 0, normal_user1, normal_user1), 0);
        EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/dec/test.txt", DEC_MODE_READ, normal_user1, normal_user1), -1);
        EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/dec/test.txt", DEC_MODE_WRITE, normal_user1, normal_user1), -1);
        EXPECT_EQ(TestAccess(TOKEN_ID1,
            "/data/mntdecaccess/dir1/dir11/dir11test1.txt", 0, normal_user1, normal_user1), -1);
        EXPECT_EQ(TestAccess(TOKEN_ID1,
            "/data/mntdecaccess/dir1/dir11/dir11test1.txt", DEC_MODE_READ, normal_user1, normal_user1), -1);
        EXPECT_EQ(TestAccess(TOKEN_ID1,
            "/data/mntdecaccess/dir1/dir11/dir11test1.txt", DEC_MODE_WRITE, normal_user1, normal_user1), -1);
        exit(0);
    } else {
        wait(NULL);
    }
    system("umount /data/mntdecaccess -l");
    system("rm -rf /data/dec");
}

/**
 * @tc.name: testpaths008
 * @tc.desc: Test testpaths
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCaseExt, testpaths008, TestSize.Level0)
{
    system("rm -rf /data/dec");
    system("mkdir -p /data/dec");
    system("mkdir -p /data/dec/dir1/dir11");
    system("mkdir -p /data/dec/dir1/...");
    system("mkdir -p /data/mntdecpaths");
    system("mount -t sharefs /data/dec /data/mntdecpaths -o override_support_delete -o user_id=100");
    pid_t pid = fork();
    if (pid == 0) {
        EXPECT_EQ(ConstraintPath("/data/mntdecpaths/"), 0);
        EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntdecpaths/test//.mp4", DEC_MODE_RW, true, 0, USER_ID), -1);
        EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntdecpaths/dir1/../test.mp4", DEC_MODE_RW, true, 0, USER_ID), -1);
        EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntdecpaths/dir1/./test.mp4", DEC_MODE_RW, true, 0, USER_ID), -1);
        EXPECT_EQ(SetPath(TOKEN_ID, "data/mntdecpaths/dir1/./test.mp4", DEC_MODE_RW, true, 0, USER_ID), -1);
        EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntdecpaths/dir1/.../", DEC_MODE_RW, true, 0, USER_ID), 0);
        exit(0);
    } else {
        wait(NULL);
    }
    system("umount /data/mntdecpaths -l");
    system("rm -rf /data/dec");
}
} // SandboxManager
} // AccessControl
} // OHOS
#endif