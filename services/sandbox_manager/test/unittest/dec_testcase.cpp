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

#ifdef DEC_ENABLED
const uint64_t TOKEN_ID = 123;
const uint64_t TOKEN_ID1 = 222;
const int32_t USER_ID = 100;
const uint64_t TIMESTAMP = 1;
const uint64_t TIMESTAMP1 = 2;
const uint64_t TIMESTAMP2 = 3;
const uint64_t TIMESTAMP3 = 4;
const uint64_t TIMESTAMP4 = 5;

using namespace testing::ext;

const char* const TEST_BASE_PATH =
    "testdirdirtestdirdirtestdirdirtestdirdirtestdirdirr/"
    "testdirdirtestdirdirtestdirdirtestdirdirtestdirdirr/";
const char* const PATH_PREFIX = "/data/mntdecpaths/testdirdir/testdir/";
const char* const SUFFIX = "dir";

std::string CreatePath()
{
    std::string path{};
    path += PATH_PREFIX;
    const int BASE_COUNT = 39;
    for (int i = 0; i < BASE_COUNT; ++i) {
        path += TEST_BASE_PATH;
    }
    path += SUFFIX;
    return path;
}
const std::string TEST_LONG_PATH_4096 = CreatePath();
const std::string TEST_LONG_PATH_4097 = TEST_LONG_PATH_4096 + 'a';

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class DecTestCase : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DecTestCase::SetUpTestCase(void)
{}

void DecTestCase::TearDownTestCase(void)
{
    DecTestClose();
}

void DecTestCase::SetUp(void)
{}

void DecTestCase::TearDown(void)
{}

/**
 * @tc.name: DecTestCase001
 * @tc.desc: Test DecTestCase
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCase, DecTestCase001, TestSize.Level0)
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
 * @tc.name: DecTestCase002
 * @tc.desc: Test DecTestCase
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCase, DecTestCase002, TestSize.Level0)
{
    system("rm -rf /data/dec");
    system("mkdir -p /data/dec/dir1/dir11");
    system("mkdir -p /data/mntdec");
    system("touch /data/dec/dir1/dir11/test.txt");
    system("touch /data/dec/dir1/dir1test.txt");
    system("touch /data/dec/test.txt");
    system("mount -t sharefs /data/dec /data/mntdec -o override_support_delete -o user_id=100");
    EXPECT_EQ(ConstraintPath("/data/mntdec"), 0);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntdec", DEC_MODE_WRITE, true, 0, USER_ID), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec", DEC_MODE_WRITE), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/test.txt"), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/testA.txt"), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/dir1/dir11/newtest.txt"), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt"), 0);
    EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt"), -1);
    EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/test.txt"), -1);
    EXPECT_EQ(TestCopy(TOKEN_ID, "/data/mntdec/test.txt", "/data/mntdec/dstTest1.txt"), -1);
    EXPECT_EQ(TestCopy(TOKEN_ID, "/data/mntdec/test.txt", "/data/dec/dstTest11.txt"), -1);
    EXPECT_EQ(Mkdir(TOKEN_ID, "/data/mntdec/dir2"), 0);
    EXPECT_EQ(Mkdir(TOKEN_ID, "/data/mntdec/dir1/dir12"), 0);
    EXPECT_EQ(TestRename(TOKEN_ID, "/data/mntdec/test.txt"), 0);
    EXPECT_EQ(TestRename(TOKEN_ID, "/data/mntdec/dir1/dir11/test.txt"), 0);
    EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntdec/test.txt"), 0);
    EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntdec/dir1/dir1test.txt"), 0);
    EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt"), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID, 0), 0);
    system("umount /data/mntdec -l");
    system("rm -rf /data/dec");
}

/**
 * @tc.name: DecTestCase003
 * @tc.desc: Test DecTestCase
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCase, DecTestCase003, TestSize.Level0)
{
    system("rm -rf /data/dec");
    system("mkdir -p /data/dec/dir1/dir11");
    system("mkdir -p /data/mntdec");
    system("touch /data/dec/dir1/dir11/dir11test.txt");
    system("touch /data/dec/test.txt");
    system("mount -t sharefs /data/dec /data/mntdec -o override_support_delete -o user_id=100");
    EXPECT_EQ(ConstraintPath("/data/mntdec"), 0);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntdec", DEC_MODE_READ, true, 0, USER_ID), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec", DEC_MODE_READ), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec", DEC_MODE_WRITE), -1);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec", DEC_MODE_RW), -1);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/testnew.txt"), -1);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt"), -1);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/test.txt"), -1);
    EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt"), 0);
    EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/test.txt"), 0);
    EXPECT_EQ(TestCopy(TOKEN_ID, "/data/mntdec/test.txt", "/data/mntdec/dstTest.txt"), -1);
    EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntdec/test.txt"), -1);
    EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt"), -1);
    EXPECT_EQ(TestRename(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt"), -1);
    EXPECT_EQ(Mkdir(TOKEN_ID, "/data/mntdec/dir2"), -1);
    EXPECT_EQ(Mkdir(TOKEN_ID, "/data/mntdec/dir1/dir12"), -1);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID, 0), 0);
    system("umount /data/mntdec -l");
    system("rm -rf /data/dec");
}

/**
 * @tc.name: DecTestCase004
 * @tc.desc: Test DecTestCase
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCase, DecTestCase004, TestSize.Level0)
{
    system("rm -rf /data/dec");
    system("mkdir -p /data/dec/dir1/dir11");
    system("mkdir -p /data/dec/dir2/dir21");
    system("mkdir -p /data/mntdec");
    system("touch /data/dec/dir1/dir1test.txt");
    system("touch /data/dec/test.txt");
    system("touch /data/dec/dir2/dir21/dir21test.txt");
    system("mount -t sharefs /data/dec /data/mntdec -o override_support_delete -o user_id=100");
    EXPECT_EQ(ConstraintPath("/data/mntdec"), 0);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntdec", DEC_MODE_RW, true, 0, USER_ID), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec", DEC_MODE_RW), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec/dir2", DEC_MODE_RW), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntdec/dir2/dir21", DEC_MODE_RW), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/testnew.txt"), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec//dir2/testnew.txt"), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/dir2/dir21/testnew.txt"), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt"), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/test.txt"), 0);
    EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt"), 0);
    EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/test.txt"), 0);
    EXPECT_EQ(TestCopy(TOKEN_ID, "/data/mntdec/test.txt", "/data/mntdec/dstTest.txt"), 0);
    EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntdec/test.txt"), 0);
    EXPECT_EQ(TestRename(TOKEN_ID, "/data/mntdec/dir1/dir11/dir11test.txt"), 0);
    EXPECT_EQ(Mkdir(TOKEN_ID, "/data/mntdec/dir1/dir12"), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID, 0), 0);
    system("umount /data/mntdec -l");
    system("rm -rf /data/dec");
}

/**
 * @tc.name: DecTestCase005
 * @tc.desc: Test DecTestCase
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCase, DecTestCase005, TestSize.Level0)
{
    system("rm -rf /data/dec");
    system("mkdir -p /data/dec/dir1");
    system("mkdir -p /data/mntdec");
    system("touch /data/dec/dir1/dir1test.txt");
    system("touch /data/dec/dir1/dir1test2.txt");
    system("touch /data/dec/test.txt");
    system("touch /data/dec/test2.txt");
    system("mount -t sharefs /data/dec /data/mntdec -o override_support_delete -o user_id=100");
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
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/test.txt"), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/test2.txt"), -1);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/dir1/dir1test.txt"), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdec/dir1/dir1test2.txt"), -1);
    EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/test.txt"), 0);
    EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/test2.txt"), 0);
    EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/dir1/dir1test.txt"), 0);
    EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntdec/dir1/dir1test2.txt"), 0);
    system("umount /data/mntdec -l");
    system("rm -rf /data/dec");
}

/**
 * @tc.name: testaccess006
 * @tc.desc: Test testaccess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCase, testaccess006, TestSize.Level0)
{
    system("rm -rf /data/dec");
    system("mkdir -p /data/dec/dir1/dir11");
    system("mkdir -p /data/mntdecaccess");
    system("touch /data/dec/dir1/dir11/dir11test.txt");
    system("touch /data/dec/dir1/dir1test.txt");
    system("touch /data/dec/dir1/dir1test2.txt");
    system("touch /data/dec/test.txt");
    system("mount -t sharefs /data/dec /data/mntdecaccess -o override_support_delete -o user_id=100");
    EXPECT_EQ(ConstraintPath("/data/mntdecaccess/dir1"), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID1, 0), 0);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/dir1/dir11/dir11test.txt", 0), 0);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/dir1/dir11/dir11test.txt", DEC_MODE_READ), -1);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/dir1/dir11/dir11test.txt", DEC_MODE_WRITE), -1);
    EXPECT_EQ(SetPath(TOKEN_ID1, "/data/mntdecaccess/dir1", DEC_MODE_READ, true, 0, USER_ID), 0);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/dir1/dir11/dir11test.txt", 0), 0);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/dir1/dir11/dir11test.txt", DEC_MODE_READ), 0);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/dir1/dir11/dir11test.txt", DEC_MODE_WRITE), -1);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID1, 0), 0);
    EXPECT_EQ(SetPath(TOKEN_ID1, "/data/mntdecaccess/dir1", DEC_MODE_WRITE, true, 0, USER_ID), 0);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/dir1/dir11/dir11test.txt", 0), 0);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/dir1/dir11/dir11test.txt", DEC_MODE_READ), -1);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/dir1/dir11/dir11test.txt", DEC_MODE_WRITE), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID1, 0), 0);
    EXPECT_EQ(SetPath(TOKEN_ID1, "/data/mntdecaccess/dir1", DEC_MODE_RW, true, 0, USER_ID), 0);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/dir1/dir11/dir11test.txt", 0), 0);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/dir1/dir11/dir11test.txt", DEC_MODE_READ), 0);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/dir1/dir11/dir11test.txt", DEC_MODE_WRITE), 0);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/test.txt", 0), 0);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/test.txt", DEC_MODE_READ), 0);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/test.txt", DEC_MODE_WRITE), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID1, 0), 0);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/dir1/dir11/dir11test.txt", 0), 0);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/dir1/dir11/dir11test.txt", DEC_MODE_READ), -1);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/dir1/dir11/dir11test.txt", DEC_MODE_WRITE), -1);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/dec/test.txt", 0), 0);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/dec/test.txt", DEC_MODE_READ), 0);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/dec/test.txt", DEC_MODE_WRITE), 0);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/dir1/dir11/dir11test1.txt", 0), -1);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/dir1/dir11/dir11test1.txt", DEC_MODE_READ), -1);
    EXPECT_EQ(TestAccess(TOKEN_ID1, "/data/mntdecaccess/dir1/dir11/dir11test1.txt", DEC_MODE_WRITE), -1);
    system("umount /data/mntdecaccess -l");
    system("rm -rf /data/dec");
}

/**
 * @tc.name: testpaths007
 * @tc.desc: Test testpaths
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCase, testpaths007, TestSize.Level0)
{
    system("rm -rf /data/dec");
    system("mkdir -p /data/dec");
    system("mkdir -p /data/dec/dir1/dir11");
    system("mkdir -p /data/dec/dir1/...");
    system("mkdir -p /data/mntdecpaths");
    system("mount -t sharefs /data/dec /data/mntdecpaths -o override_support_delete -o user_id=100");
    EXPECT_EQ(ConstraintPath("/data/mntdecpaths/"), 0);
    EXPECT_EQ(ConstraintPath(TEST_LONG_PATH_4096), 0);
    EXPECT_EQ(ConstraintPath(TEST_LONG_PATH_4097), -1);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntdecpaths/test//.mp4", DEC_MODE_RW, true, 0, USER_ID), -1);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntdecpaths/dir1/../test.mp4", DEC_MODE_RW, true, 0, USER_ID), -1);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntdecpaths/dir1/./test.mp4", DEC_MODE_RW, true, 0, USER_ID), -1);
    EXPECT_EQ(SetPath(TOKEN_ID, "data/mntdecpaths/dir1/./test.mp4", DEC_MODE_RW, true, 0, USER_ID), -1);
    EXPECT_EQ(SetPath(TOKEN_ID, TEST_LONG_PATH_4096, DEC_MODE_RW, true, 0, USER_ID), 0);
    EXPECT_EQ(SetPath(TOKEN_ID, TEST_LONG_PATH_4097, DEC_MODE_RW, true, 0, USER_ID), -1);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntdecpaths/dir1/.../", DEC_MODE_RW, true, 0, USER_ID), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntdecpaths/dir1/.../test.mp4"), 0);
    system("umount /data/mntdecpaths -l");
    system("rm -rf /data/dec");
}

/**
 * @tc.name: testFatherChild008
 * @tc.desc: Test testFatherChild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCase, testFatherChild008, TestSize.Level0)
{
    int result = ConstraintPath("/a/b");
    EXPECT_EQ(result, 0);
    EXPECT_EQ(SetPath(TOKEN_ID, "/a/b/c", DEC_MODE_WRITE, true, 0, USER_ID), 0);
    EXPECT_EQ(SetPath(TOKEN_ID, "/a/b/c/d", DEC_MODE_READ, true, 0, USER_ID), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/a/b/c/d/e", DEC_MODE_WRITE), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/a/b/c/d/e", DEC_MODE_READ), -1);
    EXPECT_EQ(DeletePath(TOKEN_ID, "/a/b/c", 0), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/a/b/c/d/e", DEC_MODE_WRITE), -1);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/a/b/c/d/e", DEC_MODE_READ), 0);
}

/**
 * @tc.name: testDir009
 * @tc.desc: Test testDir
 * @tc.type: FUNC
 * @tc.require:
 */
 HWTEST_F(DecTestCase, testDir009, TestSize.Level0)
{
    system("rm -rf /data/dec");
    system("mkdir -p /data/dec/a");
    system("touch /data/dec/test.mp4");
    system("touch /data/dec/a/test.mp4");
    system("mkdir -p /data/mntDeleteDir");
    system("mount -t sharefs /data/dec /data/mntDeleteDir -o override_support_delete -o user_id=100");
    EXPECT_EQ(ConstraintPath("/data/mntDeleteDir"), 0);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntDeleteDir", DEC_MODE_RW, true, 0, USER_ID), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID, 0), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntDeleteDir", DEC_MODE_RW), -1);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntDeleteDir/test.mp4", DEC_MODE_RW), -1);
    EXPECT_EQ(TestReadDir(TOKEN_ID, "/data/mntDeleteDir/"), -1);
    EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntDeleteDir/test.mp4"), -1);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntDeleteDir/test.mp4"), -1);
    EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntDeleteDir/a/test.mp4"), -1);
    EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntDeleteDir/test.mp4"), -1);
    EXPECT_EQ(TestRemoveDir(TOKEN_ID, "/data/mntDeleteDir/a"), -1);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntDeleteDir", DEC_MODE_RW, true, 0, USER_ID), 0);
    EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntDeleteDir/a/test.mp4"), 0);
    EXPECT_EQ(TestRemoveDir(TOKEN_ID, "/data/mntDeleteDir/a"), 0);
    EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntDeleteDir/test.mp4"), 0);
    EXPECT_EQ(TestReadDir(TOKEN_ID, "/data/mntDeleteDir/"), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID, 0), 0);
    system("umount /data/mntDeleteDir -l");
    system("rm -rf /data/dec");
}

/**
 * @tc.name: testdelete010
 * @tc.desc: Test testdelete
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCase, testdelete010, TestSize.Level0)
{
    system("rm -rf /data/a");
    system("mkdir -p /data/a/b/c");
    system("touch /data/a/b/c/test.mp4");
    system("mkdir -p /data/mnta");
    system("mount -t sharefs /data/a /data/mnta -o override_support_delete -o user_id=100");
    EXPECT_EQ(ConstraintPath("/data/mnta/"), 0);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mnta/b/c", DEC_MODE_RW, true, 0, USER_ID), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mnta/b/c", DEC_MODE_RW), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mnta/b/c/test.mp4"), 0);
    EXPECT_EQ(DeletePath(TOKEN_ID, "/data/mnta/b/c", 0), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mnta/b/c", DEC_MODE_RW), -1);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mnta/b/c/test.mp4"), -1);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mnta/b/c", DEC_MODE_RW, true, 0, USER_ID), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mnta/b/c", DEC_MODE_RW), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mnta/b/c/test.mp4"), 0);
    system("umount /data/mnta -l");
    system("rm -rf /data/a");
}

/**
 * @tc.name: testdestroy011
 * @tc.desc: Test testdestroy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCase, testdestroy011, TestSize.Level0)
{
    system("rm -rf /data/a");
    system("mkdir -p /data/a/b/c");
    system("touch /data/a/b/c/test.mp4");
    system("mkdir -p /data/mnta");
    system("mount -t sharefs /data/a /data/mnta -o override_support_delete -o user_id=100");
    EXPECT_EQ(ConstraintPath("/data/mnta/"), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID, 0), 0);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mnta/b/c", DEC_MODE_RW, true, 0, USER_ID), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mnta/b/c", DEC_MODE_RW), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mnta/b/c/test.mp4"), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID, 0), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mnta/b/c", DEC_MODE_RW), -1);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mnta/b/c/test.mp4"), -1);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mnta/b/c", DEC_MODE_RW, true, 0, USER_ID), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mnta/b/c", DEC_MODE_RW), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mnta/b/c/test.mp4"), 0);
    system("umount /data/mnta -l");
    system("rm -rf /data/a");
}

/**
 * @tc.name: testUserId012
 * @tc.desc: Test testUserId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCase, testUserId012, TestSize.Level0)
{
    system("rm -rf /data/testUserId");
    system("mkdir -p /data/testUserId/a");
    system("touch /data/testUserId/a/test.txt");
    system("mkdir -p /data/mntTestUserId/");
    system("mount -t sharefs /data/testUserId /data/mntTestUserId -o override_support_delete -o user_id=100");
    EXPECT_EQ(ConstraintPath("/data/mntTestUserId/"), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID, 0), 0);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntTestUserId/a/test.txt", DEC_MODE_RW, true, 0, USER_ID), 0);
    EXPECT_EQ(SetPath(TOKEN_ID + 1, "/data/mntTestUserId/a/test.txt", DEC_MODE_RW, true, 0, USER_ID + 1), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID + 1, "/data/mntTestUserId/a/test.txt", 0), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntTestUserId/a/test.txt", 0), 0);
    EXPECT_EQ(DeletePathByUser(USER_ID, "/data/mntTestUserId/a/test.txt"), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID + 1, "/data/mntTestUserId/a/test.txt", 0), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntTestUserId/a/test.txt", 0), -1);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntTestUserId/a/test.txt", DEC_MODE_RW, true, 0, USER_ID), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntTestUserId/a/test.txt", 0), 0);
    system("umount /data/mntTestUserId -l");
    system("rm -rf /data/testUserId");
}

/**
 * @tc.name: testTimestamp013
 * @tc.desc: Test testTimestamp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCase, testTimestamp013, TestSize.Level0)
{
    system("rm -rf /data/testTimestamp");
    system("mkdir -p /data/testTimestamp/a");
    system("touch /data/testTimestamp/a/test.txt");
    system("mkdir -p /data/mntTestTimestamp/");
    system(
        "mount -t sharefs /data/testTimestamp /data/mntTestTimestamp -o override_support_delete -o user_id=100");
    EXPECT_EQ(ConstraintPath("/data/mntTestTimestamp/"), 0);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntTestTimestamp/a/test.txt", DEC_MODE_RW, true, TIMESTAMP2, USER_ID), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntTestTimestamp/a/test.txt", 0), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID, TIMESTAMP1), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntTestTimestamp/a/test.txt", 0), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID, TIMESTAMP4), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntTestTimestamp/a/test.txt", 0), -1);
    system("umount /data/mntTestTimestamp -l");
    system("rm -rf /data/testTimestamp");
}

/**
 * @tc.name: testTimestampUpdate014
 * @tc.desc: Test testTimestampUpdate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCase, testTimestampUpdate014, TestSize.Level0)
{
    system("rm -rf /data/testTimestampUpdate");
    system("mkdir -p /data/testTimestampUpdate/a");
    system("touch /data/testTimestampUpdate/a/test.txt");
    system("mkdir -p /data/mntTestTimestampUpdate/");
    system("mount -t sharefs /data/testTimestampUpdate "
        "/data/mntTestTimestampUpdate -o override_support_delete -o user_id=100");
    EXPECT_EQ(ConstraintPath("/data/mntTestTimestampUpdate/"), 0);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntTestTimestampUpdate/a/test.txt", DEC_MODE_RW, true, TIMESTAMP2, USER_ID), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntTestTimestampUpdate/a/test.txt", 0), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID, TIMESTAMP1), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntTestTimestampUpdate/a/test.txt", 0), 0);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntTestTimestampUpdate/a/test.txt", DEC_MODE_RW, true, TIMESTAMP, USER_ID), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID, TIMESTAMP4), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntTestTimestampUpdate/a/test.txt", 0), -1);
    system("umount /data/mntTestTimestampUpdate -l");
    system("rm -rf /data/testTimestampUpdate");
}

/**
 * @tc.name: testTimestampDelete015
 * @tc.desc: Test testTimestampDelete
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCase, testTimestampDelete015, TestSize.Level0)
{
    system("rm -rf /data/testTimestampDelete");
    system("mkdir -p /data/testTimestampDelete/a");
    system("touch /data/testTimestampDelete/a/test.txt");
    system("mkdir -p /data/mntTimestampDelete/");
    system("mount -t sharefs /data/testTimestampDelete "
        "/data/mntTimestampDelete -o override_support_delete -o user_id=100");
    EXPECT_EQ(ConstraintPath("/data/mntTimestampDelete/"), 0);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntTimestampDelete/a/test.txt", DEC_MODE_RW, true, TIMESTAMP2, USER_ID), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntTimestampDelete/a/test.txt", 0), 0);
    EXPECT_EQ(DeletePath(TOKEN_ID, "/data/mntTimestampDelete/a/test.txt", TIMESTAMP1), -1);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntTimestampDelete/a/test.txt", 0), 0);
    EXPECT_EQ(DeletePath(TOKEN_ID, "/data/mntTimestampDelete/a/test.txt", TIMESTAMP3), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntTimestampDelete/a/test.txt", 0), -1);
    system("umount /data/mntTimestampDelete -l");
    system("rm -rf /data/testTimestampDelete");
}

/**
 * @tc.name: testRootPath016
 * @tc.desc: Test testRootPath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCase, testRootPath016, TestSize.Level0)
{
    system("rm -rf /data/dec");
    system("mkdir -p /data/dec/dir1/dir11");
    system("mkdir -p /data/mntdec");
    system("touch /data/dec/dir1/dir11/dir11test.txt");
    system("touch /data/dec/dir1/dir11/dir11test.txt");
    system("touch /data/dec/dir1/dir1test.txt");
    system("touch /data/dec/test.txt");
    system("mount -t sharefs /data/dec /data/mntdec -o override_support_delete -o user_id=100");
    EXPECT_EQ(SetPath(TOKEN_ID, "/", DEC_MODE_RW, true, 0, USER_ID), 0);
    EXPECT_EQ(DestroyByTokenid(TOKEN_ID, 0), 0);
    system("umount /data/mntdec -l");
    system("rm -rf /data/dec");
}

/**
 * @tc.name: testUserId017
 * @tc.desc: Test UserIdTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DecTestCase, testUserId017, TestSize.Level0)
{
    system("rm -rf /data/UserIdTest");
    system("mkdir -p /data/UserIdTest/a");
    system("touch /data/UserIdTest/a/test.txt");
    system("mkdir -p /data/mntUserIdTest/");
    system("mount -t sharefs /data/UserIdTest /data/mntUserIdTest -o override_support_delete -o user_id=100");
    EXPECT_EQ(ConstraintPath("/data/mntUserIdTest/"), 0);
    EXPECT_EQ(SetPath(TOKEN_ID, "/data/mntUserIdTest/", DEC_MODE_RW, true, 0, USER_ID), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntUserIdTest/a", 0), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntUserIdTest/a/test.txt", 0), 0);
    EXPECT_EQ(TestReadDir(TOKEN_ID, "/data/mntUserIdTest/a"), 0);
    EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntUserIdTest/a/test.txt"), 0);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntUserIdTest/a/test.txt"), 0);
    EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntUserIdTest/a/test.txt"), 0);
    EXPECT_EQ(TestRemoveDir(TOKEN_ID, "/data/mntUserIdTest/a"), 0);

    EXPECT_EQ(DeletePathByUser(USER_ID, "/data/mntUserIdTest/"), 0);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntUserIdTest/a", 0), -1);
    EXPECT_EQ(CheckPath(TOKEN_ID, "/data/mntUserIdTest/a/test.txt", 0), -1);
    EXPECT_EQ(TestReadDir(TOKEN_ID, "/data/mntUserIdTest/a"), -1);
    EXPECT_EQ(TestRead(TOKEN_ID, "/data/mntUserIdTest/a/test.txt"), -1);
    EXPECT_EQ(TestWrite(TOKEN_ID, "/data/mntUserIdTest/a/test.txt"), -1);
    EXPECT_EQ(TestRemove(TOKEN_ID, "/data/mntUserIdTest/a/test.txt"), -1);
    EXPECT_EQ(TestRemoveDir(TOKEN_ID, "/data/mntUserIdTest/a"), -1);
    system("umount /data/mntUserIdTest -l");
    system("rm -rf /data/UserIdTest");
    system("rm -rf /data/mntUserIdTest/");
}
} // SandboxManager
} // AccessControl
} // OHOS
#endif