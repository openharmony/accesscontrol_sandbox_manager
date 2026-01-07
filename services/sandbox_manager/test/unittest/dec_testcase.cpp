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
{
    OpenDevDec();
}

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


HWTEST_F(DecTestCase, testDestroy, TestSize.Level0)
{
    EXPECT_TRUE(ExcuteCmd("if [ -d /data/a ]; then rm -rf /data/a; fi"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/a/b/c"));
    EXPECT_TRUE(ExcuteCmd("touch /data/a/b/c/test.mp4"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/mnta"));
    EXPECT_TRUE(ExcuteCmd("mount -t sharefs /data/a /data/mnta -o override_support_delete -o user_id=100"));

    DestroyByTokenid(123, 0);
    EXPECT_TRUE(SetPath(123, "/data/mnta/b/c", DEC_MODE_RW, true, 0, USER_ID) == RET_OK);
    EXPECT_TRUE(CheckPath(123, "/data/mnta/b/c", 0) == RET_OK);
    EXPECT_TRUE(TestWrite(123, "/data/mnta/b/c/test.mp4") == RET_OK);
    EXPECT_TRUE(DestroyByTokenid(TOKEN_ID, 0) == RET_OK);

    EXPECT_FALSE(CheckPath(123, "/data/mnta/b/c", 0) == RET_OK);
    EXPECT_FALSE(TestWrite(123, "/data/mnta/b/c/test.mp4") == RET_OK);

    EXPECT_TRUE(SetPath(123, "/data/mnta/b/c", DEC_MODE_RW, true, 0, USER_ID) == RET_OK);
    EXPECT_TRUE(CheckPath(123, "/data/mnta/b/c", 0) == RET_OK);
    EXPECT_TRUE(TestWrite(123, "/data/mnta/b/c/test.mp4") == RET_OK);

    EXPECT_TRUE(ExcuteCmd("umount /data/mnta -l"));
    EXPECT_TRUE(ExcuteCmd("if [ -d /data/a ]; then rm -rf /data/a; fi"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/mnta ] && rm -rf /data/mnta"));
}

HWTEST_F(DecTestCase, testAppData, TestSize.Level0)
{
    EXPECT_TRUE(ExcuteCmd("if [ -d /data/a ]; then rm -rf /data/a; fi"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/a/currentUser/appdata/el2"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/a/currentUser/Desktop"));
    EXPECT_TRUE(ExcuteCmd("touch /data/a/currentUser/appdata/test.mp4"));
    EXPECT_TRUE(ExcuteCmd("touch /data/a/currentUser/appdata/el2/test.mp4"));
    EXPECT_TRUE(ExcuteCmd("touch /data/a/currentUser/Desktop/test.mp4"));
    EXPECT_TRUE(ExcuteCmd("touch /data/a/currentUser/test.mp4"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/mnta/currentUser"));

    EXPECT_TRUE(ExcuteCmd("mount -t sharefs /data/a/currentUser /data/mnta/currentUser -o \
        override_support_delete -o user_id=100"));

    EXPECT_TRUE(SetPrefix("/data/mnta/currentUser/appdata") == RET_OK);
    EXPECT_TRUE(SetPath(123, "/data/mnta/currentUser", DEC_MODE_RW, true, 0, USER_ID) == RET_OK);
    EXPECT_TRUE(SetPath(123, "/data/mnta/currentUser/appdata/el2", DEC_MODE_RW, true, 0, USER_ID) == RET_OK);
    EXPECT_TRUE(CheckPath(123, "/data/mnta/currentUser/appdata/el2/test.mp4", DEC_MODE_RW) == RET_OK);
    EXPECT_TRUE(TestWrite(123, "/data/mnta/currentUser/test.mp4") == RET_OK);
    EXPECT_TRUE(TestReadDir(123, "/data/mnta/currentUser") == RET_OK);
    EXPECT_TRUE(CheckPath(123, "/data/mnta/currentUser/test.mp4", DEC_MODE_RW) == RET_OK);
    EXPECT_TRUE(CheckPath(123, "/data/mnta/currentUser/Desktop/test.mp4", DEC_MODE_RW) == RET_OK);
    EXPECT_FALSE(CheckPath(123, "/data/mnta/currentUser/appdata/test.mp4", DEC_MODE_RW) == RET_OK);
    EXPECT_FALSE(CheckPath(123, "/data/mnta/currentUser/appdata/test.mp4", DEC_MODE_RW) == RET_OK);
    EXPECT_TRUE(TestWrite(123, "/data/mnta/currentUser/test.mp4") == RET_OK);
    EXPECT_TRUE(TestWrite(123, "/data/mnta/currentUser/Desktop/test.mp4") == RET_OK);
    EXPECT_FALSE(TestWrite(123, "/data/mnta/currentUser/appdata/test.mp4") == RET_OK);
    EXPECT_TRUE(SetPath(123, "/data/mnta/currentUser/appdata", DEC_MODE_RW, true, 0, USER_ID) == RET_OK);
    EXPECT_TRUE(CheckPath(123, "/data/mnta/currentUser/appdata/test.mp4", DEC_MODE_RW) == RET_OK);
    EXPECT_TRUE(TestWrite(123, "/data/mnta/currentUser/appdata/test.mp4") == RET_OK);

    EXPECT_TRUE(DestroyByTokenid(123, 0) == RET_OK);

    EXPECT_TRUE(ExcuteCmd("umount /data/mnta/currentUser"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/a ] && rm -rf /data/a"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/mnta/currentUser ] && rm -rf /data/mnta/currentUser"));
}

HWTEST_F(DecTestCase, testRenameWithConstraint, TestSize.Level0)
{
    EXPECT_TRUE(ExcuteCmd("if [ -d /data/a ]; then rm -rf /data/a; fi"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/a/b/c"));

    EXPECT_TRUE(ExcuteCmd("touch /data/a/test.mp4"));
    EXPECT_TRUE(ExcuteCmd("touch /data/a/b/test.mp4"));
    EXPECT_TRUE(ExcuteCmd("touch /data/a/b/c/test.mp4"));
    EXPECT_TRUE(ExcuteCmd("touch /data/a/b/c/test2.mp4"));

    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/mnta"));
    EXPECT_TRUE(ExcuteCmd("mount -t sharefs /data/a /data/mnta -o override_support_delete -o user_id=100"));

    EXPECT_TRUE(ConstraintPath("/data/mnta/") == RET_OK);
    EXPECT_FALSE(TestRename(123, "/data/mntdec/test.txt") == RET_OK);
    EXPECT_FALSE(TestRename(123, "/data/mnta/b/c/test.mp4") == RET_OK);
    EXPECT_TRUE(SetPath(123, "/data/mnta/b", DEC_MODE_RW, true, 0, USER_ID) == RET_OK);
    EXPECT_FALSE(TestRename2(123, "/data/mnta/test.mp4", "/data/mnta/b/bnewtest.mp4") == RET_OK);
    EXPECT_FALSE(TestRename2(123, "/data/mnta/b/test.mp4", "/data/mnta/anewtest.mp4") == RET_OK);
    EXPECT_TRUE(TestRename2(123, "/data/mnta/b/test.mp4", "/data/mnta/b/c/cnewtest.mp4") == RET_OK);
    EXPECT_TRUE(DestroyByTokenid(123) == RET_OK);

    EXPECT_TRUE(ExcuteCmd("umount /data/mnta/ -l"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/a ] && rm -rf /data/a"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/mnta ] && rm -rf /data/mnta"));
}

HWTEST_F(DecTestCase, testRemove, TestSize.Level0)
{
    EXPECT_TRUE(ExcuteCmd("if [ -d /data/a ]; then rm -rf /data/a; fi"));

    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/a/b/c"));
    EXPECT_TRUE(ExcuteCmd("touch /data/a/test.mp4"));
    EXPECT_TRUE(ExcuteCmd("touch /data/a/b/c/test.mp4"));
    EXPECT_TRUE(ExcuteCmd("touch /data/a/b/c/test2.mp4"));

    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/mnta"));
    EXPECT_TRUE(ExcuteCmd("mount -t sharefs /data/a /data/mnta -o override_support_delete -o user_id=100"));

    EXPECT_TRUE(ConstraintPath("/data/mnta/") == RET_OK);

    EXPECT_FALSE(TestRemove(789, "/data/mntdec/test.txt") == RET_OK);
    EXPECT_FALSE(TestRemove(789, "/data/mnta/b/c/test.mp4") == RET_OK);

    EXPECT_TRUE(ExcuteCmd("umount /data/mnta/ -l"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/a ] && rm -rf /data/a"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/mnta ] && rm -rf /data/mnta"));
}

HWTEST_F(DecTestCase, testRecursiveDelete, TestSize.Level0)
{
    EXPECT_TRUE(ExcuteCmd("if [ -d /data/RecursiveDelete ]; then rm -rf /data/RecursiveDelete; fi"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/RecursiveDelete/a/b/c"));
    EXPECT_TRUE(ExcuteCmd("touch /data/RecursiveDelete/a/b/c/test.mp4"));

    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/mntRecursiveDelete"));

    EXPECT_TRUE(ExcuteCmd("mount -t sharefs /data/RecursiveDelete /data/mntRecursiveDelete -o \
        override_support_delete -o user_id=100"));

    EXPECT_TRUE(ConstraintPath("/data/mntRecursiveDelete/") == RET_OK);

    EXPECT_TRUE(SetPath(1, "/data/mntRecursiveDelete/a/b/c/test.mp4", DEC_MODE_RW, true, 0, 100) == RET_OK);
    EXPECT_TRUE(SetPath(2, "/data/mntRecursiveDelete/a/b/c/test.mp4", DEC_MODE_RW, true, 0, 101) == RET_OK);
    EXPECT_FALSE(CheckPath(1, "/data/mntRecursiveDelete/a/", DEC_MODE_RW) == RET_OK);
    EXPECT_TRUE(CheckPath(1, "/data/mntRecursiveDelete/a/b/c/test.mp4", DEC_MODE_RW) == RET_OK);
    EXPECT_TRUE(CheckPath(2, "/data/mntRecursiveDelete/a/b/c/test.mp4", DEC_MODE_RW) == RET_OK);

    EXPECT_TRUE(DeletePathByUser(100, "/data/mntRecursiveDelete/a/") == RET_OK);
    EXPECT_FALSE(CheckPath(1, "/data/mntRecursiveDelete/a/b/c/test.mp4", DEC_MODE_RW) == RET_OK);
    EXPECT_TRUE(CheckPath(2, "/data/mntRecursiveDelete/a/b/c/test.mp4", DEC_MODE_RW) == RET_OK);

    EXPECT_TRUE(ExcuteCmd("umount /data/mntRecursiveDelete -l"));
    EXPECT_TRUE(ExcuteCmd("if [ -d /data/RecursiveDelete ]; then rm -rf /data/RecursiveDelete; fi"));
    EXPECT_TRUE(ExcuteCmd("if [ -d /data/mntRecursiveDelete ]; then rm -rf /data/mntRecursiveDelete; fi"));
}

HWTEST_F(DecTestCase, testDenyInherit, TestSize.Level0)
{
    EXPECT_TRUE(ExcuteCmd("if [ -d /data/testDeny ]; then rm -rf /data/testDeny; fi"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/testDeny/appdata/"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/testDeny/dir1/"));
    EXPECT_TRUE(ExcuteCmd("touch /data/testDeny/appdata/test.mp4"));
    EXPECT_TRUE(ExcuteCmd("touch /data/testDeny/dir1/test.mp4"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/mntTestDeny"));

    EXPECT_TRUE(ExcuteCmd("mount -t sharefs /data/testDeny /data/mntTestDeny -o \
        override_support_delete -o user_id=100"));

    EXPECT_TRUE(ConstraintPath("/data/mntTestDeny/") == RET_OK);
    EXPECT_TRUE(DenyPath(123, "/data/mntTestDeny/appdata", DEC_DENY_INHERIT, 0, USER_ID) == RET_OK);
    EXPECT_TRUE(SetPath(123, "/data/mntTestDeny/", DEC_MODE_RW, true, 0, USER_ID) == RET_OK);
    EXPECT_FALSE(CheckPath(123, "/data/mntTestDeny/appdata/", DEC_MODE_RW) == RET_OK);
    EXPECT_FALSE(CheckPath(123, "/data/mntTestDeny/appdata/test.mp4", DEC_MODE_RW) == RET_OK);
    EXPECT_TRUE(SetPath(123, "/data/mntTestDeny/appdata", DEC_MODE_RW, true, 0, USER_ID) == RET_OK);
    EXPECT_TRUE(CheckPath(123, "/data/mntTestDeny/appdata/", DEC_MODE_RW) == RET_OK);
    EXPECT_TRUE(CheckPath(123, "/data/mntTestDeny/appdata/test.mp4", DEC_MODE_RW) == RET_OK);
    EXPECT_TRUE(DestroyByTokenid(123) == RET_OK);

    EXPECT_TRUE(ExcuteCmd("umount /data/mntTestDeny -l"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/testDeny/ ] && rm -rf  "));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/mntTestDeny ] && rm -rf /data/mntTestDeny"));
}

HWTEST_F(DecTestCase, testDenyDelete, TestSize.Level0)
{
    EXPECT_TRUE(ExcuteCmd("if [ -d /data/testDenyDelete ]; then rm -rf /data/testDenyDelete; fi"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/testDenyDelete/.Trash/"));

    EXPECT_TRUE(ExcuteCmd("touch /data/testDenyDelete/test.mp4"));
    EXPECT_TRUE(ExcuteCmd("touch /data/testDenyDelete/.Trash/test.mp4"));

    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/mntTestDenyDelete"));

    EXPECT_TRUE(ExcuteCmd(
        "mount -t sharefs /data/testDenyDelete /data/mntTestDenyDelete -o override_support_delete -o user_id=100"));

    EXPECT_TRUE(ConstraintPath("/data/mntTestDenyDelete/") == RET_OK);
    EXPECT_TRUE(SetPath(123, "/data/mntTestDenyDelete/", DEC_MODE_RW, true, 0, USER_ID) == RET_OK);
    EXPECT_TRUE(DenyPath(0, "/data/mntTestDenyDelete/.Trash", DEC_DENY_REMOVE, 0, USER_ID) == RET_OK);

    EXPECT_TRUE(TestRemove(123, "/data/mntTestDenyDelete/.Trash/test.mp4") == RET_OK);
    EXPECT_TRUE(TestRemove(123, "/data/mntTestDenyDelete/test.mp4") == RET_OK);

    EXPECT_FALSE(TestRemoveDir(123, "/data/mntTestDenyDelete/.Trash/") == RET_OK);

    EXPECT_TRUE(ExcuteCmd("umount /data/mntTestDenyDelete -l"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/testDenyDelete/ ] && rm -rf  "));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/mntTestDenyDelete ] && rm -rf /data/mntTestDenyDelete"));
}

HWTEST_F(DecTestCase, testDenyRename, TestSize.Level0)
{
    EXPECT_TRUE(ExcuteCmd("if [ -d /data/testDenyRename ]; then rm -rf /data/testDenyRename; fi"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/testDenyRename/.Recent/"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/testDenyRename/dir1/"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/testDenyRename/.Recent/dir1"));

    EXPECT_TRUE(ExcuteCmd("touch /data/testDenyRename/.Recent/test.mp4"));

    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/mntTestDenyRename"));

    EXPECT_TRUE(ExcuteCmd("mount -t sharefs /data/testDenyRename /data/mntTestDenyRename -o \
        override_support_delete -o user_id=100"));

    EXPECT_TRUE(ConstraintPath("/data/mntTestDenyRename/") == RET_OK);
    EXPECT_TRUE(SetPath(123, "/data/mntTestDenyRename/", DEC_MODE_RW, true, 0, USER_ID) == RET_OK);
    EXPECT_TRUE(DenyPath(0, "/data/mntTestDenyRename/.Recent", DEC_DENY_RENAME, 0, USER_ID) == RET_OK);

    EXPECT_FALSE(TestRename(123, "/data/mntTestDenyRename/.Recent") == RET_OK);
    EXPECT_TRUE(TestRename(123, "/data/mntTestDenyRename/.Recent/dir1") == RET_OK);
    EXPECT_TRUE(TestRename(123, "/data/mntTestDenyRename/dir1") == RET_OK);

    
    EXPECT_TRUE(ExcuteCmd("umount /data/mntTestDenyRename -l"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/testDenyRename/ ] && rm -rf testDenyRename"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/mntTestDenyRename ] && rm -rf /data/mntTestDenyRename"));
}

HWTEST_F(DecTestCase, testSingleCreate, TestSize.Level0)
{
    EXPECT_TRUE(ExcuteCmd("if [ -d /data/testSingleCreate ]; then rm -rf /data/testSingleCreate; fi"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/testSingleCreate/"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/mntTestSingleCreate/"));

    EXPECT_TRUE(ExcuteCmd("mount -t sharefs /data/testSingleCreate /data/mntTestSingleCreate -o \
        override_support_delete -o user_id=100"));

    EXPECT_TRUE(ConstraintPath("/data/mntTestSingleCreate/") == RET_OK);

    EXPECT_TRUE(SetPath(123, "/data/mntTestSingleCreate/newtest.txt", DEC_MODE_RW, true, 0, USER_ID) == RET_OK);
    EXPECT_TRUE(SetPath(123, "/data/mntTestSingleCreate/newtest.txt", DEC_CREATE_MODE, true, 0, USER_ID) == RET_OK);

    EXPECT_TRUE(TestWrite(123, "/data/mntTestSingleCreate/newtest.txt") == RET_OK);

    EXPECT_TRUE(DestroyByTokenid(123) == RET_OK);

    EXPECT_TRUE(ExcuteCmd("umount /data/mntTestSingleCreate -l"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/testSingleCreate/ ] && rm -rf testSingleCreate"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/mntTestSingleCreate ] && rm -rf /data/mntTestSingleCreate"));
}

HWTEST_F(DecTestCase, testSingleCreateDir, TestSize.Level0)
{
    EXPECT_TRUE(ExcuteCmd("if [ -d /data/testSingleCreateDir ]; then rm -rf /data/testSingleCreateDir; fi"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/testSingleCreateDir/"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/mntTestSingleCreateDir/"));

    EXPECT_TRUE(ExcuteCmd("mount -t sharefs /data/testSingleCreateDir /data/mntTestSingleCreateDir -o \
        override_support_delete -o user_id=100"));

    EXPECT_TRUE(ConstraintPath("/data/mntTestSingleCreateDir/") == RET_OK);
    EXPECT_TRUE(SetPath(123, "/data/mntTestSingleCreateDir/newdir", DEC_CREATE_MODE, true, 0, USER_ID) == RET_OK);
    EXPECT_TRUE(Mkdir(123, "/data/mntTestSingleCreateDir/newdir") == RET_OK);
    EXPECT_FALSE(Mkdir(123, "/data/mntTestSingleCreateDir/newdir2") == RET_OK);

    EXPECT_TRUE(ExcuteCmd("umount /data/mntTestSingleCreateDir -l"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/testSingleCreateDir/ ] && rm -rf testSingleCreateDir"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/mntTestSingleCreateDir ] && rm -rf /data/mntTestSingleCreateDir"));
}

HWTEST_F(DecTestCase, testSingleDelete, TestSize.Level0)
{
    EXPECT_TRUE(ExcuteCmd("if [ -d /data/testSingleDelete ]; then rm -rf /data/testSingleDelete; fi"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/testSingleDelete/"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/mntTestSingleDelete/"));

    EXPECT_TRUE(ExcuteCmd("touch /data/testSingleDelete/test.txt"));
    EXPECT_TRUE(ExcuteCmd("touch /data/testSingleDelete/test2.txt"));

    EXPECT_TRUE(ExcuteCmd("mount -t sharefs /data/testSingleDelete /data/mntTestSingleDelete -o \
        override_support_delete -o user_id=100"));


    EXPECT_TRUE(ConstraintPath("/data/mntTestSingleDelete/") == RET_OK);
    EXPECT_TRUE(SetPath(123, "/data/mntTestSingleDelete/test.txt", DEC_DELETE_MODE, true, 0, USER_ID) == RET_OK);

    EXPECT_TRUE(TestRemove(123, "/data/mntTestSingleDelete/test.txt") == RET_OK);
    EXPECT_FALSE(TestRemove(123, "/data/mntTestSingleDelete/test2.txt") == RET_OK);
    EXPECT_TRUE(DestroyByTokenid(123) == RET_OK);

    EXPECT_TRUE(ExcuteCmd("umount /data/mntTestSingleDelete -l"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/testSingleDelete/ ] && rm -rf testSingleDelete"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/mntTestSingleDelete ] && rm -rf /data/mntTestSingleDelete"));
}

HWTEST_F(DecTestCase, testSingleDeleteDir, TestSize.Level0)
{
    EXPECT_TRUE(ExcuteCmd("if [ -d /data/testSingleDeleteDir ]; then rm -rf /data/testSingleDeleteDir; fi"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/testSingleDeleteDir/"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/testSingleDeleteDir/testDir1"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/testSingleDeleteDir/testDir2"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/mntTestSingleDeleteDir/"));

    EXPECT_TRUE(ExcuteCmd("mount -t sharefs /data/testSingleDeleteDir /data/mntTestSingleDeleteDir -o \
        override_support_delete -o user_id=100"));

    EXPECT_TRUE(ConstraintPath("/data/mntTestSingleDeleteDir/") == RET_OK);
    EXPECT_TRUE(SetPath(123, "/data/mntTestSingleDeleteDir/testDir1", DEC_DELETE_MODE, true, 0, USER_ID) == RET_OK);

    EXPECT_TRUE(TestRemoveDir(123, "/data/mntTestSingleDeleteDir/testDir1/") == RET_OK);
    EXPECT_FALSE(TestRemoveDir(123, "/data/mntTestSingleDeleteDir/testDir2/") == RET_OK);

    EXPECT_TRUE(DestroyByTokenid(123) == RET_OK);

    EXPECT_TRUE(ExcuteCmd("umount /data/mntTestSingleDeleteDir -l"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/testSingleDeleteDir/ ] && rm -rf testSingleDeleteDir"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/mntTestSingleDeleteDir ] && rm -rf /data/mntTestSingleDeleteDir"));
}

HWTEST_F(DecTestCase, testSingleRename, TestSize.Level0)
{
    EXPECT_TRUE(ExcuteCmd("if [ -d /data/testSingleRename ]; then rm -rf /data/testSingleRename; fi"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/testSingleRename/dir1"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/testSingleRename/dir2"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/mntTestSingleRename/"));

    EXPECT_TRUE(ExcuteCmd("touch /data/testSingleRename/dir1/A.txt"));
    EXPECT_TRUE(ExcuteCmd("touch /data/testSingleRename/dir1/B.txt"));
    EXPECT_TRUE(ExcuteCmd("touch /data/testSingleRename/dir1/C.txt"));

    EXPECT_TRUE(ExcuteCmd("mount -t sharefs /data/testSingleRename /data/mntTestSingleRename -o \
        override_support_delete -o user_id=100"));

    EXPECT_TRUE(ConstraintPath("/data/mntTestSingleRename/") == RET_OK);
    EXPECT_FALSE(TestRename2(123, "/data/mntTestSingleRename/dir1/A.txt",
        "/data/mntTestSingleRename/dir2/A1.txt") == RET_OK);
    EXPECT_FALSE(TestRename2(123, "/data/mntTestSingleRename/dir2/A1.txt",
        "/data/mntTestSingleRename/dir1/A.txt") == RET_OK);
    EXPECT_FALSE(TestRename2(123, "/data/mntTestSingleRename/dir1/A.txt",
        "/data/mntTestSingleRename/dir2/A2.txt") == RET_OK);

    EXPECT_TRUE(SetPath(123, "/data/mntTestSingleRename/dir1/B.txt", DEC_RENAME_MODE, true, 0, USER_ID) == RET_OK);

    EXPECT_FALSE(TestRename2(123, "/data/mntTestSingleRename/dir2/A1.txt",
        "/data/mntTestSingleRename/dir1/A.txt") == RET_OK);
    EXPECT_FALSE(TestRename2(123, "/data/mntTestSingleRename/dir1/B1.txt",
        "/data/mntTestSingleRename/dir1/B.txt") == RET_OK);

    EXPECT_TRUE(DestroyByTokenid(123) == RET_OK);


    EXPECT_TRUE(ExcuteCmd("umount /data/mntTestSingleRename -l"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/testSingleRename/ ] && rm -rf testSingleRename"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/mntTestSingleRename ] && rm -rf /data/mntTestSingleRename"));
}

HWTEST_F(DecTestCase, testSingleRenameDir, TestSize.Level0)
{
    EXPECT_TRUE(ExcuteCmd("if [ -d /data/testSingleRenameDir ]; then rm -rf /data/testSingleRenameDir; fi"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/testSingleRenameDir/dir1"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/testSingleRenameDir/dir2"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/mntTestSingleRenameDir/"));

    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/testSingleRenameDir/dir1/A"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/testSingleRenameDir/dir1/B"));
    EXPECT_TRUE(ExcuteCmd("mkdir -p /data/testSingleRenameDir/dir1/C"));

    EXPECT_TRUE(ExcuteCmd("mount -t sharefs /data/testSingleRenameDir /data/mntTestSingleRenameDir -o \
        override_support_delete -o user_id=100"));

    EXPECT_TRUE(ConstraintPath("/data/mntTestSingleRenameDir/") == RET_OK);
    EXPECT_FALSE(TestRename2(123, "/data/mntTestSingleRenameDir/dir1/A",
        "/data/mntTestSingleRenameDir/dir2/A1") == RET_OK);
    EXPECT_FALSE(TestRename2(123, "/data/mntTestSingleRenameDir/dir1/B",
        "/data/mntTestSingleRenameDir/dir1/B1") == RET_OK);

    EXPECT_TRUE(SetPath(123, "/data/mntTestSingleRenameDir/dir1/A", DEC_RENAME_MODE, true, 0, USER_ID) == RET_OK);

    EXPECT_TRUE(SetPath(123, "/data/mntTestSingleRenameDir/dir2/A1", DEC_RENAME_MODE, true, 0, USER_ID) == RET_OK);

    EXPECT_TRUE(TestRename2(123, "/data/mntTestSingleRenameDir/dir1/A",
        "/data/mntTestSingleRenameDir/dir2/A1") == RET_OK);
    EXPECT_TRUE(TestRename2(123, "/data/mntTestSingleRenameDir/dir2/A1",
        "/data/mntTestSingleRenameDir/dir1/A") == RET_OK);
    EXPECT_FALSE(TestRename2(123, "/data/mntTestSingleRenameDir/dir1/A",
        "/data/mntTestSingleRenameDir/dir2/A2") == RET_OK);

    EXPECT_TRUE(SetPath(123, "/data/mntTestSingleRenameDir/dir1/B", DEC_RENAME_MODE, true, 0, USER_ID) == RET_OK);
    EXPECT_TRUE(TestRename2(123, "/data/mntTestSingleRenameDir/dir1/B",
        "/data/mntTestSingleRenameDir/dir1/B1") == RET_OK);
    EXPECT_TRUE(TestRename2(123, "/data/mntTestSingleRenameDir/dir1/B1",
        "/data/mntTestSingleRenameDir/dir1/B") == RET_OK);
    EXPECT_TRUE(DestroyByTokenid(123) == RET_OK);

    EXPECT_TRUE(ExcuteCmd("umount /data/mntTestSingleRenameDir -l"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/testSingleRenameDir/ ] && rm -rf testSingleRenameDir"));
    EXPECT_TRUE(ExcuteCmd("[ -d /data/mntTestSingleRenameDir ] && rm -rf /data/mntTestSingleRenameDir"));
}
} // SandboxManager
} // AccessControl
} // OHOS
#endif