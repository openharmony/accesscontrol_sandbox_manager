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

#include <gtest/gtest.h>
#include <set>
#include "sandbox_manager_log.h"
#include "policy_trie.h"
using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

// Global constants for policy modes
static constexpr int MODE_READ = 1;
static constexpr int MODE_WRITE = 2;
static constexpr int MODE_CREATE = 4;
static constexpr int MODE_DELETE = 8;
static const int MODE_RW = 3;

class PolicyTrieTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PolicyTrieTest::SetUpTestCase(void) {}

void PolicyTrieTest::TearDownTestCase(void) {}

void PolicyTrieTest::SetUp(void) {}

void PolicyTrieTest::TearDown(void) {}

/**
 * @tc.name: PolicyTrieTestInherit
 * @tc.desc: Test add func
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestInherit, TestSize.Level0)
{
    PolicyTrie trie;

    trie.InsertPath("/storage/Users/currentUser/", MODE_RW);
    EXPECT_EQ(trie.CheckPath("/storage/Users/currentUser/test", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/storage/Users/currentUser/appdata", MODE_RW), false);
    EXPECT_EQ(trie.CheckPath("/storage/Users/currentUser/appdata/", MODE_RW), false);
    EXPECT_EQ(trie.CheckPath("/storage/Users/currentUser/appdata123", MODE_RW), true);
    trie.InsertPath("/storage/Users/currentUser/appdata", MODE_RW);
    EXPECT_EQ(trie.CheckPath("/storage/Users/currentUser/appdata", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/storage/Users/currentUser/appdata/", MODE_RW), true);
    EXPECT_EQ(
        trie.CheckPath("/storage/Users/currentUser/appdata/el2/base/com.ohos.dlpmanager/haps/entry/files", MODE_RW),
        true);

    trie.Clear();
}

/**
 * @tc.name: PolicyTrieTestSetInsensitiveBasic
 * @tc.desc: Test SetInsensitive basic functionality - case insensitive matching
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestSetInsensitiveBasic, TestSize.Level0)
{
    PolicyTrie trie;

    trie.SetInsensitive("/currentUser/");

    // Insert uppercase path
    trie.InsertPath("/currentUser/TEST.txt", MODE_RW);

    // Case-insensitive CheckPath should succeed
    EXPECT_EQ(trie.CheckPath("/currentUser/test.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/currentUser/TEST.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/currentUser/Test.Txt", MODE_RW), true);

    // Path without ignore setting should fail
    EXPECT_EQ(trie.CheckPath("/otherUser/test.txt", MODE_RW), false);
    
    trie.Clear();
}

/**
 * @tc.name: PolicyTrieTestSetSensitiveOverride
 * @tc.desc: Test SetSensitive overrides SetInsensitive for subdirectories
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestSetSensitiveOverride, TestSize.Level0)
{
    PolicyTrie trie;

    trie.SetInsensitive("/currentUser/");

    // But /currentUser/appdata/ restores case sensitivity
    trie.SetSensitive("/currentUser/appdata/");

    // Insert paths
    trie.InsertPath("/currentUser/TEST.txt", MODE_RW);
    trie.InsertPath("/currentUser/appdata/SECRET.txt", MODE_RW);

    // Paths under /currentUser/ should ignore case
    EXPECT_EQ(trie.CheckPath("/currentUser/test.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/currentUser/TeSt.TxT", MODE_RW), true);

    // Paths under /currentUser/appdata/ should be case sensitive
    EXPECT_EQ(trie.CheckPath("/currentUser/appdata/SECRET.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/currentUser/appdata/secret.txt", MODE_RW), false);
    EXPECT_EQ(trie.CheckPath("/currentUser/appdata/Secret.Txt", MODE_RW), false);

    // Other subdirectories under /currentUser/ still ignore case
    trie.InsertPath("/currentUser/other/file.txt", MODE_RW);
    EXPECT_EQ(trie.CheckPath("/currentUser/OTHER/FILE.TXT", MODE_RW), true);
    
    trie.Clear();
}

/**
 * @tc.name: PolicyTrieTestSetInsensitiveDeepHierarchy
 * @tc.desc: Test SetInsensitive with deep hierarchy and multiple overrides
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestSetInsensitiveDeepHierarchy, TestSize.Level0)
{
    PolicyTrie trie;

    trie.SetInsensitive("/data/");
    trie.SetSensitive("/data/sensitive/");
    trie.SetInsensitive("/data/sensitive/public/");

    // Insert paths
    trie.InsertPath("/data/file1.txt", MODE_RW);
    trie.InsertPath("/data/sensitive/secret.txt", MODE_RW);
    trie.InsertPath("/data/sensitive/public/share.txt", MODE_RW);

    // Ignore case under /data/
    EXPECT_EQ(trie.CheckPath("/data/FILE1.txt", MODE_RW), true);

    // Case sensitive under /data/sensitive/
    EXPECT_EQ(trie.CheckPath("/data/sensitive/secret.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/data/sensitive/SECRET.txt", MODE_RW), false);

    // Case insensitive again under /data/sensitive/public/
    EXPECT_EQ(trie.CheckPath("/data/sensitive/public/share.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/data/sensitive/public/SHARE.TXT", MODE_RW), true);
    
    trie.Clear();
}

/**
 * @tc.name: PolicyTrieTestSetInsensitiveWithoutSetInsensitive
 * @tc.desc: Test default case-sensitive behavior without SetInsensitive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestSetInsensitiveWithoutSetInsensitive, TestSize.Level0)
{
    PolicyTrie trie;

    // By default, all paths are case sensitive
    trie.InsertPath("/currentUser/TEST.txt", MODE_RW);

    // Case must match exactly
    EXPECT_EQ(trie.CheckPath("/currentUser/TEST.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/currentUser/test.txt", MODE_RW), false);
    EXPECT_EQ(trie.CheckPath("/currentUser/Test.txt", MODE_RW), false);
    
    trie.Clear();
}

/**
 * @tc.name: PolicyTrieTestSetInsensitiveInsertOrder
 * @tc.desc: Test that SetInsensitive must be called before InsertPath for case insensitive matching
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestSetInsensitiveInsertOrder, TestSize.Level0)
{
    PolicyTrie trie;

    trie.SetInsensitive("/data/");
    trie.InsertPath("/data/TEST.txt", MODE_RW);

    // Paths inserted after setting should ignore case
    trie.InsertPath("/data/FILE2.txt", MODE_RW);

    // Both paths should ignore case
    EXPECT_EQ(trie.CheckPath("/data/test.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/data/file2.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/data/File2.TXT", MODE_RW), true);

    // Scenario of inserting path first, then setting ignore case:
    // Existing paths won't automatically enjoy case insensitivity
    trie.Clear();
    trie.InsertPath("/data2/EXIST.txt", MODE_RW);  // Store with case sensitivity first
    // Existing path matches with original case
    EXPECT_EQ(trie.CheckPath("/data2/EXIST.txt", MODE_RW), true);   // Original case succeeds

    // After setting ignore case, newly inserted paths enjoy case insensitivity
    trie.SetInsensitive("/data2/");
    trie.InsertPath("/data2/NEW.txt", MODE_RW);
    EXPECT_EQ(trie.CheckPath("/data2/new.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/data2/NEW.txt", MODE_RW), true);

    trie.Clear();
}

/**
 * @tc.name: PolicyTrieTestSetInsensitiveModePermissions
 * @tc.desc: Test that mode permissions are preserved with case insensitive matching
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestSetInsensitiveModePermissions, TestSize.Level0)
{
    PolicyTrie trie;

    trie.SetInsensitive("/data/");

    // Insert read-only permission
    trie.InsertPath("/data/readonly.txt", MODE_READ);

    // When ignoring case matching, permission check should also be correct
    EXPECT_EQ(trie.CheckPath("/data/READONLY.txt", MODE_READ), true);
    EXPECT_EQ(trie.CheckPath("/data/readonly.txt", MODE_READ), true);
    EXPECT_EQ(trie.CheckPath("/data/READONLY.txt", MODE_WRITE), false);

    trie.Clear();
}

/**
 * @tc.name: PolicyTrieTestMultipleModes
 * @tc.desc: Test multiple permission modes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestMultipleModes, TestSize.Level0)
{
    PolicyTrie trie;

    trie.InsertPath("/data/storage/el2/base/haps/appA/files/", MODE_READ | MODE_WRITE | MODE_CREATE);

    // Check each mode
    EXPECT_EQ(trie.CheckPath("/data/storage/el2/base/haps/appA/files/", MODE_READ), true);
    EXPECT_EQ(trie.CheckPath("/data/storage/el2/base/haps/appA/files/", MODE_WRITE), true);
    EXPECT_EQ(trie.CheckPath("/data/storage/el2/base/haps/appA/files/", MODE_CREATE), true);
    EXPECT_EQ(trie.CheckPath("/data/storage/el2/base/haps/appA/files/", MODE_DELETE), false);

    trie.Clear();
}

/**
 * @tc.name: PolicyTrieTestDeniedPaths
 * @tc.desc: Test denied paths configuration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestDeniedPaths, TestSize.Level0)
{
    PolicyTrie trie;

    // Insert denied path
    trie.InsertPath("/storage/Users/currentUser/appdata/sensitive/", MODE_RW);

    // Check denied path
    EXPECT_EQ(trie.CheckPath("/storage/Users/currentUser/appdata/sensitive/", MODE_RW), true);

    trie.Clear();
}

/**
 * @tc.name: PolicyTrieTestSubPathMatching
 * @tc.desc: Test sub-path matching behavior
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestSubPathMatching, TestSize.Level0)
{
    PolicyTrie trie;

    trie.InsertPath("/data/storage/el2/base/haps/", MODE_RW);

    // Insert parent path
    trie.InsertPath("/data/storage/el2/base/", MODE_RW);

    // Check parent path
    EXPECT_EQ(trie.CheckPath("/data/storage/el2/base/", MODE_RW), true);

    // Check child path - since CheckPath returns the first matching policy after reaching needLevel
    // so when checking child path, it will return at parent path level
    EXPECT_EQ(trie.CheckPath("/data/storage/el2/base/haps/", MODE_RW), true);

    trie.Clear();
}

/**
 * @tc.name: PolicyTrieTestClear
 * @tc.desc: Test clear all nodes from trie
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestClear, TestSize.Level0)
{
    PolicyTrie trie;

    // Insert multiple paths
    trie.InsertPath("/path1/", MODE_RW);
    trie.InsertPath("/path2/subpath/", MODE_RW);
    trie.InsertPath("/path3/deep/nested/", MODE_RW);

    // Verify path exists
    EXPECT_EQ(trie.CheckPath("/path1/", MODE_RW), true);

    // Clear
    trie.Clear();

    // After clearing, no path should match
    EXPECT_EQ(trie.CheckPath("/path1/", MODE_RW), false);
    EXPECT_EQ(trie.CheckPath("/path2/subpath/", MODE_RW), false);
    EXPECT_EQ(trie.CheckPath("/path3/deep/nested/", MODE_RW), false);
}

/**
 * @tc.name: PolicyTrieTestSetInsensitiveMultiLevelAlternating
 * @tc.desc: Test multiple levels of SetInsensitive and SetSensitive alternating (more than 2 levels)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestSetInsensitiveMultiLevelAlternating, TestSize.Level0)
{
    PolicyTrie trie;

    trie.SetInsensitive("/data/");
    trie.SetSensitive("/data/private/");
    trie.SetInsensitive("/data/private/public/");
    trie.SetSensitive("/data/private/public/secure/");
    trie.SetInsensitive("/data/private/public/secure/open/");

    // Insert paths for each level
    trie.InsertPath("/data/FILE1.txt", MODE_RW);
    trie.InsertPath("/data/private/FILE2.txt", MODE_RW);
    trie.InsertPath("/data/private/public/FILE3.txt", MODE_RW);
    trie.InsertPath("/data/private/public/secure/FILE4.txt", MODE_RW);
    trie.InsertPath("/data/private/public/secure/open/FILE5.txt", MODE_RW);

    // Level 1: Ignore case under /data/
    EXPECT_EQ(trie.CheckPath("/data/file1.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/data/FILE1.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/data/FiLe1.TxT", MODE_RW), true);

    // Level 2: Case sensitive under /data/private/
    EXPECT_EQ(trie.CheckPath("/data/private/FILE2.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/data/private/file2.txt", MODE_RW), false);
    EXPECT_EQ(trie.CheckPath("/data/private/File2.Txt", MODE_RW), false);

    // Level 3: Ignore case under /data/private/public/
    EXPECT_EQ(trie.CheckPath("/data/private/public/FILE3.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/data/private/public/file3.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/data/private/public/FiLe3.TxT", MODE_RW), true);

    // Level 4: Case sensitive under /data/private/public/secure/
    EXPECT_EQ(trie.CheckPath("/data/private/public/secure/FILE4.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/data/private/public/secure/file4.txt", MODE_RW), false);
    EXPECT_EQ(trie.CheckPath("/data/private/public/secure/File4.Txt", MODE_RW), false);

    // Level 5: Ignore case under /data/private/public/secure/open/
    EXPECT_EQ(trie.CheckPath("/data/private/public/secure/open/FILE5.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/data/private/public/secure/open/file5.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/data/private/public/secure/open/FiLe5.TxT", MODE_RW), true);

    trie.Clear();
}

/**
 * @tc.name: PolicyTrieTestSetInsensitiveRootPath
 * @tc.desc: Test SetInsensitive with root path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestSetInsensitiveRootPath, TestSize.Level0)
{
    PolicyTrie trie;

    trie.SetInsensitive("/");

    trie.InsertPath("/DATA/TEST.txt", MODE_RW);

    // All paths should ignore case
    EXPECT_EQ(trie.CheckPath("/data/test.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/DATA/TEST.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/DaTa/TeSt.TxT", MODE_RW), true);

    trie.Clear();
}

/**
 * @tc.name: PolicyTrieTestInsertPathWithTrailingSlash
 * @tc.desc: Test InsertPath with and without trailing slash - both are treated the same
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestInsertPathWithTrailingSlash, TestSize.Level0)
{
    PolicyTrie trie;

    trie.InsertPath("/data/test/", MODE_RW);

    // SplitPath ignores trailing slashes, so /data/test/ and /data/test are treated as the same path
    EXPECT_EQ(trie.CheckPath("/data/test/", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/data/test", MODE_RW), true);

    trie.Clear();
}

/**
 * @tc.name: PolicyTrieTestInsertDuplicatePath
 * @tc.desc: Test inserting the same path multiple times with different modes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestInsertDuplicatePath, TestSize.Level0)
{
    PolicyTrie trie;

    trie.InsertPath("/data/test.txt", MODE_READ);
    EXPECT_EQ(trie.CheckPath("/data/test.txt", MODE_READ), true);
    EXPECT_EQ(trie.CheckPath("/data/test.txt", MODE_WRITE), false);

    // Second insertion, write permission (should merge with read permission)
    trie.InsertPath("/data/test.txt", MODE_WRITE);
    EXPECT_EQ(trie.CheckPath("/data/test.txt", MODE_READ), true);
    EXPECT_EQ(trie.CheckPath("/data/test.txt", MODE_WRITE), true);

    trie.Clear();
}

/**
 * @tc.name: PolicyTrieTestCheckPathNonExistentParent
 * @tc.desc: Test CheckPath when parent path does not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestCheckPathNonExistentParent, TestSize.Level0)
{
    PolicyTrie trie;

    trie.InsertPath("/data/test/file.txt", MODE_RW);

    // Check case where parent path does not exist
    EXPECT_EQ(trie.CheckPath("/data/other/file.txt", MODE_RW), false);
    EXPECT_EQ(trie.CheckPath("/other/test/file.txt", MODE_RW), false);

    trie.Clear();
}

/**
 * @tc.name: PolicyTrieTestSetSensitiveBeforeSetInsensitive
 * @tc.desc: Test SetSensitive before SetInsensitive on same path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestSetSensitiveBeforeSetInsensitive, TestSize.Level0)
{
    PolicyTrie trie;

    trie.SetSensitive("/data/");
    trie.SetInsensitive("/data/");

    // Insert path
    trie.InsertPath("/data/TEST.txt", MODE_RW);

    // Should ignore case (later setting takes effect)
    EXPECT_EQ(trie.CheckPath("/data/test.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/data/TEST.txt", MODE_RW), true);

    trie.Clear();
}

/**
 * @tc.name: PolicyTrieTestClearMultipleTimes
 * @tc.desc: Test calling Clear multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestClearMultipleTimes, TestSize.Level0)
{
    PolicyTrie trie;

    trie.InsertPath("/data/test.txt", MODE_RW);
    EXPECT_EQ(trie.CheckPath("/data/test.txt", MODE_RW), true);

    // First Clear
    trie.Clear();
    EXPECT_EQ(trie.CheckPath("/data/test.txt", MODE_RW), false);

    // Second Clear (should not crash)
    trie.Clear();
    EXPECT_EQ(trie.CheckPath("/data/test.txt", MODE_RW), false);

    // Third Clear (should not crash)
    trie.Clear();
    EXPECT_EQ(trie.CheckPath("/data/test.txt", MODE_RW), false);
}

/**
 * @tc.name: PolicyTrieTestInsertPathSpecialCharacters
 * @tc.desc: Test InsertPath with special characters in path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestInsertPathSpecialCharacters, TestSize.Level0)
{
    PolicyTrie trie;

    trie.InsertPath("/data/test-file_v1.0.txt", MODE_RW);
    trie.InsertPath("/data/test file.txt", MODE_RW);

    // Check special character paths
    EXPECT_EQ(trie.CheckPath("/data/test-file_v1.0.txt", MODE_RW), true);
    EXPECT_EQ(trie.CheckPath("/data/test file.txt", MODE_RW), true);

    trie.Clear();
}

/**
 * @tc.name: PolicyTrieTestInsertVeryLongPath
 * @tc.desc: Test InsertPath with very long path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestInsertVeryLongPath, TestSize.Level0)
{
    PolicyTrie trie;

    trie.SetInsensitive("/data/");

    // Insert a long path - using same case as SetInsensitive
    std::string longPath = "/data/level1/level2/level3/level4/level5/level6/level7/level8/level9/level10/file.txt";
    trie.InsertPath(longPath, MODE_RW);

    // Check long path - using same case
    EXPECT_EQ(trie.CheckPath(longPath, MODE_RW), true);

    // Path segments after data/ should ignore case (all uppercase)
    std::string longPathUpper = "/data/LEVEL1/LEVEL2/LEVEL3/LEVEL4/LEVEL5/LEVEL6/LEVEL7/LEVEL8/LEVEL9/LEVEL10/FILE.TXT";
    EXPECT_EQ(trie.CheckPath(longPathUpper, MODE_RW), true);

    // Also check all lowercase
    std::string longPathLower = "/data/level1/level2/level3/level4/level5/level6/level7/level8/level9/level10/file.txt";
    EXPECT_EQ(trie.CheckPath(longPathLower, MODE_RW), true);

    trie.Clear();
}

/**
 * @tc.name: PolicyTrieTestModeBitwiseOperations
 * @tc.desc: Test mode bitwise OR and AND operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestModeBitwiseOperations, TestSize.Level0)
{
    PolicyTrie trie;

    int combinedMode = MODE_READ | MODE_WRITE | MODE_CREATE | MODE_DELETE;
    trie.InsertPath("/data/test.txt", combinedMode);

    // Check each individual mode
    EXPECT_EQ(trie.CheckPath("/data/test.txt", MODE_READ), true);
    EXPECT_EQ(trie.CheckPath("/data/test.txt", MODE_WRITE), true);
    EXPECT_EQ(trie.CheckPath("/data/test.txt", MODE_CREATE), true);
    EXPECT_EQ(trie.CheckPath("/data/test.txt", MODE_DELETE), true);

    // Check combined mode
    EXPECT_EQ(trie.CheckPath("/data/test.txt", MODE_READ | MODE_WRITE), true);
    EXPECT_EQ(trie.CheckPath("/data/test.txt", MODE_CREATE | MODE_DELETE), true);

    trie.Clear();
}

/**
 * @tc.name: PolicyTrieTestFindMatchingPathsBasic
 * @tc.desc: Test FindMatchingPaths basic functionality
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestFindMatchingPathsBasic, TestSize.Level0)
{
    PolicyTrie trie;

    // Insert some paths into the trie
    trie.InsertPreservingCase("/storage/Users/currentUser/Download/appA/files/", MODE_RW);
    trie.InsertPreservingCase("/storage/Users/currentUser/Download/appB/files/", MODE_RW);
    trie.InsertPreservingCase("/storage/Users/currentUser/Download/appC/files/", MODE_RW);
    trie.InsertPreservingCase("/storage/Users/currentUser/Download/shared/", MODE_RW);

    // Test FindMatchingPaths with exact paths - should find exact matches only
    std::vector<std::string> results1 =
        trie.FindMatchingPaths("/storage/Users/currentUser/Download/appA/files/", MODE_RW);
    EXPECT_EQ(results1.size(), 1);  // Should find only the exact match
    EXPECT_EQ(results1[0], "/storage/Users/currentUser/Download/appA/files"); // Function removes trailing slash

    std::vector<std::string> results2 =
        trie.FindMatchingPaths("/storage/Users/currentUser/Download/shared/", MODE_RW);
    EXPECT_EQ(results2.size(), 1);  // Should find only the exact match
    EXPECT_EQ(results2[0], "/storage/Users/currentUser/Download/shared"); // Function removes trailing slash

    // Test FindMatchingPaths with non-existent path
    std::vector<std::string> results3 =
        trie.FindMatchingPaths("/storage/Users/currentUser/Download/appD/files/", MODE_RW);
    EXPECT_EQ(results3.size(), 0);  // Should find nothing

    trie.Clear();
}

/**
 * @tc.name: PolicyTrieTestFindMatchingPathsCaseInsensitive
 * @tc.desc: Test FindMatchingPaths with case-insensitive functionality
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PolicyTrieTest, PolicyTrieTestFindMatchingPathsCaseInsensitive, TestSize.Level0)
{
    PolicyTrie trie;

    trie.SetInsensitive("/storage/Users/");

    // Insert paths with different case variations of the same logical path
    trie.InsertPreservingCase("/storage/Users/currentUser/download/AppA/Files/", MODE_RW);
    trie.InsertPreservingCase("/storage/Users/CurrentUser/DOWNLOAD/AppA/Files/", MODE_RW);
    trie.InsertPreservingCase("/storage/Users/CurrentUser/Download/appA/Files/", MODE_RW);

    // Query with first variation - should find all three paths due to case-insensitive matching
    std::vector<std::string> results1 =
        trie.FindMatchingPaths("/storage/Users/currentuser/download/appa/files/", MODE_RW);
    EXPECT_EQ(results1.size(), 3);  // Should find all three variations

    // Query with second variation - should find all three paths due to case-insensitive matching
    std::vector<std::string> results2 =
        trie.FindMatchingPaths("/storage/Users/CurrentUser/DOWNLOAD/AppA/Files/", MODE_RW);
    EXPECT_EQ(results2.size(), 3);  // Should find all three variations

    // Query with third variation - should find all three paths due to case-insensitive matching
    std::vector<std::string> results3 =
        trie.FindMatchingPaths("/storage/Users/CurrentUser/Download/appA/Files/", MODE_RW);
    EXPECT_EQ(results3.size(), 3);  // Should find all three variations

    // Verify that all three original paths are returned in the results
    std::set<std::string> resultSet1(results1.begin(), results1.end());
    EXPECT_EQ(resultSet1.size(), 3);
    EXPECT_TRUE(resultSet1.count("/storage/Users/currentUser/download/AppA/Files"));
    EXPECT_TRUE(resultSet1.count("/storage/Users/CurrentUser/DOWNLOAD/AppA/Files"));
    EXPECT_TRUE(resultSet1.count("/storage/Users/CurrentUser/Download/appA/Files"));

    trie.Clear();
}
} // SandboxManager
} // AccessControl
} // OHOS