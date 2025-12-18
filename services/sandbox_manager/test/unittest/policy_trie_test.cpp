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
#include "sandbox_manager_log.h"
#include "policy_trie.h"
using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class PolicyTrieTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

static const int MODE_RW = 3;

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
} // SandboxManager
} // AccessControl
} // OHOS