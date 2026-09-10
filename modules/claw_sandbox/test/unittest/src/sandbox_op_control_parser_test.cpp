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

#include "sandbox_op_control_parser_test.h"
#include "sandbox_cmd_parser.h"
#include "sandbox_error.h"
#include <cstdint>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <vector>

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

void ClawSandboxOpControlParserTest::SetUpTestCase() {}
void ClawSandboxOpControlParserTest::TearDownTestCase() {}
void ClawSandboxOpControlParserTest::SetUp() {}
void ClawSandboxOpControlParserTest::TearDown() {}

// ==================== SandboxPolicyTlv / ConvertOperationControlToTlv tests ====================

namespace {

// Read a little-endian uint32 from a byte buffer at the given offset.
static uint32_t ReadTlvU32At(const std::vector<uint8_t> &buf, size_t off)
{
    return static_cast<uint32_t>(buf[off]) |
        (static_cast<uint32_t>(buf[off + 1]) << 8) |
        (static_cast<uint32_t>(buf[off + 2]) << 16) |
        (static_cast<uint32_t>(buf[off + 3]) << 24);
}

// Walk a TLV stream of (type, len, payload) triples, invoking cb(tag, payloadLen)
// for each entry. The stream is self-describing (each entry carries its own
// length), so nested blocks (e.g. the operation_size policy payload) are simply
// walked as part of the flat sequence.
template <typename Fn>
static void WalkTlv(const std::vector<uint8_t> &buf, Fn &&cb)
{
    size_t off = 0;
    while (off + 8 <= buf.size()) {
        uint32_t tag = ReadTlvU32At(buf, off);
        uint32_t len = ReadTlvU32At(buf, off + 4);
        if (off + 8 + len > buf.size()) {
            return;
        }
        cb(tag, len);
        off += 8 + len;
    }
}

// Extract the payload of the first top-level TLV entry with the given tag.
// Only valid for genuine TLV-wrapped payloads (e.g. a u32 value whose payload
// is its 4-byte value); NOT valid for operation_size, whose value is a size and
// whose block follows as raw bytes (see ExtractOperationPolicyBlock).
static bool ExtractTlvPayload(const std::vector<uint8_t> &buf, uint32_t target,
    std::vector<uint8_t> &out)
{
    size_t off = 0;
    while (off + 8 <= buf.size()) {
        uint32_t tag = ReadTlvU32At(buf, off);
        uint32_t len = ReadTlvU32At(buf, off + 4);
        if (off + 8 + len > buf.size()) {
            return false;
        }
        if (tag == target) {
            out.assign(buf.begin() + off + 8, buf.begin() + off + 8 + len);
            return true;
        }
        off += 8 + len;
    }
    return false;
}

// Extract one policy's TLV block from the top-level stream. [3]operation_size is
// a u32 TLV whose VALUE is the byte length of the policy block, and the raw
// policy block bytes follow immediately after the entry (the block is NOT
// TLV-wrapped by the serializer).
static bool ExtractOperationPolicyBlock(const std::vector<uint8_t> &buf,
    std::vector<uint8_t> &out)
{
    size_t off = 0;
    while (off + 8 <= buf.size()) {
        uint32_t tag = ReadTlvU32At(buf, off);
        uint32_t len = ReadTlvU32At(buf, off + 4);
        if (off + 8 + len > buf.size()) {
            return false;
        }
        if (tag == DEC_POLICY_TLV_OPERATION_SIZE) {
            uint32_t blockSize = ReadTlvU32At(buf, off + 8);
            size_t blockStart = off + 8 + len;
            if (blockStart + blockSize > buf.size()) {
                return false;
            }
            out.assign(buf.begin() + blockStart, buf.begin() + blockStart + blockSize);
            return true;
        }
        off += 8 + len;
    }
    return false;
}

// A parsed TLV entry: (tag, payload bytes).
struct ParsedTlvEntry {
    uint32_t tag;
    std::vector<uint8_t> payload;
};

// Parse a TLV stream into its ordered entries (tag, payload). Returns false if
// the stream is truncated or leaves trailing bytes.
static bool ParseTlvEntries(const std::vector<uint8_t> &buf, std::vector<ParsedTlvEntry> &out)
{
    out.clear();
    size_t off = 0;
    while (off + 8 <= buf.size()) {
        uint32_t tag = ReadTlvU32At(buf, off);
        uint32_t len = ReadTlvU32At(buf, off + 4);
        if (off + 8 + len > buf.size()) {
            return false;
        }
        ParsedTlvEntry entry;
        entry.tag = tag;
        entry.payload.assign(buf.begin() + off + 8, buf.begin() + off + 8 + len);
        out.push_back(entry);
        off += 8 + len;
    }
    return off == buf.size();
}

// u32 value of a TLV entry whose payload is exactly 4 bytes.
static uint32_t EntryU32(const ParsedTlvEntry &entry)
{
    return ReadTlvU32At(entry.payload, 0);
}

// Index of the first entry with the given tag (entries.size() when absent).
static size_t FindTlvEntry(const std::vector<ParsedTlvEntry> &entries, uint32_t tag)
{
    for (size_t i = 0; i < entries.size(); ++i) {
        if (entries[i].tag == tag) {
            return i;
        }
    }
    return entries.size();
}

}  // namespace

/**
 * @tc.name: ConvertOperationControlToTlv001
 * @tc.desc: File delete rules are split one rule per path (no aggregation by
 *           action/eventType); each rule carries a single object entity.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, ConvertOperationControlToTlv001, TestSize.Level0)
{
    SandboxPolicyRuleGroup group;
    group.hasFile = true;
    group.fileRules.denyDelete = {"/a", "/b"};
    group.fileRules.allowDelete = {"/c"};
    std::vector<SandboxPolicyRuleGroup> groups = {group};

    SandboxPolicyTlv tlv;
    int ret = CmdParser::ConvertOperationControlToTlv(groups, DEC_POLICY_OP_TYPE_FILE, tlv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(1u, tlv.policies.size());

    const SandboxPolicyTlv::Policy &policy = tlv.policies[0];
    EXPECT_EQ(DEC_POLICY_OP_TYPE_FILE, policy.operationType);
    EXPECT_EQ(DEC_POLICY_ACTION_NONE, policy.defaultAction);  // DefaultAction not configured
    EXPECT_EQ(3u, policy.rules.size());               // one rule per path

    const uint32_t expectedActions[3] = {DEC_POLICY_ACTION_DENY, DEC_POLICY_ACTION_DENY, DEC_POLICY_ACTION_ALLOW};
    const std::string expectedPaths[3] = {"/a", "/b", "/c"};
    for (size_t i = 0; i < policy.rules.size(); ++i) {
        EXPECT_EQ(expectedActions[i], policy.rules[i].action);
        EXPECT_EQ(static_cast<uint32_t>(DEC_POLICY_FILE_EVENT_RMDIR | DEC_POLICY_FILE_EVENT_UNLINK),
            policy.rules[i].eventType);
        EXPECT_TRUE(policy.rules[i].subjectRules.empty());
        ASSERT_EQ(1u, policy.rules[i].objectRules.size());
        ASSERT_EQ(1u, policy.rules[i].objectRules[0].size());
        const SandboxPolicyTlv::FilterRule &objectRule = policy.rules[i].objectRules[0][0];
        EXPECT_EQ(DEC_POLICY_CMP_EQ, objectRule.cmpType);
        EXPECT_EQ(DEC_POLICY_ITEM_TYPE_PATH, objectRule.itemType);
        EXPECT_EQ(expectedPaths[i], objectRule.path);
    }
}

/**
 * @tc.name: ConvertOperationControlToTlv002
 * @tc.desc: File.DefaultAction (optional) is honored when configured
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, ConvertOperationControlToTlv002, TestSize.Level0)
{
    SandboxPolicyRuleGroup group;
    group.hasFile = true;
    group.fileRules.defaultAction = DEC_POLICY_ACTION_DENY;
    group.fileRules.allowDelete = {"/data/x"};
    std::vector<SandboxPolicyRuleGroup> groups = {group};

    SandboxPolicyTlv tlv;
    int ret = CmdParser::ConvertOperationControlToTlv(groups, DEC_POLICY_OP_TYPE_FILE, tlv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(1u, tlv.policies.size());
    EXPECT_EQ(DEC_POLICY_ACTION_DENY, tlv.policies[0].defaultAction);
    EXPECT_EQ(DEC_POLICY_OP_TYPE_FILE, tlv.policies[0].operationType);
}

/**
 * @tc.name: ConvertOperationControlToTlv003
 * @tc.desc: Process exec cmd rules become CMD-item rules; explicit DefaultAction
 *           (ASK) is honored
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, ConvertOperationControlToTlv003, TestSize.Level0)
{
    SandboxPolicyRuleGroup group;
    group.hasProcess = true;
    group.processRules.defaultAction = DEC_POLICY_ACTION_ASK;
    group.processRules.denyExecCmd = {"sh", "ls"};
    group.processRules.allowExecCmd = {"echo"};
    std::vector<SandboxPolicyRuleGroup> groups = {group};

    SandboxPolicyTlv tlv;
    int ret = CmdParser::ConvertOperationControlToTlv(groups, DEC_POLICY_OP_TYPE_PROCESS, tlv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(1u, tlv.policies.size());

    const SandboxPolicyTlv::Policy &policy = tlv.policies[0];
    EXPECT_EQ(DEC_POLICY_OP_TYPE_PROCESS, policy.operationType);
    EXPECT_EQ(DEC_POLICY_ACTION_ASK, policy.defaultAction);
    EXPECT_EQ(3u, policy.rules.size());  // one rule per cmd
    for (const auto &rule : policy.rules) {
        EXPECT_EQ(static_cast<uint32_t>(DEC_POLICY_PROCESS_EVENT_EXEC), rule.eventType);
        ASSERT_EQ(1u, rule.objectRules.size());
        ASSERT_EQ(1u, rule.objectRules[0].size());
        EXPECT_EQ(DEC_POLICY_ITEM_TYPE_CMD, rule.objectRules[0][0].itemType);
    }
    EXPECT_EQ("sh", policy.rules[0].objectRules[0][0].cmd);
    EXPECT_EQ(DEC_POLICY_ACTION_DENY, policy.rules[0].action);
    EXPECT_EQ(DEC_POLICY_ACTION_ALLOW, policy.rules[2].action);
}

/**
 * @tc.name: ConvertOperationControlToTlv004
 * @tc.desc: Network module carries DefaultAction and no per-rule list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, ConvertOperationControlToTlv004, TestSize.Level0)
{
    SandboxPolicyRuleGroup group;
    group.hasNetwork = true;
    group.networkRules.defaultAction = DEC_POLICY_ACTION_DENY;
    std::vector<SandboxPolicyRuleGroup> groups = {group};

    SandboxPolicyTlv tlv;
    int ret = CmdParser::ConvertOperationControlToTlv(groups, DEC_POLICY_OP_TYPE_NETWORK, tlv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(1u, tlv.policies.size());
    EXPECT_EQ(DEC_POLICY_OP_TYPE_NETWORK, tlv.policies[0].operationType);
    EXPECT_EQ(DEC_POLICY_ACTION_DENY, tlv.policies[0].defaultAction);
    EXPECT_TRUE(tlv.policies[0].rules.empty());
}

/**
 * @tc.name: ConvertOperationControlToTlv005
 * @tc.desc: Cross-group overlap is legal under per-group delivery: the same path
 *           denied in one group and allowed in another yields two independent
 *           policies (deny first, allow second), each keeping its own action
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, ConvertOperationControlToTlv005, TestSize.Level0)
{
    SandboxPolicyRuleGroup group1;
    group1.hasFile = true;
    group1.fileRules.denyDelete = {"/x"};
    SandboxPolicyRuleGroup group2;
    group2.hasFile = true;
    group2.fileRules.allowDelete = {"/x"};

    SandboxPolicyTlv tlv;
    int ret = CmdParser::ConvertOperationControlToTlv(
        {group1, group2}, DEC_POLICY_OP_TYPE_FILE, tlv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(2u, tlv.policies.size());

    const SandboxPolicyTlv::Policy &policy0 = tlv.policies[0];
    EXPECT_EQ(DEC_POLICY_OP_TYPE_FILE, policy0.operationType);
    ASSERT_EQ(1u, policy0.rules.size());
    EXPECT_EQ(DEC_POLICY_ACTION_DENY, policy0.rules[0].action);
    ASSERT_EQ(1u, policy0.rules[0].objectRules.size());
    ASSERT_EQ(1u, policy0.rules[0].objectRules[0].size());
    EXPECT_EQ("/x", policy0.rules[0].objectRules[0][0].path);

    const SandboxPolicyTlv::Policy &policy1 = tlv.policies[1];
    EXPECT_EQ(DEC_POLICY_OP_TYPE_FILE, policy1.operationType);
    ASSERT_EQ(1u, policy1.rules.size());
    EXPECT_EQ(DEC_POLICY_ACTION_ALLOW, policy1.rules[0].action);
    ASSERT_EQ(1u, policy1.rules[0].objectRules.size());
    ASSERT_EQ(1u, policy1.rules[0].objectRules[0].size());
    EXPECT_EQ("/x", policy1.rules[0].objectRules[0][0].path);
}

/**
 * @tc.name: ConvertOperationControlToTlv006
 * @tc.desc: Intra-group conflict: the same path under deny and allow within one
 *           group is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, ConvertOperationControlToTlv006, TestSize.Level0)
{
    SandboxPolicyRuleGroup group;
    group.hasFile = true;
    group.fileRules.denyDelete = {"/x"};
    group.fileRules.allowDelete = {"/x"};

    SandboxPolicyTlv tlv;
    int ret = CmdParser::ConvertOperationControlToTlv({group}, DEC_POLICY_OP_TYPE_FILE, tlv);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ConvertOperationControlToTlv007
 * @tc.desc: Process exec cmd conflict (same cmd in deny and allow) is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, ConvertOperationControlToTlv007, TestSize.Level0)
{
    SandboxPolicyRuleGroup group;
    group.hasProcess = true;
    group.processRules.denyExecCmd = {"ls"};
    group.processRules.allowExecCmd = {"ls"};

    SandboxPolicyTlv tlv;
    int ret = CmdParser::ConvertOperationControlToTlv({group}, DEC_POLICY_OP_TYPE_PROCESS, tlv);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
}

/**
 * @tc.name: ConvertOperationControlToTlv008
 * @tc.desc: A module that is not configured by any group produces no policy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, ConvertOperationControlToTlv008, TestSize.Level0)
{
    SandboxPolicyRuleGroup group;
    group.hasFile = true;
    group.fileRules.allowDelete = {"/data/x"};

    SandboxPolicyTlv tlv;
    int ret = CmdParser::ConvertOperationControlToTlv({group}, DEC_POLICY_OP_TYPE_NETWORK, tlv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_TRUE(tlv.policies.empty());
}

/**
 * @tc.name: ConvertOperationControlToTlv010
 * @tc.desc: Two File groups with distinct DefaultAction and deny sets each produce
 *           their own policy carrying their own header -- no first-group-wins
 *           merge, no policy_cnt accumulation beyond one per group
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, ConvertOperationControlToTlv010, TestSize.Level0)
{
    SandboxPolicyRuleGroup group1;
    group1.hasFile = true;
    group1.fileRules.defaultAction = DEC_POLICY_ACTION_DENY;
    group1.fileRules.denyDelete = {"/a"};
    SandboxPolicyRuleGroup group2;
    group2.hasFile = true;
    group2.fileRules.defaultAction = DEC_POLICY_ACTION_ALLOW;
    group2.fileRules.denyDelete = {"/b"};

    SandboxPolicyTlv tlv;
    int ret = CmdParser::ConvertOperationControlToTlv(
        {group1, group2}, DEC_POLICY_OP_TYPE_FILE, tlv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(2u, tlv.policies.size());

    const SandboxPolicyTlv::Policy &policy0 = tlv.policies[0];
    EXPECT_EQ(DEC_POLICY_OP_TYPE_FILE, policy0.operationType);
    EXPECT_EQ(DEC_POLICY_ACTION_DENY, policy0.defaultAction);
    ASSERT_EQ(1u, policy0.rules.size());
    ASSERT_EQ(1u, policy0.rules[0].objectRules.size());
    ASSERT_EQ(1u, policy0.rules[0].objectRules[0].size());
    EXPECT_EQ("/a", policy0.rules[0].objectRules[0][0].path);

    const SandboxPolicyTlv::Policy &policy1 = tlv.policies[1];
    EXPECT_EQ(DEC_POLICY_OP_TYPE_FILE, policy1.operationType);
    EXPECT_EQ(DEC_POLICY_ACTION_ALLOW, policy1.defaultAction);
    ASSERT_EQ(1u, policy1.rules.size());
    ASSERT_EQ(1u, policy1.rules[0].objectRules.size());
    ASSERT_EQ(1u, policy1.rules[0].objectRules[0].size());
    EXPECT_EQ("/b", policy1.rules[0].objectRules[0][0].path);
}

/**
 * @tc.name: OperationControlTlvSerialize001
 * @tc.desc: Serialize emits the scope block, policy headers (operation_type,
 *           default_action, ask_timeout_default_action, ruleslist_cnt) and one
 *           rule. Default action defaults to NONE, ask-timeout default to DENY.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, OperationControlTlvSerialize001, TestSize.Level0)
{
    SandboxPolicyTlv tlv;
    SandboxPolicyTlv::Policy policy;
    policy.operationType = DEC_POLICY_OP_TYPE_FILE;
    SandboxPolicyTlv::Rule rule;
    rule.action = DEC_POLICY_ACTION_DENY;
    rule.eventType = static_cast<uint32_t>(DEC_POLICY_FILE_EVENT_RMDIR | DEC_POLICY_FILE_EVENT_UNLINK);
    SandboxPolicyTlv::FilterRule objectRule;
    objectRule.cmpType = DEC_POLICY_CMP_EQ;
    objectRule.itemType = DEC_POLICY_ITEM_TYPE_PATH;
    objectRule.path = "/data/test/a";
    rule.objectRules.push_back(std::vector<SandboxPolicyTlv::FilterRule>{objectRule});
    policy.rules.push_back(rule);
    tlv.policies.push_back(policy);

    std::vector<uint8_t> out;
    int ret = tlv.Serialize(out);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_FALSE(out.empty());

    // Scope block leads the stream: [1]scope (the scope_size prefix is no
    // longer emitted).
    EXPECT_EQ(DEC_POLICY_TLV_SCOPE, ReadTlvU32At(out, 0));

    // [3]operation_size carries the policy-block size; the raw block follows.
    // The block's first four fields are u32 TLVs: operation_type, default_action,
    // ask_timeout_default_action, ruleslist_cnt.
    std::vector<uint8_t> policyBlock;
    ASSERT_TRUE(ExtractOperationPolicyBlock(out, policyBlock));
    ASSERT_GE(policyBlock.size(), 48u);
    EXPECT_EQ(DEC_POLICY_TLV_OPERATION_TYPE, ReadTlvU32At(policyBlock, 0));
    EXPECT_EQ(DEC_POLICY_OP_TYPE_FILE, ReadTlvU32At(policyBlock, 8));
    EXPECT_EQ(DEC_POLICY_TLV_DEFAULT_ACTION, ReadTlvU32At(policyBlock, 12));
    EXPECT_EQ(DEC_POLICY_ACTION_NONE, ReadTlvU32At(policyBlock, 20));   // not configured → NONE
    EXPECT_EQ(DEC_POLICY_TLV_ASK_TIMEOUT_DEFAULT_ACTION, ReadTlvU32At(policyBlock, 24));
    EXPECT_EQ(DEC_POLICY_ACTION_DENY, ReadTlvU32At(policyBlock, 32));   // ask-timeout default → DENY
    EXPECT_EQ(DEC_POLICY_TLV_RULESLIST_CNT, ReadTlvU32At(policyBlock, 36));
    EXPECT_EQ(1u, ReadTlvU32At(policyBlock, 44));

    // Exactly one rule action; the split rule carries object_cnt = 1.
    int ruleActionCount = 0;
    int objectCntOne = 0;
    WalkTlv(policyBlock, [&](uint32_t tag, uint32_t /*len*/) {
        if (tag == DEC_POLICY_TLV_RULE_ACTION) {
            ++ruleActionCount;
        }
        if (tag == DEC_POLICY_TLV_FILTER_RULE_OBJECT_CNT) {
            ++objectCntOne;
        }
    });
    EXPECT_EQ(1, ruleActionCount);
    EXPECT_EQ(1, objectCntOne);
}

/**
 * @tc.name: OperationControlTlvSerialize002
 * @tc.desc: Serialize with no policies emits scope + policy_cnt=0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, OperationControlTlvSerialize002, TestSize.Level0)
{
    SandboxPolicyTlv tlv;  // no policies

    std::vector<uint8_t> out;
    int ret = tlv.Serialize(out);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_FALSE(out.empty());

    std::vector<uint8_t> cntPayload;
    ASSERT_TRUE(ExtractTlvPayload(out, DEC_POLICY_TLV_POLICY_CNT, cntPayload));
    EXPECT_EQ(4u, cntPayload.size());
    EXPECT_EQ(0u, ReadTlvU32At(cntPayload, 0));
}

/**
 * @tc.name: OperationControlTlvSerialize003
 * @tc.desc: A filter rule whose item type is outside PATH/CMD/FD (here the kernel
 *           _NR sentinel) fails Serialize instead of silently emitting a bogus
 *           path string.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, OperationControlTlvSerialize003, TestSize.Level0)
{
    SandboxPolicyTlv tlv;
    SandboxPolicyTlv::Policy policy;
    policy.operationType = DEC_POLICY_OP_TYPE_FILE;
    SandboxPolicyTlv::Rule rule;
    rule.action = DEC_POLICY_ACTION_DENY;
    SandboxPolicyTlv::FilterRule objectRule;
    objectRule.cmpType = DEC_POLICY_CMP_EQ;
    objectRule.itemType = DEC_POLICY_ITEM_TYPE_NR;  // not PATH/CMD/FD
    objectRule.path = "/data/test/a";
    rule.objectRules.push_back(std::vector<SandboxPolicyTlv::FilterRule>{objectRule});
    policy.rules.push_back(rule);
    tlv.policies.push_back(policy);

    std::vector<uint8_t> out;
    int ret = tlv.Serialize(out);
    EXPECT_NE(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: OperationControlTlvSerialize004
 * @tc.desc: A filter rule with both cmpType and itemType left at their NR-sentinel
 *           Serialize too -- fail-closed, never silently treated as PATH.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, OperationControlTlvSerialize004, TestSize.Level0)
{
    SandboxPolicyTlv tlv;
    SandboxPolicyTlv::Policy policy;
    policy.operationType = DEC_POLICY_OP_TYPE_FILE;
    SandboxPolicyTlv::Rule rule;
    rule.action = DEC_POLICY_ACTION_DENY;
    SandboxPolicyTlv::FilterRule objectRule;  // unset: cmpType+itemType keep NR sentinels
    objectRule.path = "/data/test/a";
    rule.objectRules.push_back(std::vector<SandboxPolicyTlv::FilterRule>{objectRule});
    policy.rules.push_back(rule);
    tlv.policies.push_back(policy);

    std::vector<uint8_t> out;
    int ret = tlv.Serialize(out);
    EXPECT_NE(SANDBOX_SUCCESS, ret);
}

/**
 * @tc.name: OperationControlTlvSerializeFdPathSplit001
 * @tc.desc: A single PATH file rule serializes into TWO single-rule object
 *           entities on the wire: an FD entity (item = the open fd) followed by
 *           a PATH entity (item = path); the path item no longer carries the
 *           fd prefix.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, OperationControlTlvSerializeFdPathSplit001, TestSize.Level0)
{
    SandboxPolicyTlv tlv;
    SandboxPolicyTlv::Policy policy;
    policy.operationType = DEC_POLICY_OP_TYPE_FILE;
    SandboxPolicyTlv::Rule rule;
    rule.action = DEC_POLICY_ACTION_DENY;
    rule.eventType = static_cast<uint32_t>(DEC_POLICY_FILE_EVENT_RMDIR | DEC_POLICY_FILE_EVENT_UNLINK);
    SandboxPolicyTlv::FilterRule pathRule;
    pathRule.cmpType = DEC_POLICY_CMP_EQ;
    pathRule.itemType = DEC_POLICY_ITEM_TYPE_PATH;
    pathRule.path = "/data/test/a";
    pathRule.fd = 7;  // simulate a successful open
    rule.objectRules.push_back(std::vector<SandboxPolicyTlv::FilterRule>{pathRule});
    policy.rules.push_back(rule);
    tlv.policies.push_back(policy);

    std::vector<uint8_t> out;
    ASSERT_EQ(SANDBOX_SUCCESS, tlv.Serialize(out));
    std::vector<uint8_t> policyBlock;
    ASSERT_TRUE(ExtractOperationPolicyBlock(out, policyBlock));

    std::vector<ParsedTlvEntry> entries;
    ASSERT_TRUE(ParseTlvEntries(policyBlock, entries));
    const size_t objCntIdx = FindTlvEntry(entries, DEC_POLICY_TLV_FILTER_RULE_OBJECT_CNT);
    ASSERT_NE(entries.size(), objCntIdx);
    EXPECT_EQ(2u, EntryU32(entries[objCntIdx]));  // FD entity + PATH entity

    // Following object_cnt, in order (each entity = one rule block): an FD
    // entity carrying the fd value, then a PATH entity carrying the path. Each
    // block is cmp_type/item_type/item; the item payload length is the TLV len.
    const std::string path("/data/test/a");
    ASSERT_GE(entries.size(), objCntIdx + 7);
    EXPECT_EQ(DEC_POLICY_TLV_FILTER_RULE_CMP_TYPE, entries[objCntIdx + 1].tag);
    EXPECT_EQ(DEC_POLICY_CMP_EQ, EntryU32(entries[objCntIdx + 1]));
    EXPECT_EQ(DEC_POLICY_TLV_FILTER_RULE_ITEM_TYPE, entries[objCntIdx + 2].tag);
    EXPECT_EQ(DEC_POLICY_ITEM_TYPE_FD, EntryU32(entries[objCntIdx + 2]));
    EXPECT_EQ(DEC_POLICY_TLV_FILTER_RULE_ITEM, entries[objCntIdx + 3].tag);
    ASSERT_EQ(4u, entries[objCntIdx + 3].payload.size());
    EXPECT_EQ(7u, EntryU32(entries[objCntIdx + 3]));

    EXPECT_EQ(DEC_POLICY_TLV_FILTER_RULE_CMP_TYPE, entries[objCntIdx + 4].tag);
    EXPECT_EQ(DEC_POLICY_CMP_EQ, EntryU32(entries[objCntIdx + 4]));
    EXPECT_EQ(DEC_POLICY_TLV_FILTER_RULE_ITEM_TYPE, entries[objCntIdx + 5].tag);
    EXPECT_EQ(DEC_POLICY_ITEM_TYPE_PATH, EntryU32(entries[objCntIdx + 5]));
    EXPECT_EQ(DEC_POLICY_TLV_FILTER_RULE_ITEM, entries[objCntIdx + 6].tag);
    ASSERT_EQ(path.size() + 1, entries[objCntIdx + 6].payload.size());
    std::string pathItem(reinterpret_cast<const char *>(entries[objCntIdx + 6].payload.data()),
        entries[objCntIdx + 6].payload.size());
    EXPECT_EQ(path + '\0', pathItem);
}

/**
 * @tc.name: OperationControlTlvSerializeFdPathSplit002
 * @tc.desc: A single CMD process rule is NOT split: object_cnt stays 1, the
 *           entity holds one CMD rule, and no FD entity appears anywhere.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, OperationControlTlvSerializeFdPathSplit002, TestSize.Level0)
{
    SandboxPolicyTlv tlv;
    SandboxPolicyTlv::Policy policy;
    policy.operationType = DEC_POLICY_OP_TYPE_PROCESS;
    SandboxPolicyTlv::Rule rule;
    rule.action = DEC_POLICY_ACTION_DENY;
    rule.eventType = static_cast<uint32_t>(DEC_POLICY_PROCESS_EVENT_EXEC);
    SandboxPolicyTlv::FilterRule cmdRule;
    cmdRule.cmpType = DEC_POLICY_CMP_EQ;
    cmdRule.itemType = DEC_POLICY_ITEM_TYPE_CMD;
    cmdRule.cmd = "/bin/echo";
    rule.objectRules.push_back(std::vector<SandboxPolicyTlv::FilterRule>{cmdRule});
    policy.rules.push_back(rule);
    tlv.policies.push_back(policy);

    std::vector<uint8_t> out;
    ASSERT_EQ(SANDBOX_SUCCESS, tlv.Serialize(out));
    std::vector<uint8_t> policyBlock;
    ASSERT_TRUE(ExtractOperationPolicyBlock(out, policyBlock));

    std::vector<ParsedTlvEntry> entries;
    ASSERT_TRUE(ParseTlvEntries(policyBlock, entries));
    const size_t objCntIdx = FindTlvEntry(entries, DEC_POLICY_TLV_FILTER_RULE_OBJECT_CNT);
    ASSERT_NE(entries.size(), objCntIdx);
    EXPECT_EQ(1u, EntryU32(entries[objCntIdx]));

    // Following object_cnt, the single entity is one rule block
    // (cmp_type/item_type/item) carrying the CMD string.
    const std::string cmd("/bin/echo");
    ASSERT_GE(entries.size(), objCntIdx + 4);
    EXPECT_EQ(DEC_POLICY_TLV_FILTER_RULE_CMP_TYPE, entries[objCntIdx + 1].tag);
    EXPECT_EQ(DEC_POLICY_CMP_EQ, EntryU32(entries[objCntIdx + 1]));
    EXPECT_EQ(DEC_POLICY_TLV_FILTER_RULE_ITEM_TYPE, entries[objCntIdx + 2].tag);
    EXPECT_EQ(DEC_POLICY_ITEM_TYPE_CMD, EntryU32(entries[objCntIdx + 2]));
    EXPECT_EQ(DEC_POLICY_TLV_FILTER_RULE_ITEM, entries[objCntIdx + 3].tag);
    ASSERT_EQ(cmd.size() + 1, entries[objCntIdx + 3].payload.size());
    std::string cmdItem(reinterpret_cast<const char *>(entries[objCntIdx + 3].payload.data()),
        entries[objCntIdx + 3].payload.size());
    EXPECT_EQ(cmd + '\0', cmdItem);

    // No FD entity may appear for a CMD rule.
    int fdItemCnt = 0;
    for (const auto &e : entries) {
        if (e.tag == DEC_POLICY_TLV_FILTER_RULE_ITEM_TYPE && EntryU32(e) == DEC_POLICY_ITEM_TYPE_FD) {
            ++fdItemCnt;
        }
    }
    EXPECT_EQ(0, fdItemCnt);
}

/**
 * @tc.name: BuildAlPolicyContext001
 * @tc.desc: BuildAlPolicyContext copies the serialized TLV into SandboxPolicyArg
 *           and the caller frees it
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, BuildAlPolicyContext001, TestSize.Level0)
{
    SandboxPolicyTlv tlv;
    SandboxPolicyTlv::Policy policy;
    policy.operationType = DEC_POLICY_OP_TYPE_FILE;
    SandboxPolicyTlv::Rule rule;
    rule.action = DEC_POLICY_ACTION_ALLOW;
    rule.eventType = static_cast<uint32_t>(DEC_POLICY_FILE_EVENT_RMDIR | DEC_POLICY_FILE_EVENT_UNLINK);
    SandboxPolicyTlv::FilterRule objectRule;
    objectRule.cmpType = DEC_POLICY_CMP_EQ;
    objectRule.itemType = DEC_POLICY_ITEM_TYPE_PATH;
    objectRule.path = "/data/test/a";
    rule.objectRules.push_back(std::vector<SandboxPolicyTlv::FilterRule>{objectRule});
    policy.rules.push_back(rule);
    tlv.policies.push_back(policy);

    struct SandboxPolicyArg *context = nullptr;
    int ret = CmdParser::BuildAlPolicyContext(tlv, context);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_NE(nullptr, context);
    EXPECT_EQ(1u, context->version);
    EXPECT_GT(context->size, 0u);
    std::free(context);
}

/**
 * @tc.name: BuildAlPolicyContext002
 * @tc.desc: BuildAlPolicyContext accepts an empty policy set: Serialize still
 *           emits the scope block + policy_cnt=0, so the context is valid
 *           (carrier non-empty), not an error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, BuildAlPolicyContext002, TestSize.Level0)
{
    SandboxPolicyTlv tlv;  // no policies

    struct SandboxPolicyArg *context = nullptr;
    int ret = CmdParser::BuildAlPolicyContext(tlv, context);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_NE(nullptr, context);
    EXPECT_EQ(1u, context->version);
    EXPECT_GT(context->size, 0u);
    std::free(context);
}

/**
 * @tc.name: OpenFileFds001
 * @tc.desc: OpenFileFds returns SANDBOX_ERR_PATH_INVALID when a PATH cannot be
 *           opened; the failing rule keeps the "not open" marker, CMD rules stay
 *           untouched, and CloseFileFds() afterwards is a safe no-op
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, OpenFileFds001, TestSize.Level0)
{
    SandboxPolicyTlv tlv;
    SandboxPolicyTlv::Policy policy;
    policy.operationType = DEC_POLICY_OP_TYPE_FILE;
    SandboxPolicyTlv::Rule rule;
    rule.action = DEC_POLICY_ACTION_DENY;
    rule.eventType = static_cast<uint32_t>(DEC_POLICY_FILE_EVENT_RMDIR | DEC_POLICY_FILE_EVENT_UNLINK);
    SandboxPolicyTlv::FilterRule pathRule;
    pathRule.cmpType = DEC_POLICY_CMP_EQ;
    pathRule.itemType = DEC_POLICY_ITEM_TYPE_PATH;
    pathRule.path = "/nonexistent/definitely/missing";
    SandboxPolicyTlv::FilterRule cmdRule;
    cmdRule.cmpType = DEC_POLICY_CMP_EQ;
    cmdRule.itemType = DEC_POLICY_ITEM_TYPE_CMD;
    cmdRule.cmd = "/bin/echo";
    rule.objectRules.push_back(
        std::vector<SandboxPolicyTlv::FilterRule>{pathRule, cmdRule});
    policy.rules.push_back(rule);
    tlv.policies.push_back(policy);

    int ret = tlv.OpenFileFds();
    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, ret);                     // open failed → error
    EXPECT_EQ(-1, tlv.policies[0].rules[0].objectRules[0][0].fd);  // still "not open"
    EXPECT_EQ(-1, tlv.policies[0].rules[0].objectRules[0][1].fd);  // CMD untouched (fd never set)

    tlv.CloseFileFds();  // must not close the "not open" marker / default -1
}

// Return a directory the test process can actually create files in, probed once at
// first call. /tmp is not guaranteed writable for a non-root unit-test process on
// every target, so fall back through TMPDIR / cwd / /data/local/tmp before /tmp.
static std::string GetWritableTempDir()
{
    static const std::string dir = []() -> std::string {
        std::vector<std::string> candidates;
        const char *envDir = getenv("TMPDIR");
        if (envDir != nullptr && envDir[0] != '\0') {
            candidates.push_back(envDir);
        }
        char cwdBuf[4096];
        if (getcwd(cwdBuf, sizeof(cwdBuf)) != nullptr) {
            candidates.push_back(cwdBuf);
        }
        candidates.push_back("/data/local/tmp");
        candidates.push_back("/tmp");
        for (const auto &cand : candidates) {
            std::string tmpl = cand + "/claw_sandbox_writable_probe_XXXXXX";
            if (tmpl.size() + 1 > sizeof(cwdBuf)) {
                continue;  // path too long for mkstemp
            }
            std::vector<char> buf(tmpl.begin(), tmpl.end());
            buf.push_back('\0');
            int fd = mkstemp(buf.data());
            if (fd >= 0) {
                close(fd);
                unlink(buf.data());
                return cand;
            }
        }
        return std::string("/tmp");  // last resort: keeps the same failure signal if none writable
    }();
    return dir;
}

// Build a mkstemp path under the writable temp dir (pattern must end in XXXXXX).
static std::string MakeTempFilePath(const char *pattern)
{
    std::string tmpl = GetWritableTempDir() + "/" + pattern;
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    int fd = mkstemp(buf.data());
    if (fd >= 0) {
        close(fd);
    }
    return std::string(buf.data());
}

// Create a real regular temp file and return its path (caller unlink()s it).
static std::string CreateOpenableFile()
{
    return MakeTempFilePath("claw_sandbox_rule_file_XXXXXX");
}

/**
 * @tc.name: OpenFileFds002
 * @tc.desc: OpenFileFds opens an existing regular file successfully and returns
 *           SANDBOX_SUCCESS with a valid fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, OpenFileFds002, TestSize.Level0)
{
    const std::string file = CreateOpenableFile();

    SandboxPolicyTlv tlv;
    SandboxPolicyTlv::Policy policy;
    policy.operationType = DEC_POLICY_OP_TYPE_FILE;
    SandboxPolicyTlv::Rule rule;
    rule.action = DEC_POLICY_ACTION_DENY;
    rule.eventType = static_cast<uint32_t>(DEC_POLICY_FILE_EVENT_RMDIR | DEC_POLICY_FILE_EVENT_UNLINK);
    SandboxPolicyTlv::FilterRule pathRule;
    pathRule.cmpType = DEC_POLICY_CMP_EQ;
    pathRule.itemType = DEC_POLICY_ITEM_TYPE_PATH;
    pathRule.path = file;
    rule.objectRules.push_back(std::vector<SandboxPolicyTlv::FilterRule>{pathRule});
    policy.rules.push_back(rule);
    tlv.policies.push_back(policy);

    int ret = tlv.OpenFileFds();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    const int fd = tlv.policies[0].rules[0].objectRules[0][0].fd;
    EXPECT_GE(fd, 0);   // a real opened fd is non-negative
    EXPECT_NE(-1, fd);  // never the "not open" sentinel

    tlv.CloseFileFds();
    unlink(file.c_str());
}

/**
 * @tc.name: OpenFileFds003
 * @tc.desc: OpenFileFds accepts a symlink: every PATH rule opens with
 *           O_PATH|O_NOFOLLOW, so the symlink itself is opened (never followed),
 *           returning SANDBOX_SUCCESS with a valid fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, OpenFileFds003, TestSize.Level0)
{
    const std::string target = CreateOpenableFile();
    const std::string link = GetWritableTempDir() + "/claw_sandbox_rule_link_" + std::to_string(getpid());
    unlink(link.c_str());  // clear a stale link from an earlier aborted run
    ASSERT_EQ(0, symlink(target.c_str(), link.c_str()));

    SandboxPolicyTlv tlv;
    SandboxPolicyTlv::Policy policy;
    policy.operationType = DEC_POLICY_OP_TYPE_FILE;
    SandboxPolicyTlv::Rule rule;
    rule.action = DEC_POLICY_ACTION_DENY;
    rule.eventType = static_cast<uint32_t>(DEC_POLICY_FILE_EVENT_RMDIR | DEC_POLICY_FILE_EVENT_UNLINK);
    SandboxPolicyTlv::FilterRule pathRule;
    pathRule.cmpType = DEC_POLICY_CMP_EQ;
    pathRule.itemType = DEC_POLICY_ITEM_TYPE_PATH;
    pathRule.path = link;
    rule.objectRules.push_back(std::vector<SandboxPolicyTlv::FilterRule>{pathRule});
    policy.rules.push_back(rule);
    tlv.policies.push_back(policy);

    int ret = tlv.OpenFileFds();
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    const int fd = tlv.policies[0].rules[0].objectRules[0][0].fd;
    EXPECT_GE(fd, 0);   // a real opened fd is non-negative
    EXPECT_NE(-1, fd);  // never the "not open" sentinel

    tlv.CloseFileFds();
    unlink(link.c_str());
    unlink(target.c_str());
}

/**
 * @tc.name: ConvertOperationControlToTlv011
 * @tc.desc: An empty rule-group list yields SUCCESS with no policies
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, ConvertOperationControlToTlv011, TestSize.Level0)
{
    SandboxPolicyTlv tlv;
    int ret = CmdParser::ConvertOperationControlToTlv({}, DEC_POLICY_OP_TYPE_FILE, tlv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    EXPECT_TRUE(tlv.policies.empty());
}

/**
 * @tc.name: ConvertOperationControlToTlv012
 * @tc.desc: File AskDelete rules carry the ASK action (one rule per path)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, ConvertOperationControlToTlv012, TestSize.Level0)
{
    SandboxPolicyRuleGroup group;
    group.hasFile = true;
    group.fileRules.askDelete = {"/a"};
    std::vector<SandboxPolicyRuleGroup> groups = {group};

    SandboxPolicyTlv tlv;
    int ret = CmdParser::ConvertOperationControlToTlv(groups, DEC_POLICY_OP_TYPE_FILE, tlv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(1u, tlv.policies.size());
    ASSERT_EQ(1u, tlv.policies[0].rules.size());
    EXPECT_EQ(DEC_POLICY_ACTION_ASK, tlv.policies[0].rules[0].action);
    EXPECT_EQ(static_cast<uint32_t>(DEC_POLICY_FILE_EVENT_RMDIR | DEC_POLICY_FILE_EVENT_UNLINK),
        tlv.policies[0].rules[0].eventType);
    ASSERT_EQ(1u, tlv.policies[0].rules[0].objectRules.size());
    ASSERT_EQ(1u, tlv.policies[0].rules[0].objectRules[0].size());
    EXPECT_EQ(DEC_POLICY_ITEM_TYPE_PATH, tlv.policies[0].rules[0].objectRules[0][0].itemType);
}

/**
 * @tc.name: ConvertOperationControlToTlv013
 * @tc.desc: Intra-group deny+ask conflict on one File path is rejected (the ASK
 *           action participates in conflict detection, not just deny/allow)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, ConvertOperationControlToTlv013, TestSize.Level0)
{
    SandboxPolicyRuleGroup group;
    group.hasFile = true;
    group.fileRules.denyDelete = {"/x"};
    group.fileRules.askDelete = {"/x"};

    SandboxPolicyTlv tlv;
    int ret = CmdParser::ConvertOperationControlToTlv({group}, DEC_POLICY_OP_TYPE_FILE, tlv);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
    EXPECT_TRUE(tlv.policies.empty());
}

/**
 * @tc.name: ConvertOperationControlToTlv014
 * @tc.desc: Process AskExecCmd rules carry the ASK action
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, ConvertOperationControlToTlv014, TestSize.Level0)
{
    SandboxPolicyRuleGroup group;
    group.hasProcess = true;
    group.processRules.askExecCmd = {"sh"};
    std::vector<SandboxPolicyRuleGroup> groups = {group};

    SandboxPolicyTlv tlv;
    int ret = CmdParser::ConvertOperationControlToTlv(groups, DEC_POLICY_OP_TYPE_PROCESS, tlv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    ASSERT_EQ(1u, tlv.policies.size());
    ASSERT_EQ(1u, tlv.policies[0].rules.size());
    EXPECT_EQ(DEC_POLICY_ACTION_ASK, tlv.policies[0].rules[0].action);
    EXPECT_EQ(static_cast<uint32_t>(DEC_POLICY_PROCESS_EVENT_EXEC),
        tlv.policies[0].rules[0].eventType);
    ASSERT_EQ(1u, tlv.policies[0].rules[0].objectRules.size());
    ASSERT_EQ(1u, tlv.policies[0].rules[0].objectRules[0].size());
    EXPECT_EQ(DEC_POLICY_ITEM_TYPE_CMD, tlv.policies[0].rules[0].objectRules[0][0].itemType);
}

/**
 * @tc.name: OperationControlTlvSerializeSubjectPath001
 * @tc.desc: A PATH rule on the SUBJECT side also splits into FD + PATH single-rule
 *           entities under the subject_cnt tag (object side stays 0)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, OperationControlTlvSerializeSubjectPath001, TestSize.Level0)
{
    SandboxPolicyTlv tlv;
    SandboxPolicyTlv::Policy policy;
    policy.operationType = DEC_POLICY_OP_TYPE_FILE;
    SandboxPolicyTlv::Rule rule;
    rule.action = DEC_POLICY_ACTION_DENY;
    rule.eventType = static_cast<uint32_t>(DEC_POLICY_FILE_EVENT_RMDIR | DEC_POLICY_FILE_EVENT_UNLINK);
    SandboxPolicyTlv::FilterRule pathRule;
    pathRule.cmpType = DEC_POLICY_CMP_EQ;
    pathRule.itemType = DEC_POLICY_ITEM_TYPE_PATH;
    pathRule.path = "/data/test/subj";
    pathRule.fd = 9;  // simulate a successful open
    rule.subjectRules.push_back(std::vector<SandboxPolicyTlv::FilterRule>{pathRule});
    policy.rules.push_back(rule);
    tlv.policies.push_back(policy);

    std::vector<uint8_t> out;
    ASSERT_EQ(SANDBOX_SUCCESS, tlv.Serialize(out));
    std::vector<uint8_t> policyBlock;
    ASSERT_TRUE(ExtractOperationPolicyBlock(out, policyBlock));

    std::vector<ParsedTlvEntry> entries;
    ASSERT_TRUE(ParseTlvEntries(policyBlock, entries));
    const size_t subjCntIdx = FindTlvEntry(entries, DEC_POLICY_TLV_FILTER_RULE_SUBJECT_CNT);
    ASSERT_NE(entries.size(), subjCntIdx);
    EXPECT_EQ(2u, EntryU32(entries[subjCntIdx]));  // FD entity + PATH entity

    // Following subject_cnt, in order: an FD entity (item = fd value), then a
    // PATH entity (item = path). The subject split mirrors the object split.
    const std::string path("/data/test/subj");
    ASSERT_GE(entries.size(), subjCntIdx + 7);
    EXPECT_EQ(DEC_POLICY_TLV_FILTER_RULE_CMP_TYPE, entries[subjCntIdx + 1].tag);
    EXPECT_EQ(DEC_POLICY_CMP_EQ, EntryU32(entries[subjCntIdx + 1]));
    EXPECT_EQ(DEC_POLICY_TLV_FILTER_RULE_ITEM_TYPE, entries[subjCntIdx + 2].tag);
    EXPECT_EQ(DEC_POLICY_ITEM_TYPE_FD, EntryU32(entries[subjCntIdx + 2]));
    EXPECT_EQ(DEC_POLICY_TLV_FILTER_RULE_ITEM, entries[subjCntIdx + 3].tag);
    ASSERT_EQ(4u, entries[subjCntIdx + 3].payload.size());
    EXPECT_EQ(9u, EntryU32(entries[subjCntIdx + 3]));

    EXPECT_EQ(DEC_POLICY_TLV_FILTER_RULE_CMP_TYPE, entries[subjCntIdx + 4].tag);
    EXPECT_EQ(DEC_POLICY_CMP_EQ, EntryU32(entries[subjCntIdx + 4]));
    EXPECT_EQ(DEC_POLICY_TLV_FILTER_RULE_ITEM_TYPE, entries[subjCntIdx + 5].tag);
    EXPECT_EQ(DEC_POLICY_ITEM_TYPE_PATH, EntryU32(entries[subjCntIdx + 5]));
    EXPECT_EQ(DEC_POLICY_TLV_FILTER_RULE_ITEM, entries[subjCntIdx + 6].tag);
    ASSERT_EQ(path.size() + 1, entries[subjCntIdx + 6].payload.size());
    std::string pathItem(reinterpret_cast<const char *>(entries[subjCntIdx + 6].payload.data()),
        entries[subjCntIdx + 6].payload.size());
    EXPECT_EQ(path + '\0', pathItem);

    // Object side is empty → object_cnt = 0.
    const size_t objCntIdx = FindTlvEntry(entries, DEC_POLICY_TLV_FILTER_RULE_OBJECT_CNT);
    ASSERT_NE(entries.size(), objCntIdx);
    EXPECT_EQ(0u, EntryU32(entries[objCntIdx]));
}

/**
 * @tc.name: OperationControlTlvSerializeMultiPolicy001
 * @tc.desc: Two policies serialize as policy_cnt=2 with two operation_size
 *           blocks (per-group delivery means a tlv can hold several policies)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, OperationControlTlvSerializeMultiPolicy001, TestSize.Level0)
{
    SandboxPolicyTlv tlv;
    SandboxPolicyTlv::Policy networkPolicy;
    networkPolicy.operationType = DEC_POLICY_OP_TYPE_NETWORK;
    networkPolicy.defaultAction = DEC_POLICY_ACTION_DENY;
    SandboxPolicyTlv::Policy filePolicy;
    filePolicy.operationType = DEC_POLICY_OP_TYPE_FILE;
    filePolicy.defaultAction = DEC_POLICY_ACTION_ASK;
    tlv.policies.push_back(networkPolicy);
    tlv.policies.push_back(filePolicy);

    std::vector<uint8_t> out;
    ASSERT_EQ(SANDBOX_SUCCESS, tlv.Serialize(out));

    std::vector<uint8_t> cntPayload;
    ASSERT_TRUE(ExtractTlvPayload(out, DEC_POLICY_TLV_POLICY_CNT, cntPayload));
    EXPECT_EQ(2u, ReadTlvU32At(cntPayload, 0));

    int opSizeCount = 0;
    WalkTlv(out, [&](uint32_t tag, uint32_t /*len*/) {
        if (tag == DEC_POLICY_TLV_OPERATION_SIZE) {
            ++opSizeCount;
        }
    });
    EXPECT_EQ(2, opSizeCount);
}

/**
 * @tc.name: BuildAlPolicyContext003
 * @tc.desc: BuildAlPolicyContext propagates a Serialize failure (here an
 *           unsupported filter-rule item type) and leaves the context null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, BuildAlPolicyContext003, TestSize.Level0)
{
    SandboxPolicyTlv tlv;
    SandboxPolicyTlv::Policy policy;
    policy.operationType = DEC_POLICY_OP_TYPE_FILE;
    SandboxPolicyTlv::Rule rule;
    rule.action = DEC_POLICY_ACTION_DENY;
    SandboxPolicyTlv::FilterRule objectRule;
    objectRule.cmpType = DEC_POLICY_CMP_EQ;
    objectRule.itemType = DEC_POLICY_ITEM_TYPE_NR;  // not PATH/CMD/FD → Serialize fails
    rule.objectRules.push_back(std::vector<SandboxPolicyTlv::FilterRule>{objectRule});
    policy.rules.push_back(rule);
    tlv.policies.push_back(policy);

    struct SandboxPolicyArg *context = nullptr;
    int ret = CmdParser::BuildAlPolicyContext(tlv, context);
    EXPECT_NE(SANDBOX_SUCCESS, ret);
    EXPECT_EQ(nullptr, context);
}

/**
 * @tc.name: BuildAlPolicyContext004
 * @tc.desc: A serialized policy payload larger than the kernel TLV cap is
 *           rejected (SANDBOX_ERR_CONFIG_INVALID) without allocating the context
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, BuildAlPolicyContext004, TestSize.Level0)
{
    SandboxPolicyTlv tlv;
    SandboxPolicyTlv::Policy policy;
    policy.operationType = DEC_POLICY_OP_TYPE_PROCESS;
    // ~81 bytes per minimal CMD rule; 1000 rules push the payload past 64 KiB.
    for (int i = 0; i < 1000; ++i) {
        SandboxPolicyTlv::Rule rule;
        rule.action = DEC_POLICY_ACTION_DENY;
        rule.eventType = static_cast<uint32_t>(DEC_POLICY_PROCESS_EVENT_EXEC);
        SandboxPolicyTlv::FilterRule fr;
        fr.cmpType = DEC_POLICY_CMP_EQ;
        fr.itemType = DEC_POLICY_ITEM_TYPE_CMD;
        rule.objectRules.push_back(std::vector<SandboxPolicyTlv::FilterRule>{fr});
        policy.rules.push_back(rule);
    }
    tlv.policies.push_back(policy);

    struct SandboxPolicyArg *context = nullptr;
    int ret = CmdParser::BuildAlPolicyContext(tlv, context);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);
    EXPECT_EQ(nullptr, context);
}

/**
 * @tc.name: OpenFileFds004
 * @tc.desc: OpenFileFds opens SUBJECT path rules before object rules: a subject
 *           path that opens succeeds, then the object path failure aborts; the
 *           opened subject fd is freed by the subsequent CloseFileFds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, OpenFileFds004, TestSize.Level0)
{
    const std::string file = CreateOpenableFile();

    SandboxPolicyTlv tlv;
    SandboxPolicyTlv::Policy policy;
    policy.operationType = DEC_POLICY_OP_TYPE_FILE;
    SandboxPolicyTlv::Rule rule;
    rule.action = DEC_POLICY_ACTION_DENY;
    rule.eventType = static_cast<uint32_t>(DEC_POLICY_FILE_EVENT_RMDIR | DEC_POLICY_FILE_EVENT_UNLINK);
    SandboxPolicyTlv::FilterRule subjRule;
    subjRule.cmpType = DEC_POLICY_CMP_EQ;
    subjRule.itemType = DEC_POLICY_ITEM_TYPE_PATH;
    subjRule.path = file;
    SandboxPolicyTlv::FilterRule objRule;
    objRule.cmpType = DEC_POLICY_CMP_EQ;
    objRule.itemType = DEC_POLICY_ITEM_TYPE_PATH;
    objRule.path = "/nonexistent/definitely/missing";
    rule.subjectRules.push_back(std::vector<SandboxPolicyTlv::FilterRule>{subjRule});
    rule.objectRules.push_back(std::vector<SandboxPolicyTlv::FilterRule>{objRule});
    policy.rules.push_back(rule);
    tlv.policies.push_back(policy);

    int ret = tlv.OpenFileFds();
    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, ret);                 // object open failed
    const int subjFd = tlv.policies[0].rules[0].subjectRules[0][0].fd;
    EXPECT_GE(subjFd, 0);                                     // subject path opened first
    EXPECT_EQ(-1, tlv.policies[0].rules[0].objectRules[0][0].fd);  // object never opened

    tlv.CloseFileFds();                                       // closes only the subject fd
    EXPECT_EQ(-1, tlv.policies[0].rules[0].subjectRules[0][0].fd);
    unlink(file.c_str());
}

/**
 * @tc.name: ConvertOperationControlToTlv015
 * @tc.desc: A symlink and the file it points at are two objects, so opposing
 *           actions on them are not a conflict. Rule fds open O_NOFOLLOW, which
 *           makes a policy on the symlink itself a supported thing to write;
 *           resolving the path for conflict detection would refuse it.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, ConvertOperationControlToTlv015, TestSize.Level0)
{
    const std::string target = MakeTempFilePath("claw_sandbox_conflict_target_XXXXXX");
    ASSERT_FALSE(target.empty());
    const std::string link = target + ".link";
    ASSERT_EQ(0, symlink(target.c_str(), link.c_str()));

    SandboxPolicyRuleGroup group;
    group.hasFile = true;
    group.fileRules.denyDelete = {link};
    group.fileRules.allowDelete = {target};

    SandboxPolicyTlv tlv;
    int ret = CmdParser::ConvertOperationControlToTlv({group}, DEC_POLICY_OP_TYPE_FILE, tlv);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);

    unlink(link.c_str());
    unlink(target.c_str());
}

/**
 * @tc.name: ConvertOperationControlToTlv016
 * @tc.desc: Two spellings of one file are still one object, so opposing actions
 *           on them do conflict. Without this the two would both be delivered
 *           and the later action would silently override the earlier one.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, ConvertOperationControlToTlv016, TestSize.Level0)
{
    const std::string file = MakeTempFilePath("claw_sandbox_conflict_spelling_XXXXXX");
    ASSERT_FALSE(file.empty());
    const size_t slash = file.rfind('/');
    ASSERT_NE(std::string::npos, slash);
    // Same file, written with a "." component before the last one.
    const std::string spelled = file.substr(0, slash) + "/./" + file.substr(slash + 1);

    SandboxPolicyRuleGroup group;
    group.hasFile = true;
    group.fileRules.denyDelete = {file};
    group.fileRules.allowDelete = {spelled};

    SandboxPolicyTlv tlv;
    int ret = CmdParser::ConvertOperationControlToTlv({group}, DEC_POLICY_OP_TYPE_FILE, tlv);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);

    unlink(file.c_str());
}

/**
 * @tc.name: ConvertOperationControlToTlv017
 * @tc.desc: Two hard links to one file are one object, so opposing actions on
 *           them conflict. This is the other half of what keying on the inode
 *           buys: comparing paths, canonicalised or not, cannot see it, and the
 *           two rules would both be delivered with the later action winning.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxOpControlParserTest, ConvertOperationControlToTlv017, TestSize.Level0)
{
    const std::string first = MakeTempFilePath("claw_sandbox_conflict_hard_XXXXXX");
    ASSERT_FALSE(first.empty());
    const std::string second = first + ".hard";
    unlink(second.c_str());  // clear a stale link from an earlier aborted run
    ASSERT_EQ(0, link(first.c_str(), second.c_str()));

    SandboxPolicyRuleGroup group;
    group.hasFile = true;
    group.fileRules.denyDelete = {first};
    group.fileRules.allowDelete = {second};

    SandboxPolicyTlv tlv;
    int ret = CmdParser::ConvertOperationControlToTlv({group}, DEC_POLICY_OP_TYPE_FILE, tlv);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, ret);

    unlink(second.c_str());
    unlink(first.c_str());
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
