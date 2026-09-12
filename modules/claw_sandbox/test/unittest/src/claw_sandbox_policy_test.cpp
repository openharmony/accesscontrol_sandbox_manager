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

#include "claw_sandbox_policy_test.h"
#include "sandbox_cmd_parser.h"
#include "sandbox_error.h"
#include "sandbox_limits.h"
#include "sandbox_mock_state.h"
#include "sandbox_policy.h"

#include <cerrno>
#include <climits>
#include <string>
#include <unistd.h>
#include <vector>

/*
 * Last on purpose. sandbox_log.h #undefs LOG_TAG and LOG_DOMAIN and redefines
 * them, and those are plain macros read where SANDBOX_LOGx is written, not
 * settings applied once. Any header included after this one that defines its own
 * LOG_TAG silently takes over, and the log lines go out under someone else's tag
 * and domain - which looks exactly like logging being broken.
 */
#include "sandbox_log.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

namespace {
constexpr int32_t TEST_MOCK_FD = 100;

/*
 * Rule group JSON covering both modules a dynamic policy may carry, so one
 * DEC_CMD_POLICY_ADD ioctl is expected per module.
 *
 * Scope carries Type and nothing else, and the parser reads no key but Type, so
 * anything else written there is ignored rather than refused.
 */
/*
 * A path that is certain to open. OpenFileFds opens every PATH item through the
 * real kernel - the mock only intercepts /dev/dec - so a rule naming a path that
 * does not exist is dropped, and one dropped rule alone makes the whole request
 * partial. That is AddOperationControlPolicies008's subject; this fixture needs
 * every rule to survive as far as the device.
 *
 * The test binary itself is used rather than a fixed location like /data/test,
 * which is not guaranteed to exist on the machine running these.
 */
std::string ExistingFilePath()
{
    char self[PATH_MAX] = {0};
    ssize_t length = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (length > 0) {
        return std::string(self, static_cast<size_t>(length));
    }
    /*
     * The readlink matters: the protected-object check compares inodes, and a
     * rule fd is opened O_NOFOLLOW while the reference is stat'd. Handing back
     * the symlink instead of its target would make those two different objects.
     */
    return "/proc/self/exe";
}

// Every module a dynamic policy may carry - File and Process. Network is not one
// of them: these documents go through CmdParser::ParseOperationControlPolicy,
// which parses as SANDBOX_POLICY_PARSE_DYNAMIC, and EnforcePhaseRules refuses a
// Network module there.
std::string AllDynamicModulesPolicy()
{
    return R"({
    "AddOperationControlRuleGroups": [
        {
            "Scope": { "Type": "self_session" },
            "File": { "DenyDelete": [")" + ExistingFilePath() + R"("] },
            "Process": { "DefaultAction": "ask", "DenyExecCmd": ["rm"] }
        }
    ]
})";
}

// File contradicts itself, Process does not. The conflict is confined to the
// file module, so the other one must still be delivered.
const char *FILE_CONFLICT_POLICY = R"({
    "AddOperationControlRuleGroups": [
        {
            "Scope": { "Type": "self_session" },
            "File": { "DenyDelete": ["/data/test/a.txt"],
                      "AllowDelete": ["/data/test/a.txt"] },
            "Process": { "DefaultAction": "ask", "DenyExecCmd": ["rm"] }
        }
    ]
})";

const char *PROCESS_ONLY_POLICY = R"({
    "AddOperationControlRuleGroups": [
        {
            "Scope": { "Type": "self_session" },
            "Process": { "DefaultAction": "ask", "DenyExecCmd": ["rm"] }
        }
    ]
})";

std::vector<SandboxPolicyRuleGroup> BuildRuleGroups(const char *json)
{
    std::vector<SandboxPolicyRuleGroup> ruleGroups;
    int ret = CmdParser::ParseOperationControlPolicy(json, ruleGroups);
    EXPECT_EQ(SANDBOX_SUCCESS, ret);
    return ruleGroups;
}
} // namespace

void ClawSandboxPolicyTest::SetUpTestCase() {}
void ClawSandboxPolicyTest::TearDownTestCase() {}

void ClawSandboxPolicyTest::SetUp()
{
    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.openFail = false;
    g_ioctlMockState.mockFd = TEST_MOCK_FD;
    g_ioctlMockState.failOnCallIndex = -1;
    g_ioctlMockState.ioctlErrno = EINVAL;
    g_ioctlMockState.ioctlCallCount = 0;
}

void ClawSandboxPolicyTest::TearDown()
{
    g_ioctlMockState.mockEnabled = false;
    g_ioctlMockState.openFail = true;
    g_ioctlMockState.failOnCallIndex = -1;
    g_ioctlMockState.ioctlCallCount = 0;
}

/**
 * @tc.name: AddOperationControlPolicies001
 * @tc.desc: AddOperationControlPolicies rejects an invalid device fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, AddOperationControlPolicies001, TestSize.Level0)
{
    std::vector<SandboxPolicyRuleGroup> ruleGroups = BuildRuleGroups(AllDynamicModulesPolicy().c_str());
    ASSERT_FALSE(ruleGroups.empty());

    EXPECT_EQ(SANDBOX_ERR_DEVICE_IO, AddOperationControlPolicies(-1, ruleGroups));
    EXPECT_EQ(0, g_ioctlMockState.ioctlCallCount);
}

/**
 * @tc.name: AddOperationControlPolicies002
 * @tc.desc: AddOperationControlPolicies succeeds without any ioctl when there are no rules
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, AddOperationControlPolicies002, TestSize.Level0)
{
    std::vector<SandboxPolicyRuleGroup> empty;
    EXPECT_EQ(SANDBOX_SUCCESS, AddOperationControlPolicies(TEST_MOCK_FD, empty));
    EXPECT_EQ(0, g_ioctlMockState.ioctlCallCount);
}

/**
 * @tc.name: AddOperationControlPolicies003
 * @tc.desc: AddOperationControlPolicies delivers one ioctl per configured module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, AddOperationControlPolicies003, TestSize.Level0)
{
    std::vector<SandboxPolicyRuleGroup> ruleGroups = BuildRuleGroups(AllDynamicModulesPolicy().c_str());
    ASSERT_FALSE(ruleGroups.empty());

    EXPECT_EQ(SANDBOX_SUCCESS, AddOperationControlPolicies(TEST_MOCK_FD, ruleGroups));
    // FILE and PROCESS: the two modules a dynamic policy may carry. Network is
    // refused at parse time by EnforcePhaseRules, so it never gets an ioctl.
    EXPECT_EQ(2, g_ioctlMockState.ioctlCallCount);
}

/**
 * @tc.name: AddOperationControlPolicies004
 * @tc.desc: AddOperationControlPolicies skips modules that carry no rules
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, AddOperationControlPolicies004, TestSize.Level0)
{
    std::vector<SandboxPolicyRuleGroup> ruleGroups = BuildRuleGroups(PROCESS_ONLY_POLICY);
    ASSERT_FALSE(ruleGroups.empty());

    EXPECT_EQ(SANDBOX_SUCCESS, AddOperationControlPolicies(TEST_MOCK_FD, ruleGroups));
    EXPECT_EQ(1, g_ioctlMockState.ioctlCallCount);
}

/**
 * @tc.name: AddSocketProtectionPolicy001
 * @tc.desc: No path and an invalid fd are both no-ops, not failures
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, AddSocketProtectionPolicy001, TestSize.Level0)
{
    EXPECT_EQ(SANDBOX_SUCCESS, AddSocketProtectionPolicy(TEST_MOCK_FD, ""));
    EXPECT_EQ(SANDBOX_SUCCESS, AddSocketProtectionPolicy(-1, "/tmp/whatever"));
    EXPECT_EQ(0, g_ioctlMockState.ioctlCallCount);
}

/**
 * @tc.name: AddSocketProtectionPolicy002
 * @tc.desc: A socket the sandbox cannot see needs no rule, and that is success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, AddSocketProtectionPolicy002, TestSize.Level0)
{
    // ENOENT means the path is outside the sandbox's view, so the child cannot
    // reach it either - nothing to protect, and nothing delivered.
    EXPECT_EQ(SANDBOX_SUCCESS,
        AddSocketProtectionPolicy(TEST_MOCK_FD, "/definitely/not/here/claw-ut.sock"));
    EXPECT_EQ(0, g_ioctlMockState.ioctlCallCount);
}

/**
 * @tc.name: AddSocketProtectionPolicy003
 * @tc.desc: A reachable path is delivered as exactly one ioctl of its own
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, AddSocketProtectionPolicy003, TestSize.Level0)
{
    // O_PATH opens anything that exists, so any real path exercises the path
    // this takes for a socket.
    EXPECT_EQ(SANDBOX_SUCCESS, AddSocketProtectionPolicy(TEST_MOCK_FD, "/"));
    EXPECT_EQ(1, g_ioctlMockState.ioctlCallCount);
}

/**
 * @tc.name: AddOperationControlPolicies008
 * @tc.desc: A rule whose path will not open is dropped and reported, and the
 *           request as a whole comes back partial
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, AddOperationControlPolicies008, TestSize.Level0)
{
    // The only rule points at a path that cannot exist. The kernel binds a rule
    // to an fd and has no path-string fallback, so the module is refused rather
    // than delivered without it.
    const char *MISSING_PATH_POLICY = R"({
        "AddOperationControlRuleGroups": [
            {
                "Scope": { "Type": "self_session" },
                "File": { "DefaultAction": "deny",
                          "DenyDelete": ["/definitely/not/here/claw-ut"] }
            }
        ]
    })";
    std::vector<SandboxPolicyRuleGroup> ruleGroups = BuildRuleGroups(MISSING_PATH_POLICY);
    ASSERT_FALSE(ruleGroups.empty());

    std::vector<PolicyScopeResult> results;
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_PARTIAL,
        AddOperationControlPolicies(TEST_MOCK_FD, ruleGroups, "", &results));
    ASSERT_EQ(1u, results.size());
    const std::vector<PolicyError> &errors = results[0].errors;

    ASSERT_EQ(1u, errors.size());
    EXPECT_EQ("open_failed", errors[0].reason);
    EXPECT_EQ("/definitely/not/here/claw-ut", errors[0].object);
    EXPECT_FALSE(errors[0].detail.empty());

    // Refused before delivery: nothing reached the device.
    EXPECT_EQ(0, g_ioctlMockState.ioctlCallCount);
}

/**
 * @tc.name: AddOperationControlPolicies009
 * @tc.desc: A conflict in one module does not hold back the modules that are
 *           free of it; the rejected one is named in delivered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, AddOperationControlPolicies009, TestSize.Level0)
{
    std::vector<SandboxPolicyRuleGroup> ruleGroups = BuildRuleGroups(FILE_CONFLICT_POLICY);
    ASSERT_FALSE(ruleGroups.empty());

    std::vector<PolicyScopeResult> results;
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_PARTIAL,
        AddOperationControlPolicies(TEST_MOCK_FD, ruleGroups, "", &results));
    ASSERT_EQ(1u, results.size());
    const std::vector<PolicyError> &errors = results[0].errors;
    const std::vector<PolicyModuleResult> &delivered = results[0].delivered;

    // One ioctl, not two: file never reached the device.
    EXPECT_EQ(1, g_ioctlMockState.ioctlCallCount);

    // File still appears, carrying its own verdict. Leaving it out would read
    // as "not configured", which is a different thing entirely.
    ASSERT_EQ(2u, delivered.size());
    EXPECT_EQ(DEC_POLICY_OP_TYPE_FILE, delivered[0].module);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, delivered[0].result);
    EXPECT_EQ(SANDBOX_SUCCESS, delivered[1].result);

    ASSERT_EQ(1u, errors.size());
    EXPECT_EQ("action_conflict", errors[0].reason);
    EXPECT_EQ("FileDelete", errors[0].operation);
}

/**
 * @tc.name: AddOperationControlPolicies010
 * @tc.desc: Even when nothing at all was delivered the verdict is partial, so
 *           that delivered can be carried back in the body
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, AddOperationControlPolicies010, TestSize.Level0)
{
    std::vector<SandboxPolicyRuleGroup> ruleGroups = BuildRuleGroups(FILE_CONFLICT_POLICY);
    ASSERT_FALSE(ruleGroups.empty());
    // Strip everything but the contradicting file rules.
    for (SandboxPolicyRuleGroup &group : ruleGroups) {
        group.hasProcess = false;
    }

    std::vector<PolicyScopeResult> results;
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_PARTIAL,
        AddOperationControlPolicies(TEST_MOCK_FD, ruleGroups, "", &results));
    ASSERT_EQ(1u, results.size());
    const std::vector<PolicyModuleResult> &delivered = results[0].delivered;
    EXPECT_EQ(0, g_ioctlMockState.ioctlCallCount);
    ASSERT_EQ(1u, delivered.size());
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, delivered[0].result);
    EXPECT_FALSE(delivered[0].detail.empty());
}

/**
 * @tc.name: AddOperationControlPolicies011
 * @tc.desc: A rule naming the protected path costs the file module only; process
 *           and network are unrelated and still go
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, AddOperationControlPolicies011, TestSize.Level0)
{
    std::vector<SandboxPolicyRuleGroup> ruleGroups = BuildRuleGroups(AllDynamicModulesPolicy().c_str());
    ASSERT_FALSE(ruleGroups.empty());

    // The one path the file rules already name, declared off limits.
    const std::string protectedPath = ExistingFilePath();

    std::vector<PolicyScopeResult> results;
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_PARTIAL,
        AddOperationControlPolicies(TEST_MOCK_FD, ruleGroups, protectedPath, &results));
    ASSERT_EQ(1u, results.size());
    const std::vector<PolicyError> &errors = results[0].errors;
    const std::vector<PolicyModuleResult> &delivered = results[0].delivered;

    // One ioctl, not two: only file was held back.
    EXPECT_EQ(1, g_ioctlMockState.ioctlCallCount);

    ASSERT_EQ(2u, delivered.size());
    EXPECT_EQ(DEC_POLICY_OP_TYPE_FILE, delivered[0].module);
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, delivered[0].result);
    EXPECT_EQ(SANDBOX_SUCCESS, delivered[1].result);

    ASSERT_EQ(1u, errors.size());
    EXPECT_EQ("protected_object", errors[0].reason);
    EXPECT_EQ(protectedPath, errors[0].object);
}

/**
 * @tc.name: AddOperationControlPolicies005
 * @tc.desc: A failing module does not stop the ones behind it, and the mix is
 *           reported as partial
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, AddOperationControlPolicies005, TestSize.Level0)
{
    std::vector<SandboxPolicyRuleGroup> ruleGroups = BuildRuleGroups(AllDynamicModulesPolicy().c_str());
    ASSERT_FALSE(ruleGroups.empty());

    std::vector<PolicyScopeResult> results;
    g_ioctlMockState.failOnCallIndex = 0;
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_PARTIAL,
        AddOperationControlPolicies(TEST_MOCK_FD, ruleGroups, "", &results));
    ASSERT_EQ(1u, results.size());
    const std::vector<PolicyModuleResult> &delivered = results[0].delivered;

    // All three were attempted even though the first one failed: the kernel
    // replaces a module's policy, so carrying on cannot compound the damage.
    EXPECT_EQ(2, g_ioctlMockState.ioctlCallCount);
    ASSERT_EQ(2u, delivered.size());
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_FAILED, delivered[0].result);
    EXPECT_EQ(SANDBOX_SUCCESS, delivered[1].result);
}

/**
 * @tc.name: AddOperationControlPolicies006
 * @tc.desc: AddOperationControlPolicies reports a failure raised by a later module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, AddOperationControlPolicies006, TestSize.Level0)
{
    std::vector<SandboxPolicyRuleGroup> ruleGroups = BuildRuleGroups(AllDynamicModulesPolicy().c_str());
    ASSERT_FALSE(ruleGroups.empty());

    std::vector<PolicyScopeResult> results;
    g_ioctlMockState.failOnCallIndex = 1;
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_PARTIAL,
        AddOperationControlPolicies(TEST_MOCK_FD, ruleGroups, "", &results));
    ASSERT_EQ(1u, results.size());
    const std::vector<PolicyModuleResult> &delivered = results[0].delivered;
    EXPECT_EQ(2, g_ioctlMockState.ioctlCallCount);
    ASSERT_EQ(2u, delivered.size());
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_FAILED, delivered[1].result);
}

/**
 * @tc.name: AddOperationControlPolicies007
 * @tc.desc: Every attempted module failing is still partial - the caller needs
 *           delivered, and only a partial result carries it
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, AddOperationControlPolicies007, TestSize.Level0)
{
    // One module configured, so "the only one failed" and "all of them failed"
    // are the same run.
    std::vector<SandboxPolicyRuleGroup> ruleGroups = BuildRuleGroups(PROCESS_ONLY_POLICY);
    ASSERT_FALSE(ruleGroups.empty());

    std::vector<PolicyScopeResult> results;
    g_ioctlMockState.failOnCallIndex = 0;
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_PARTIAL,
        AddOperationControlPolicies(TEST_MOCK_FD, ruleGroups, "", &results));
    ASSERT_EQ(1u, results.size());
    const std::vector<PolicyModuleResult> &delivered = results[0].delivered;
    EXPECT_EQ(1, g_ioctlMockState.ioctlCallCount);
    ASSERT_EQ(1u, delivered.size());
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_FAILED, delivered[0].result);
    // strerror text of the ioctl failure, not an error code repeated.
    EXPECT_FALSE(delivered[0].detail.empty());
}

/**
 * @tc.name: ParseOperationControlPolicy001
 * @tc.desc: ParseOperationControlPolicy accepts a valid rule group object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, ParseOperationControlPolicy001, TestSize.Level0)
{
    std::vector<SandboxPolicyRuleGroup> ruleGroups;
    EXPECT_EQ(SANDBOX_SUCCESS,
        CmdParser::ParseOperationControlPolicy(AllDynamicModulesPolicy(), ruleGroups));
    ASSERT_EQ(1u, ruleGroups.size());
    EXPECT_TRUE(ruleGroups[0].hasFile);
    EXPECT_TRUE(ruleGroups[0].hasProcess);
    EXPECT_FALSE(ruleGroups[0].hasNetwork);  // a dynamic policy cannot carry one
    EXPECT_EQ(DEC_POLICY_ACTION_ASK, ruleGroups[0].processRules.defaultAction);
}

/**
 * @tc.name: ParseOperationControlPolicy002
 * @tc.desc: ParseOperationControlPolicy rejects a body over the maximum policy length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, ParseOperationControlPolicy002, TestSize.Level0)
{
    std::string oversize(MAX_POLICY_JSON_LENGTH + 1, 'a');
    std::vector<SandboxPolicyRuleGroup> ruleGroups;
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
        CmdParser::ParseOperationControlPolicy(oversize, ruleGroups));
    EXPECT_TRUE(ruleGroups.empty());
}

/**
 * @tc.name: ParseOperationControlPolicy003
 * @tc.desc: ParseOperationControlPolicy rejects malformed JSON
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, ParseOperationControlPolicy003, TestSize.Level0)
{
    std::vector<SandboxPolicyRuleGroup> ruleGroups;
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
        CmdParser::ParseOperationControlPolicy("{not json", ruleGroups));
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
        CmdParser::ParseOperationControlPolicy("", ruleGroups));
}

/**
 * @tc.name: ParseOperationControlPolicy004
 * @tc.desc: ParseOperationControlPolicy rejects a JSON value that is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, ParseOperationControlPolicy004, TestSize.Level0)
{
    std::vector<SandboxPolicyRuleGroup> ruleGroups;
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
        CmdParser::ParseOperationControlPolicy("[1,2,3]", ruleGroups));
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
        CmdParser::ParseOperationControlPolicy("\"text\"", ruleGroups));
}

/**
 * @tc.name: ParseOperationControlPolicy005
 * @tc.desc: ParseOperationControlPolicy accepts an object without the rule group array
 *           and leaves the output untouched
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, ParseOperationControlPolicy005, TestSize.Level0)
{
    std::vector<SandboxPolicyRuleGroup> ruleGroups;
    EXPECT_EQ(SANDBOX_SUCCESS,
        CmdParser::ParseOperationControlPolicy("{\"Other\":1}", ruleGroups));
    EXPECT_TRUE(ruleGroups.empty());
}

/**
 * @tc.name: ParseOperationControlPolicy006
 * @tc.desc: ParseOperationControlPolicy rejects a rule group array element that is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, ParseOperationControlPolicy006, TestSize.Level0)
{
    const char *missingScope = R"({
        "AddOperationControlRuleGroups": [
            { "Process": { "DefaultAction": "ask", "DenyExecCmd": ["rm"] } }
        ]
    })";
    std::vector<SandboxPolicyRuleGroup> ruleGroups;
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
        CmdParser::ParseOperationControlPolicy(missingScope, ruleGroups));
    EXPECT_TRUE(ruleGroups.empty());

    const char *notAnArray = R"({ "AddOperationControlRuleGroups": {} })";
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
        CmdParser::ParseOperationControlPolicy(notAnArray, ruleGroups));
}

/**
 * @tc.name: ParseOperationControlPolicy007
 * @tc.desc: ParseOperationControlPolicy leaves a previous result untouched when parsing fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, ParseOperationControlPolicy007, TestSize.Level0)
{
    std::vector<SandboxPolicyRuleGroup> ruleGroups = BuildRuleGroups(PROCESS_ONLY_POLICY);
    ASSERT_EQ(1u, ruleGroups.size());

    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
        CmdParser::ParseOperationControlPolicy("{bad", ruleGroups));
    // The failed parse must not clear what the caller already held.
    EXPECT_EQ(1u, ruleGroups.size());
}

/**
 * @tc.name: ParseOperationControlPolicy008
 * @tc.desc: A policy arriving over the monitor socket may not carry a Network
 *           module: it parses as SANDBOX_POLICY_PARSE_DYNAMIC, and the network
 *           default action is fixed when the sandbox starts. Rejecting the whole
 *           document is what keeps a caller from believing it changed something
 *           that cannot be changed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, ParseOperationControlPolicy008, TestSize.Level0)
{
    const char *withNetwork = R"({
        "AddOperationControlRuleGroups": [
            {
                "Scope": { "Type": "self_session" },
                "Network": { "DefaultAction": "deny" }
            }
        ]
    })";
    std::vector<SandboxPolicyRuleGroup> ruleGroups;
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
        CmdParser::ParseOperationControlPolicy(withNetwork, ruleGroups));
    EXPECT_TRUE(ruleGroups.empty());

    // The rest of the document being valid does not save it: the group is
    // refused as a whole, not stripped of its Network module.
    const char *networkBesideFile = R"({
        "AddOperationControlRuleGroups": [
            {
                "Scope": { "Type": "self_session" },
                "Network": { "DefaultAction": "deny" },
                "File": { "DenyDelete": ["/data/test/a.txt"] }
            }
        ]
    })";
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
        CmdParser::ParseOperationControlPolicy(networkBesideFile, ruleGroups));
    EXPECT_TRUE(ruleGroups.empty());
}

/**
 * @tc.name: AddOperationControlPolicies012
 * @tc.desc: Every clash in one operation is reported, not just the first: the
 *           caller has to fix all of them, and one per round trip would make
 *           that N round trips
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, AddOperationControlPolicies012, TestSize.Level0)
{
    const char *THREE_CONFLICTS = R"({
        "AddOperationControlRuleGroups": [
            {
                "Scope": { "Type": "self_session" },
                "File": { "DenyDelete": ["/data/test/a", "/data/test/b", "/data/test/c"],
                          "AllowDelete": ["/data/test/a", "/data/test/b", "/data/test/c"] }
            }
        ]
    })";
    std::vector<SandboxPolicyRuleGroup> ruleGroups = BuildRuleGroups(THREE_CONFLICTS);
    ASSERT_FALSE(ruleGroups.empty());

    std::vector<PolicyScopeResult> results;
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_PARTIAL,
        AddOperationControlPolicies(TEST_MOCK_FD, ruleGroups, "", &results));
    ASSERT_EQ(1u, results.size());
    const std::vector<PolicyError> &errors = results[0].errors;

    ASSERT_EQ(3u, errors.size());
    for (const PolicyError &error : errors) {
        EXPECT_EQ("action_conflict", error.reason);
        EXPECT_EQ("FileDelete", error.operation);
        ASSERT_EQ(2u, error.actions.size());
    }
    // Each object named once, in the order the deny list was written.
    EXPECT_EQ("/data/test/a", errors[0].object);
    EXPECT_EQ("/data/test/b", errors[1].object);
    EXPECT_EQ("/data/test/c", errors[2].object);

    EXPECT_EQ(0, g_ioctlMockState.ioctlCallCount);
}

/**
 * @tc.name: AddOperationControlPolicies013
 * @tc.desc: Every path that will not open is reported, not just the first
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, AddOperationControlPolicies013, TestSize.Level0)
{
    const char *THREE_MISSING = R"({
        "AddOperationControlRuleGroups": [
            {
                "Scope": { "Type": "self_session" },
                "File": { "DenyDelete": ["/definitely/not/here/one",
                                         "/definitely/not/here/two",
                                         "/definitely/not/here/three"] }
            }
        ]
    })";
    std::vector<SandboxPolicyRuleGroup> ruleGroups = BuildRuleGroups(THREE_MISSING);
    ASSERT_FALSE(ruleGroups.empty());

    std::vector<PolicyScopeResult> results;
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_PARTIAL,
        AddOperationControlPolicies(TEST_MOCK_FD, ruleGroups, "", &results));
    ASSERT_EQ(1u, results.size());
    const std::vector<PolicyError> &errors = results[0].errors;

    ASSERT_EQ(3u, errors.size());
    for (const PolicyError &error : errors) {
        EXPECT_EQ("open_failed", error.reason);
        EXPECT_FALSE(error.detail.empty());
    }
    EXPECT_EQ("/definitely/not/here/one", errors[0].object);
    EXPECT_EQ("/definitely/not/here/two", errors[1].object);
    EXPECT_EQ("/definitely/not/here/three", errors[2].object);

    EXPECT_EQ(0, g_ioctlMockState.ioctlCallCount);
}

/**
 * @tc.name: AddOperationControlPolicies014
 * @tc.desc: A rule that spells the protected path differently is still refused.
 *           The kernel keys rules on the inode, so a string compare would let
 *           "/dir/./file" through and the newest rule would override the
 *           sandbox's own protection on its socket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxPolicyTest, AddOperationControlPolicies014, TestSize.Level0)
{
    const std::string real = ExistingFilePath();
    const size_t slash = real.rfind('/');
    ASSERT_NE(std::string::npos, slash);
    // Same file, different spelling: a "." component before the last one.
    const std::string spelled = real.substr(0, slash) + "/./" + real.substr(slash + 1);

    const std::string json = R"({
        "AddOperationControlRuleGroups": [
            {
                "Scope": { "Type": "self_session" },
                "File": { "AllowDelete": [")" + spelled + R"("] },
                "Process": { "DenyExecCmd": ["rm"] }
            }
        ]
    })";
    std::vector<SandboxPolicyRuleGroup> ruleGroups = BuildRuleGroups(json.c_str());
    ASSERT_FALSE(ruleGroups.empty());

    std::vector<PolicyScopeResult> results;
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_PARTIAL,
        AddOperationControlPolicies(TEST_MOCK_FD, ruleGroups, real, &results));
    ASSERT_EQ(1u, results.size());
    const std::vector<PolicyError> &errors = results[0].errors;

    ASSERT_EQ(1u, errors.size());
    EXPECT_EQ("protected_object", errors[0].reason);
    // Reported as the app wrote it, so it can find the rule in its own config.
    EXPECT_EQ(spelled, errors[0].object);

    // Only process reached the device.
    EXPECT_EQ(1, g_ioctlMockState.ioctlCallCount);
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
