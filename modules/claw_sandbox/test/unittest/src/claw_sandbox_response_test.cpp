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

#include "claw_sandbox_response_test.h"
#include "sandbox_error.h"
#include "sandbox_policy.h"
#include "sandbox_response.h"
#include "sandbox_socket.h"

#include <string>
#include <vector>

#include "cJSON.h"

/*
 * Last on purpose. sandbox_log.h #undefs LOG_TAG and LOG_DOMAIN and redefines
 * them, and those are plain macros read where SANDBOX_LOGx is written, not
 * settings applied once.
 */
#include "sandbox_log.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

namespace {
// Parses the body and hands back the root, so each test can assert on fields
// without repeating the null checks. Caller owns the result.
cJSON *ParseBody(const std::string &body)
{
    return body.empty() ? nullptr : cJSON_Parse(body.c_str());
}

std::string StringField(cJSON *object, const char *name)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
    return (cJSON_IsString(item) && item->valuestring != nullptr) ? item->valuestring : "";
}

bool HasField(cJSON *object, const char *name)
{
    return cJSON_GetObjectItemCaseSensitive(object, name) != nullptr;
}

int32_t NumberField(cJSON *object, const char *name)
{
    return static_cast<int32_t>(
        cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(object, name)));
}

/*
 * Every test below describes one rule group, so these two keep the assertions
 * about the group's own fields instead of restating the groups array each time.
 */
std::string BuildOneGroup(const std::vector<PolicyError> &errors,
    const std::vector<PolicyModuleResult> &delivered)
{
    PolicyScopeResult result;
    result.scope = DEC_POLICY_SCOPE_TYPE_SELF_SESSION;
    result.errors = errors;
    result.delivered = delivered;
    return ResponseBody::BuildAddPolicyResult({result});
}

cJSON *FirstGroup(cJSON *root)
{
    return cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(root, "groups"), 0);
}
} // namespace

void ClawSandboxResponseTest::SetUpTestCase() {}
void ClawSandboxResponseTest::TearDownTestCase() {}
void ClawSandboxResponseTest::SetUp() {}
void ClawSandboxResponseTest::TearDown() {}

/**
 * @tc.name: ResponseBodyEnvelope001
 * @tc.desc: The envelope fields are unconditional, top level and per group, so
 *           the app never has to test for a key before reading it
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxResponseTest, ResponseBodyEnvelope001, TestSize.Level0)
{
    const std::vector<PolicyError> errors = {PolicyError::OpenFailed("/data/x", "No such file")};
    const std::vector<PolicyModuleResult> delivered = {
        PolicyModuleResult {.module = DEC_POLICY_OP_TYPE_FILE, .result = SANDBOX_SUCCESS, .detail = ""},
    };

    cJSON *root = ParseBody(BuildOneGroup(errors, delivered));
    ASSERT_NE(nullptr, root);

    EXPECT_EQ(std::string(SANDBOX_RESPONSE_TYPE_ADD_POLICY), StringField(root, "type"));
    EXPECT_EQ(static_cast<int32_t>(SANDBOX_RESPONSE_BODY_VERSION), NumberField(root, "version"));
    ASSERT_TRUE(cJSON_IsArray(cJSON_GetObjectItemCaseSensitive(root, "groups")));

    cJSON *group = FirstGroup(root);
    ASSERT_NE(nullptr, group);
    EXPECT_EQ("self_session", StringField(group, "scope"));
    EXPECT_TRUE(HasField(group, "truncated"));
    EXPECT_TRUE(cJSON_IsArray(cJSON_GetObjectItemCaseSensitive(group, "errors")));
    EXPECT_TRUE(cJSON_IsArray(cJSON_GetObjectItemCaseSensitive(group, "delivered")));

    cJSON_Delete(root);
}

/**
 * @tc.name: ResponseBodyEnvelope002
 * @tc.desc: Both arrays are present even when one of them is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxResponseTest, ResponseBodyEnvelope002, TestSize.Level0)
{
    // The shape a failed ioctl produces: no rule is individually at fault, so
    // errors is empty and the whole story is in delivered. An app that tests
    // "are there errors" by the key's presence would report success here.
    const std::vector<PolicyModuleResult> delivered = {
        PolicyModuleResult {.module = DEC_POLICY_OP_TYPE_NETWORK,
            .result = SANDBOX_ERR_SET_POLICY_FAILED, .detail = "Permission denied"},
    };

    cJSON *root = ParseBody(BuildOneGroup({}, delivered));
    ASSERT_NE(nullptr, root);

    cJSON *errors = cJSON_GetObjectItemCaseSensitive(FirstGroup(root), "errors");
    ASSERT_TRUE(cJSON_IsArray(errors));
    EXPECT_EQ(0, cJSON_GetArraySize(errors));
    EXPECT_EQ(1, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(FirstGroup(root), "delivered")));

    cJSON_Delete(root);
}

/**
 * @tc.name: ResponseBodyError001
 * @tc.desc: action_conflict carries operation and both actions, and no detail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxResponseTest, ResponseBodyError001, TestSize.Level0)
{
    const std::vector<PolicyError> errors = {
        PolicyError::ActionConflict("FileDelete", "/data/foo", "deny", "allow"),
    };

    cJSON *root = ParseBody(BuildOneGroup(errors, {}));
    ASSERT_NE(nullptr, root);

    cJSON *first = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(FirstGroup(root), "errors"), 0);
    ASSERT_NE(nullptr, first);
    EXPECT_EQ("action_conflict", StringField(first, "reason"));
    EXPECT_EQ("FileDelete", StringField(first, "operation"));
    EXPECT_EQ("/data/foo", StringField(first, "object"));
    // Not applicable, so omitted rather than sent empty.
    EXPECT_FALSE(HasField(first, "detail"));

    cJSON *actions = cJSON_GetObjectItemCaseSensitive(first, "actions");
    ASSERT_TRUE(cJSON_IsArray(actions));
    ASSERT_EQ(2, cJSON_GetArraySize(actions));
    // Encounter order, so the app can tell which one was declared first.
    EXPECT_STREQ("deny", cJSON_GetArrayItem(actions, 0)->valuestring);
    EXPECT_STREQ("allow", cJSON_GetArrayItem(actions, 1)->valuestring);

    cJSON_Delete(root);
}

/**
 * @tc.name: ResponseBodyError002
 * @tc.desc: open_failed carries detail and no operation or actions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxResponseTest, ResponseBodyError002, TestSize.Level0)
{
    const std::vector<PolicyError> errors = {
        PolicyError::OpenFailed("/data/missing", "No such file or directory"),
    };

    cJSON *root = ParseBody(BuildOneGroup(errors, {}));
    ASSERT_NE(nullptr, root);

    cJSON *first = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(FirstGroup(root), "errors"), 0);
    ASSERT_NE(nullptr, first);
    EXPECT_EQ("open_failed", StringField(first, "reason"));
    EXPECT_EQ("/data/missing", StringField(first, "object"));
    EXPECT_EQ("No such file or directory", StringField(first, "detail"));
    EXPECT_FALSE(HasField(first, "operation"));
    EXPECT_FALSE(HasField(first, "actions"));

    cJSON_Delete(root);
}

/**
 * @tc.name: ResponseBodyError003
 * @tc.desc: protected_object carries operation as well as detail - the field
 *           combination the documentation once got wrong
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxResponseTest, ResponseBodyError003, TestSize.Level0)
{
    const std::vector<PolicyError> errors = {
        PolicyError::ProtectedObject("FileDelete", "/data/storage/el2/base/app.sock"),
    };

    cJSON *root = ParseBody(BuildOneGroup(errors, {}));
    ASSERT_NE(nullptr, root);

    cJSON *first = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(FirstGroup(root), "errors"), 0);
    ASSERT_NE(nullptr, first);
    EXPECT_EQ("protected_object", StringField(first, "reason"));
    // Present, unlike what "operation belongs to action_conflict only" would say.
    EXPECT_EQ("FileDelete", StringField(first, "operation"));
    EXPECT_EQ("/data/storage/el2/base/app.sock", StringField(first, "object"));
    // The wording is part of the wire contract, fixed by the factory.
    EXPECT_EQ("the monitor socket is protected by the sandbox", StringField(first, "detail"));
    EXPECT_FALSE(HasField(first, "actions"));

    cJSON_Delete(root);
}

/**
 * @tc.name: ResponseBodyTruncated001
 * @tc.desc: Errors past the cap are dropped and the body says so
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxResponseTest, ResponseBodyTruncated001, TestSize.Level0)
{
    constexpr int REPORTED_LIMIT = 64;

    std::vector<PolicyError> atLimit;
    for (int i = 0; i < REPORTED_LIMIT; ++i) {
        atLimit.push_back(PolicyError::OpenFailed("/data/" + std::to_string(i), "gone"));
    }

    cJSON *root = ParseBody(BuildOneGroup(atLimit, {}));
    ASSERT_NE(nullptr, root);
    EXPECT_TRUE(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(FirstGroup(root), "truncated")));
    EXPECT_EQ(REPORTED_LIMIT, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(FirstGroup(root), "errors")));
    cJSON_Delete(root);

    std::vector<PolicyError> overLimit = atLimit;
    overLimit.push_back(PolicyError::OpenFailed("/data/one_too_many", "gone"));

    root = ParseBody(BuildOneGroup(overLimit, {}));
    ASSERT_NE(nullptr, root);
    EXPECT_TRUE(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(FirstGroup(root), "truncated")));
    // The extra one is dropped outright: there is no continuation of any kind.
    EXPECT_EQ(REPORTED_LIMIT, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(FirstGroup(root), "errors")));
    cJSON_Delete(root);
}

/**
 * @tc.name: ResponseBodyDelivered001
 * @tc.desc: Every module is listed with its own verdict, successes included,
 *           and internal codes are translated to the wire ones
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxResponseTest, ResponseBodyDelivered001, TestSize.Level0)
{
    const std::vector<PolicyModuleResult> delivered = {
        PolicyModuleResult {.module = DEC_POLICY_OP_TYPE_FILE,
            .result = SANDBOX_ERR_CONFIG_INVALID, .detail = "refused before delivery"},
        PolicyModuleResult {.module = DEC_POLICY_OP_TYPE_PROCESS,
            .result = SANDBOX_SUCCESS, .detail = ""},
        PolicyModuleResult {.module = DEC_POLICY_OP_TYPE_NETWORK,
            .result = SANDBOX_ERR_SET_POLICY_FAILED, .detail = "Permission denied"},
    };

    cJSON *root = ParseBody(BuildOneGroup({}, delivered));
    ASSERT_NE(nullptr, root);

    cJSON *array = cJSON_GetObjectItemCaseSensitive(FirstGroup(root), "delivered");
    ASSERT_TRUE(cJSON_IsArray(array));
    ASSERT_EQ(3, cJSON_GetArraySize(array));

    // Refused by the monitor: the app must be able to tell this from a kernel
    // rejection, because only one of the two is worth retrying.
    cJSON *file = cJSON_GetArrayItem(array, 0);
    EXPECT_EQ("file", StringField(file, "module"));
    EXPECT_EQ(SANDBOX_RSP_BAD_REQUEST, NumberField(file, "result"));
    EXPECT_EQ("refused before delivery", StringField(file, "detail"));

    // Live in the kernel. No detail, so the key is absent.
    cJSON *process = cJSON_GetArrayItem(array, 1);
    EXPECT_EQ("process", StringField(process, "module"));
    EXPECT_EQ(0, NumberField(process, "result"));
    EXPECT_FALSE(HasField(process, "detail"));

    // Rejected by the kernel; detail is the errno text.
    cJSON *network = cJSON_GetArrayItem(array, 2);
    EXPECT_EQ("network", StringField(network, "module"));
    EXPECT_EQ(SANDBOX_RSP_INTERNAL, NumberField(network, "result"));
    EXPECT_EQ("Permission denied", StringField(network, "detail"));

    cJSON_Delete(root);
}

/**
 * @tc.name: ResponseBodyEnvelope003
 * @tc.desc: One entry per rule group, each carrying its own scope, errors and
 *           verdicts - an error on its own does not say which group it came from
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxResponseTest, ResponseBodyEnvelope003, TestSize.Level0)
{
    PolicyScopeResult first;
    first.scope = DEC_POLICY_SCOPE_TYPE_SELF_SESSION;
    first.errors = {PolicyError::OpenFailed("/data/x", "No such file")};
    first.delivered = {PolicyModuleResult {.module = DEC_POLICY_OP_TYPE_FILE,
        .result = SANDBOX_ERR_PATH_INVALID, .detail = "a rule path could not be opened"}};

    PolicyScopeResult second;
    second.scope = DEC_POLICY_SCOPE_TYPE_SELF_APP;
    second.delivered = {PolicyModuleResult {.module = DEC_POLICY_OP_TYPE_PROCESS,
        .result = SANDBOX_SUCCESS, .detail = ""}};

    cJSON *root = ParseBody(ResponseBody::BuildAddPolicyResult({first, second}));
    ASSERT_NE(nullptr, root);

    cJSON *groups = cJSON_GetObjectItemCaseSensitive(root, "groups");
    ASSERT_TRUE(cJSON_IsArray(groups));
    ASSERT_EQ(2, cJSON_GetArraySize(groups));

    cJSON *a = cJSON_GetArrayItem(groups, 0);
    EXPECT_EQ("self_session", StringField(a, "scope"));
    EXPECT_EQ(1, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(a, "errors")));

    // The second group carries no error, and its arrays are still both there.
    cJSON *b = cJSON_GetArrayItem(groups, 1);
    EXPECT_EQ("self_app", StringField(b, "scope"));
    EXPECT_EQ(0, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(b, "errors")));
    EXPECT_EQ(1, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(b, "delivered")));

    cJSON_Delete(root);
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
