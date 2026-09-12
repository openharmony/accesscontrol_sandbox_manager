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

#include "sandbox_response.h"

#include <algorithm>

#include "cJSON.h"
#include "sandbox_log.h"
#include "sandbox_policy.h"
#include "sandbox_socket.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

/*
 * How many rejection reasons one response body carries. A policy can be wrong
 * in as many places as it has rules, and the body has to stay well inside
 * MAX_BODY_LENGTH; past this the app has more than enough to work with.
 */
constexpr size_t MAX_RESPONSE_ERROR_COUNT = 64;

// Fields that do not apply to this reason are omitted rather than sent empty,
// so the app can tell "not applicable" from "applicable but blank".
static bool AddOptionalString(cJSON *item, const char *name, const std::string &value)
{
    return value.empty() || cJSON_AddStringToObject(item, name, value.c_str()) != nullptr;
}

/*
 * One rejection reason as a JSON object. Returns null on failure, having freed
 * whatever it built.
 */
static cJSON *BuildPolicyErrorJson(const PolicyError &error)
{
    cJSON *item = cJSON_CreateObject();
    if (item == nullptr) {
        return nullptr;
    }

    if (cJSON_AddStringToObject(item, "reason", error.reason.c_str()) == nullptr ||
        !AddOptionalString(item, "operation", error.operation) ||
        !AddOptionalString(item, "object", error.object) ||
        !AddOptionalString(item, "detail", error.detail)) {
        cJSON_Delete(item);
        return nullptr;
    }

    if (error.actions.empty()) {
        return item;
    }

    cJSON *actions = cJSON_CreateArray();
    if (actions == nullptr || !cJSON_AddItemToObject(item, "actions", actions)) {
        // item has not taken actions over yet, and Delete tolerates a null.
        cJSON_Delete(actions);
        cJSON_Delete(item);
        return nullptr;
    }

    for (const std::string &action : error.actions) {
        cJSON *value = cJSON_CreateString(action.c_str());
        if (value == nullptr || !cJSON_AddItemToArray(actions, value)) {
            cJSON_Delete(value);
            cJSON_Delete(item);
            return nullptr;
        }
    }

    return item;
}

// Per-module delivery verdicts, each result translated on the way out so no
// internal code reaches the app through the body either.
static bool AppendDeliveredJson(cJSON *root, const std::vector<PolicyModuleResult> &delivered)
{
    cJSON *array = cJSON_CreateArray();
    if (array == nullptr || !cJSON_AddItemToObject(root, "delivered", array)) {
        cJSON_Delete(array);
        return false;
    }

    for (const PolicyModuleResult &entry : delivered) {
        cJSON *item = cJSON_CreateObject();
        if (item == nullptr || !cJSON_AddItemToArray(array, item)) {
            cJSON_Delete(item);
            return false;
        }
        if (cJSON_AddStringToObject(item, "module", PolicyModuleName(entry.module)) == nullptr ||
            cJSON_AddNumberToObject(item, "result", ToResponseCode(entry.result)) == nullptr) {
            return false;
        }
        if (!AddOptionalString(item, "detail", entry.detail)) {
            return false;
        }
    }

    return true;
}

/*
 * Render why an add-policy request was rejected, as the response body.
 *
 * Returns an empty string when there is nothing to report or the JSON could not
 * be built. That is deliberate rather than an error path: the body is detail,
 * and the response itself must go out either way.
 */
// One rule group: its scope, its errors and its per-module verdicts.
static cJSON *BuildScopeResultJson(const PolicyScopeResult &result)
{
    cJSON *item = cJSON_CreateObject();
    if (item == nullptr) {
        return nullptr;
    }

    cJSON *errorArray = cJSON_CreateArray();
    if (errorArray == nullptr || !cJSON_AddItemToObject(item, "errors", errorArray)) {
        cJSON_Delete(errorArray);
        cJSON_Delete(item);
        return nullptr;
    }

    const size_t reported = std::min(result.errors.size(), MAX_RESPONSE_ERROR_COUNT);
    bool built =
        cJSON_AddStringToObject(item, "scope", PolicyScopeName(result.scope)) != nullptr &&
        cJSON_AddBoolToObject(item, "truncated", reported < result.errors.size()) != nullptr;

    for (size_t i = 0; built && i < reported; ++i) {
        cJSON *error = BuildPolicyErrorJson(result.errors[i]);
        if (error == nullptr || !cJSON_AddItemToArray(errorArray, error)) {
            cJSON_Delete(error);
            built = false;
        }
    }

    if (built) {
        built = AppendDeliveredJson(item, result.delivered);
    }
    if (!built) {
        cJSON_Delete(item);
        return nullptr;
    }
    return item;
}

std::string ResponseBody::BuildAddPolicyResult(const std::vector<PolicyScopeResult> &results)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        return "";
    }

    cJSON *groupArray = cJSON_CreateArray();
    if (groupArray == nullptr || !cJSON_AddItemToObject(root, "groups", groupArray)) {
        cJSON_Delete(groupArray);
        cJSON_Delete(root);
        return "";
    }

    bool built =
        cJSON_AddStringToObject(root, "type", SANDBOX_RESPONSE_TYPE_ADD_POLICY) != nullptr &&
        cJSON_AddNumberToObject(root, "version", SANDBOX_RESPONSE_BODY_VERSION) != nullptr;

    for (const PolicyScopeResult &result : results) {
        if (!built) {
            break;
        }
        cJSON *item = BuildScopeResultJson(result);
        if (item == nullptr || !cJSON_AddItemToArray(groupArray, item)) {
            cJSON_Delete(item);
            built = false;
        }
    }

    char *jsonStr = built ? cJSON_PrintUnformatted(root) : nullptr;
    std::string body;
    if (jsonStr != nullptr) {
        body = jsonStr;
        cJSON_free(jsonStr);
    } else {
        SANDBOX_LOGE("Failed to render the add policy result, answering without a body");
    }

    cJSON_Delete(root);
    return body;
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
