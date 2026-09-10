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

#ifndef CLAW_SANDBOX_RESPONSE_H
#define CLAW_SANDBOX_RESPONSE_H

#include <cstdint>
#include <string>
#include <vector>

#include "sandbox_policy_result.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

/*
 * RESPONSE body envelope. Only RSP_PARTIAL carries a body, so type is what
 * tells the app which shape it is looking at; anything it does not recognise it
 * ignores whole, and the response code alone still says what happened.
 */
constexpr uint32_t SANDBOX_RESPONSE_BODY_VERSION = 1;
constexpr const char *SANDBOX_RESPONSE_TYPE_ADD_POLICY = "add_policy_result";

/*
 * Renders what the policy layer decided into the JSON the app reads.
 *
 * The mirror of TlvEventParser, which turns kernel TLV into JSON going the
 * other way. Static like it, and for the same reason: this is a pure mapping
 * from values to text, with no state worth keeping between calls.
 */
class ResponseBody {
public:
    /*
     * The body of a partial add-policy result.
     *
     * Only a partial result has one, and a partial result always has one: every
     * other outcome is fully described by the response code alone. So this
     * never returns early for lack of content - "" means the JSON could not be
     * built, and the caller still sends the response bare.
     *
     * type, version and groups are unconditional, and inside each group so are
     * scope, truncated, errors and delivered. An app that has to test for a
     * field's presence before reading it is an app that will eventually get it
     * wrong.
     */
    static std::string BuildAddPolicyResult(const std::vector<PolicyScopeResult> &results);
};

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS

#endif // CLAW_SANDBOX_RESPONSE_H
