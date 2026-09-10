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

#ifndef CLAW_SANDBOX_LIMITS_H
#define CLAW_SANDBOX_LIMITS_H

#include <cstddef>

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

constexpr size_t MAX_POLICY_JSON_LENGTH = 102400;
constexpr size_t MAX_EVENT_ANSWER_JSON_LENGTH = 256;

/*
 * Largest socket message body.
 */
constexpr size_t MAX_BODY_LENGTH = 100 * 1024;
constexpr size_t SOCKET_HEADER_LENGTH = 40;
constexpr size_t MAX_TX_BUFFER_SIZE = MAX_BODY_LENGTH + SOCKET_HEADER_LENGTH;

/*
 * The monitor's table caps. Here rather than file local in sandbox_monitor.cpp
 * because the unit tests assert against them: they used to keep their own copies
 * and one silently drifted, which turned a shrunk queue into a crash rather than
 * a failed assertion.
 */
constexpr size_t MAX_PENDING_ANSWER_COUNT = 256;
constexpr size_t MAX_SOCKET_TX_QUEUE_COUNT = 64;
// Just above MAX_BODY_LENGTH, as the static_assert below requires. An eviction
// threshold, not a reservation.
constexpr size_t MAX_SOCKET_TX_QUEUE_BYTES = 128 * 1024;

/*
 * The queue has to be able to hold anything the socket would have accepted,
 * otherwise PushSocketMessage would refuse a message that SendMessage was
 * willing to send - the same event would then be delivered or dropped purely
 * depending on whether the channel happened to be busy.
 */
static_assert(MAX_BODY_LENGTH <= MAX_SOCKET_TX_QUEUE_BYTES,
    "The Tx queue must fit any message the socket layer accepts");

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS

#endif // CLAW_SANDBOX_LIMITS_H
