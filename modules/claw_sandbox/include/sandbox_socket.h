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

#ifndef SANDBOX_SOCKET_H
#define SANDBOX_SOCKET_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <sys/types.h>
#include <vector>

#include "sandbox_error.h"
#include "sandbox_limits.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

constexpr uint32_t SANDBOX_SOCKET_MAGIC = 0x53424F58; // SBOX
constexpr uint32_t SANDBOX_SOCKET_VERSION = 1;

// Underlying type matches MessageHeader::msgType, so comparing the two does
// not mix signedness. 0 is left unused: a zeroed header should not name a type.
enum SandboxSocketMessageType : uint32_t {
    SANDBOX_SOCKET_MSG_ADD_POLICY = 1,
    SANDBOX_SOCKET_MSG_EVENT_ANSWER = 2,
    SANDBOX_SOCKET_MSG_EVENT_REPORT = 3,
    SANDBOX_SOCKET_MSG_RESPONSE = 4,
};

/*
 * Response code layout, in the 32 bits MessageHeader::result carries:
 *
 *   31..16  RESPONSE_CODE_PREFIX, fixed. It is also what makes the value
 *           negative once cast, so a code can never be read as SANDBOX_RSP_OK.
 *   15.. 8  category - what kind of failure, and so what the app should do.
 *    7.. 0  index    - which failure inside that category.
 *
 * One byte each, so a category or index past 0xFF would run into the field
 * above it. Every code here is a hand-written small constant, and the assert
 * below keeps the prefix from growing into them.
 */
constexpr uint32_t RESPONSE_CODE_PREFIX = 0xFFFF0000U;
constexpr uint32_t RESPONSE_CODE_CATEGORY_SHIFT = 8;
constexpr uint32_t RESPONSE_CODE_INDEX_MASK = 0xFFU;
constexpr uint32_t RESPONSE_CODE_CATEGORY_MASK =
    RESPONSE_CODE_INDEX_MASK << RESPONSE_CODE_CATEGORY_SHIFT;

static_assert((RESPONSE_CODE_PREFIX & RESPONSE_CODE_CATEGORY_MASK) == 0 &&
              (RESPONSE_CODE_PREFIX & RESPONSE_CODE_INDEX_MASK) == 0,
    "The response code prefix must leave the category and index fields clear");

// Assemble one code. The single place the unsigned literal becomes the signed
// int32_t that MessageHeader::result carries, so the conversion stays visible
// instead of happening implicitly wherever a code is used.
constexpr int32_t MakeResponseCode(uint32_t category, uint32_t index)
{
    return static_cast<int32_t>(RESPONSE_CODE_PREFIX |
        (category << RESPONSE_CODE_CATEGORY_SHIFT) | index);
}

enum SandboxResponseCode : int32_t {
    SANDBOX_RSP_OK = 0,

    // 0x01 - the request itself is wrong. Fix it and send again.
    SANDBOX_RSP_BAD_REQUEST      = MakeResponseCode(0x01, 0x01),
    SANDBOX_RSP_BAD_REQUEST_ID   = MakeResponseCode(0x01, 0x02),
    SANDBOX_RSP_UNSUPPORTED_TYPE = MakeResponseCode(0x01, 0x03),
    // 0x01 0x04 - the declared body length is over this type's limit. Distinct
    // from BAD_REQUEST because the fix is different: send less, not send valid.
    SANDBOX_RSP_BODY_TOO_LARGE   = MakeResponseCode(0x01, 0x04),

    // 0x02 - the request was fine, the state is not. Resending cannot help;
    // the app should update whatever it is tracking.
    SANDBOX_RSP_UNKNOWN_EVENT    = MakeResponseCode(0x02, 0x01),
    SANDBOX_RSP_UNAVAILABLE      = MakeResponseCode(0x02, 0x02),

    // 0x03 - transient. Resend the same request later.
    SANDBOX_RSP_BUSY             = MakeResponseCode(0x03, 0x01),

    // 0x04 - the sandbox side broke. Nothing the app can do about it.
    SANDBOX_RSP_INTERNAL         = MakeResponseCode(0x04, 0x01),

    // 0x05 - some of it applied. The body says which; the header cannot. The
    // only category whose handling requires reading the body.
    SANDBOX_RSP_PARTIAL          = MakeResponseCode(0x05, 0x01),
};

struct ResponseCodeMapping {
    int internalError;
    int32_t responseCode;
};

/*
 * Every internal error the app is ever told apart from the rest. Anything not
 * listed becomes SANDBOX_RSP_INTERNAL, so adding an internal code cannot widen
 * the wire contract by accident.
 *
 * Next to the wire codes rather than beside the one function that reads it: a
 * new SandboxError has to be considered here, and a table buried in a .cpp is
 * one nobody thinks to open.
 */
inline constexpr ResponseCodeMapping RESPONSE_CODE_TABLE[] = {
    {SANDBOX_SUCCESS,                  SANDBOX_RSP_OK},
    // The request itself is wrong.
    {SANDBOX_ERR_REQUEST_ID_INVALID,   SANDBOX_RSP_BAD_REQUEST_ID},
    {SANDBOX_ERR_SOCKET_PROTOCOL,      SANDBOX_RSP_UNSUPPORTED_TYPE},
    {SANDBOX_ERR_EVENT_ANSWER_INVALID, SANDBOX_RSP_BAD_REQUEST},
    {SANDBOX_ERR_CONFIG_INVALID,       SANDBOX_RSP_BAD_REQUEST},
    {SANDBOX_ERR_SOCKET_MSG_TOO_LARGE, SANDBOX_RSP_BODY_TOO_LARGE},
    // The request was fine, the state is not.
    {SANDBOX_ERR_EVENT_UNKNOWN,        SANDBOX_RSP_UNKNOWN_EVENT},
    {SANDBOX_ERR_MONITOR_DEGRADED,     SANDBOX_RSP_UNAVAILABLE},
    // Transient.
    {SANDBOX_ERR_DEVICE_BUSY,          SANDBOX_RSP_BUSY},
    // Applied in part. The only code whose handling requires the body.
    {SANDBOX_ERR_SET_POLICY_PARTIAL,   SANDBOX_RSP_PARTIAL},
};

// Internal error to wire code. An unlisted code collapses to INTERNAL; the real
// value is logged at the call site, so nothing the app could act on is lost.
constexpr int32_t ToResponseCode(int internalError)
{
    for (const ResponseCodeMapping &entry : RESPONSE_CODE_TABLE) {
        if (entry.internalError == internalError) {
            return entry.responseCode;
        }
    }

    return SANDBOX_RSP_INTERNAL;
}

static_assert(ToResponseCode(SANDBOX_SUCCESS) == SANDBOX_RSP_OK,
    "Success must never render as a failure");

// Outcome of one read step. DRAINED is the fd saying EAGAIN, which ends the
// epoll pass rather than the connection; readError_ carries the reason for
// FAILED.
enum class ReadStep {
    PROGRESSED,
    DRAINED,
    FAILED,
};

enum SocketReadState {
    SOCKET_STATE_READING_HEADER,
    SOCKET_STATE_READING_BODY,
    // Body is over its limit: consume and throw it away, so the stream stays
    // framed and the peer still gets an answer.
    SOCKET_STATE_DISCARDING_BODY
};

struct MessageHeader {
    uint32_t magic;
    // Bump on any layout change below, reserved included: nothing else catches
    // a peer built against a different definition of this struct.
    uint32_t version;
    uint32_t bodyLength;
    uint32_t msgType;
    uint32_t requestId;
    int32_t result;
    // Room to add fields without moving the ones above or changing the size.
    uint8_t reserved[16];
} __attribute__((packed));

static_assert(sizeof(MessageHeader) == 40, "Invalid MessageHeader size");

static_assert(sizeof(MessageHeader) == SOCKET_HEADER_LENGTH,
    "MAX_TX_BUFFER_SIZE is built from SOCKET_HEADER_LENGTH; keep the two in step");

/*
 * What goes into the Tx buffer is a whole frame, not just a body. Miss the
 * header here and a maximal message is refused with SANDBOX_ERR_SOCKET_TX_FULL
 * on an empty buffer - which the monitor reads as "retry on the next EPOLLOUT",
 * so it would sit at the head of the queue forever, blocking everything behind
 * it, with no error reported anywhere.
 */
static_assert(MAX_BODY_LENGTH + sizeof(MessageHeader) <= MAX_TX_BUFFER_SIZE,
    "A single legal message must always be queueable on an empty Tx buffer");

struct ParsedMessage {
    MessageHeader header;
    std::string body;
    // SANDBOX_SUCCESS when body holds the message. Otherwise the frame was read
    // and dropped, and this is what the peer must be told; body is empty.
    int rejectReason = SANDBOX_SUCCESS;
};

class SandboxSocket {
public:
    // Takes ownership of fd.
    // The fd must be a connected non-blocking Unix Domain Socket.
    explicit SandboxSocket(int fd);
    ~SandboxSocket();

    SandboxSocket(const SandboxSocket &other) = delete;
    SandboxSocket &operator=(const SandboxSocket &other) = delete;

    /*
     * Called when epoll indicates the socket is readable.
     *
     * This function consumes all currently readable data until EAGAIN.
     * Multiple complete messages may be returned in outMessages.
     */
    int OnReadable(std::vector<ParsedMessage> &outMessages);

    /*
     * Queue a message for transmission.
     *
     * SANDBOX_SUCCESS means the message has been accepted for sending.
     * The message may still be buffered internally if the non-blocking
     * socket cannot send all data immediately.
     */
    int SendMessage(uint32_t msgType, const std::string &body);

    // Queue a fixed-header response. The response has no body, echoes the
    // request ID, and carries the processing result in MessageHeader::result.
    // Answer one request. The body is optional detail about the result; the
    // result field alone is always enough to act on, so a peer that cannot
    // parse the body can still handle the response.
    int SendResponse(uint32_t requestId, int32_t result, const std::string &body = "");

    /*
     * Called when epoll indicates the socket is writable.
     *
     * This function tries to flush all pending Tx data until the buffer
     * becomes empty or the socket returns EAGAIN.
     */
    int OnWritable();

    // Used by the upper epoll layer to determine whether EPOLLOUT
    // should be monitored.
    bool HasPendingTxData() const;

    // Returns the owned connected socket fd.
    int GetFd() const;

private:
    // One read each, resumable. PROGRESSED covers a partial message as well as
    // a whole one.
    ReadStep ProcessHeader(std::vector<ParsedMessage> &outMessages);
    ReadStep ProcessBody(std::vector<ParsedMessage> &outMessages);
    ReadStep DiscardBody(std::vector<ParsedMessage> &outMessages);
    // Is this our stream at all: magic and version, nothing type specific.
    int ValidateProtocol() const;
    // Whether the declared body length is acceptable for this message type.
    int ValidateBodyLength() const;
    int QueueMessage(uint32_t msgType, const std::string &body,
        uint32_t requestId, int32_t result);

    int FlushTxBuffer();

    void ResetReadState();
    void CompactTxBuffer(size_t appendLength);

private:
    int fd_;

    // --- Rx (Receive) State Machine Variables ---
    SocketReadState readState_;
    MessageHeader currentHeader_;
    size_t headerBytesRead_;
    std::string currentBodyBuffer_;
    size_t bodyBytesRead_;
    // Bytes of an over-long body still to be consumed and dropped.
    size_t bodyBytesToDiscard_;
    // Why the last step returned FAILED.
    int readError_ = SANDBOX_SUCCESS;

    /*
     * --- Tx (Transmit) Buffer ---
     *
     * txOffset_ points to the first byte that has not been sent yet.
     *
     * [ already sent ][        pending data        ]
     *                 ^
     *             txOffset_
     */
    std::string txBuffer_;
    size_t txOffset_;
};

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS

#endif // SANDBOX_SOCKET_H
