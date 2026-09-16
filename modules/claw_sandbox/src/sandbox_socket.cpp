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

#include "sandbox_socket.h"
#include "sandbox_error.h"
#include "sandbox_limits.h"
#include "sandbox_log.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

SandboxSocket::SandboxSocket(int fd) : fd_(fd), readState_(SOCKET_STATE_READING_HEADER), currentHeader_{},
    headerBytesRead_(0), bodyBytesRead_(0), bodyBytesToDiscard_(0), txOffset_(0)
{
    /*
     * Taking ownership is what claims the fd, so the tag goes on here rather than
     * at the caller: the descriptor comes from SandboxMonitor::ConnectToApp,
     * which claims it under this same code because the manager holds a copy of
     * it until the handover and closes that copy itself. Claiming twice is
     * harmless -- MARK replaces whatever tag was there.
     */
    if (fd_ >= 0) {
        SANDBOX_FDSAN_MARK(fd_, SANDBOX_FDSAN_SITE_MONITOR_SOCKET);
    }
}

SandboxSocket::~SandboxSocket()
{
    if (fd_ < 0) {
        return;
    }
    if (SANDBOX_FDSAN_CLOSE(fd_, SANDBOX_FDSAN_SITE_MONITOR_SOCKET) < 0) {
        SANDBOX_LOGW("Failed to close socket fd: %{public}s", strerror(errno));
    }
}

int SandboxSocket::GetFd() const
{
    return fd_;
}

bool SandboxSocket::HasPendingTxData() const
{
    return txOffset_ < txBuffer_.size();
}

int SandboxSocket::OnReadable(std::vector<ParsedMessage> &outMessages)
{
    while (true) {
        ReadStep step = ReadStep::PROGRESSED;
        if (readState_ == SOCKET_STATE_READING_HEADER) {
            step = ProcessHeader(outMessages);
        } else if (readState_ == SOCKET_STATE_READING_BODY) {
            step = ProcessBody(outMessages);
        } else {
            step = DiscardBody(outMessages);
        }

        switch (step) {
            case ReadStep::PROGRESSED:
                continue;
            case ReadStep::DRAINED:
                // The fd is empty until epoll says otherwise, which is not a failure.
                return SANDBOX_SUCCESS;
            case ReadStep::FAILED:
            default:
                return readError_;
        }
    }
}

ReadStep SandboxSocket::ProcessHeader(std::vector<ParsedMessage> &outMessages)
{
    size_t bytesToRead = sizeof(MessageHeader) - headerBytesRead_;
    char *dest = reinterpret_cast<char *>(&currentHeader_) + headerBytesRead_;

    ssize_t n = read(fd_, dest, bytesToRead);
    if (n > 0) {
        headerBytesRead_ += static_cast<size_t>(n);
        if (headerBytesRead_ != sizeof(MessageHeader)) {
            // Half a header is progress: a stream socket splits messages anywhere.
            return ReadStep::PROGRESSED;
        }

        readError_ = ValidateProtocol();
        if (readError_ != SANDBOX_SUCCESS) {
            return ReadStep::FAILED;
        }

        if (ValidateBodyLength() != SANDBOX_SUCCESS) {
            // The frame is still trustworthy - magic and version matched - so
            // bodyLength says where the next message begins. Skip exactly this
            // body rather than dropping a connection over a size mistake.
            bodyBytesToDiscard_ = currentHeader_.bodyLength;
            readState_ = SOCKET_STATE_DISCARDING_BODY;
            return ReadStep::PROGRESSED;
        }

        if (currentHeader_.bodyLength == 0) {
            outMessages.push_back({currentHeader_, ""});
            ResetReadState();
        } else {
            currentBodyBuffer_.resize(currentHeader_.bodyLength);
            bodyBytesRead_ = 0;
            readState_ = SOCKET_STATE_READING_BODY;
        }
        return ReadStep::PROGRESSED;
    }

    if (n == 0) {
        SANDBOX_LOGE("Socket fd %{public}d closed by peer during header read", fd_);
        readError_ = SANDBOX_ERR_SOCKET_CLOSED;
        return ReadStep::FAILED;
    }

    int readErrno = errno;
    if (readErrno == EINTR) {
        return ReadStep::PROGRESSED;
    }
    if (readErrno == EAGAIN || readErrno == EWOULDBLOCK) {
        return ReadStep::DRAINED;
    }
    SANDBOX_LOGE("Failed to read socket header from fd %{public}d: %{public}s",
        fd_, strerror(readErrno));
    readError_ = SANDBOX_ERR_SOCKET_IO;
    return ReadStep::FAILED;
}

/*
 * Largest body this type may carry. MAX_BODY_LENGTH is the channel ceiling; a
 * type with a tighter bound of its own declares it here.
 *
 * An unknown type gets the ceiling rather than a rejection: refusing it here
 * would disconnect the app for sending something newer than this build.
 */
// Scratch for draining an over-long body. Sized for the syscall, not for the
// message: what is being read is on its way to /dev/null.
constexpr size_t DISCARD_CHUNK_SIZE = 4096;

static size_t MaxBodyLengthForType(uint32_t msgType)
{
    switch (msgType) {
        case SANDBOX_SOCKET_MSG_ADD_POLICY:
            return MAX_POLICY_JSON_LENGTH;

        case SANDBOX_SOCKET_MSG_EVENT_ANSWER:
            return MAX_EVENT_ANSWER_JSON_LENGTH;

        default:
            return MAX_BODY_LENGTH;
    }
}

/*
 * Read and throw away a body that is over its type's limit.
 *
 * Fixed scratch buffer, consumed across as many wakeups as it takes: the number
 * of bytes to drop comes from the peer, so it must never size an allocation.
 * When the last one is gone the peer is answered - the request did arrive, and
 * silence would leave it waiting on a response that is never coming.
 */
ReadStep SandboxSocket::DiscardBody(std::vector<ParsedMessage> &outMessages)
{
    char scratch[DISCARD_CHUNK_SIZE];
    size_t bytesToRead = std::min(bodyBytesToDiscard_, sizeof(scratch));

    ssize_t n = read(fd_, scratch, bytesToRead);
    if (n > 0) {
        bodyBytesToDiscard_ -= static_cast<size_t>(n);
        if (bodyBytesToDiscard_ == 0) {
            ParsedMessage message = {currentHeader_, "", SANDBOX_ERR_SOCKET_MSG_TOO_LARGE};
            outMessages.push_back(std::move(message));
            ResetReadState();
        }
        return ReadStep::PROGRESSED;
    }

    if (n == 0) {
        SANDBOX_LOGE("Socket fd %{public}d closed by peer while dropping an oversized body", fd_);
        readError_ = SANDBOX_ERR_SOCKET_CLOSED;
        return ReadStep::FAILED;
    }

    int readErrno = errno;
    if (readErrno == EINTR) {
        return ReadStep::PROGRESSED;
    }
    if (readErrno == EAGAIN || readErrno == EWOULDBLOCK) {
        return ReadStep::DRAINED;
    }
    SANDBOX_LOGE("Failed to drop an oversized body on fd %{public}d: %{public}s",
        fd_, strerror(readErrno));
    readError_ = SANDBOX_ERR_SOCKET_IO;
    return ReadStep::FAILED;
}

/*
 * Is this our stream at all. The only check that ends the connection: if the
 * header cannot be trusted, neither can the bodyLength that says where the next
 * message begins, so there is no way to resynchronise.
 *
 * Everything decidable after this point - an over-long body, an unknown msgType
 * - is answered with an error code and the connection kept.
 */
int SandboxSocket::ValidateProtocol() const
{
    if (currentHeader_.magic != SANDBOX_SOCKET_MAGIC) {
        SANDBOX_LOGE("Invalid socket message magic: %{public}d",
            static_cast<int>(currentHeader_.magic));
        return SANDBOX_ERR_SOCKET_PROTOCOL;
    }

    if (currentHeader_.version != SANDBOX_SOCKET_VERSION) {
        SANDBOX_LOGE("Unsupported socket protocol version: %{public}d",
            static_cast<int>(currentHeader_.version));
        return SANDBOX_ERR_SOCKET_PROTOCOL;
    }

    return SANDBOX_SUCCESS;
}

int SandboxSocket::ValidateBodyLength() const
{
    const size_t maxBodyLength = MaxBodyLengthForType(currentHeader_.msgType);
    if (static_cast<size_t>(currentHeader_.bodyLength) > maxBodyLength) {
        SANDBOX_LOGE("Body of %{public}u bytes exceeds the %{public}u byte limit for type %{public}u",
            currentHeader_.bodyLength, static_cast<uint32_t>(maxBodyLength), currentHeader_.msgType);
        return SANDBOX_ERR_SOCKET_MSG_TOO_LARGE;
    }

    return SANDBOX_SUCCESS;
}


ReadStep SandboxSocket::ProcessBody(std::vector<ParsedMessage> &outMessages)
{
    size_t bytesToRead = currentHeader_.bodyLength - bodyBytesRead_;
    char *dest = &currentBodyBuffer_[bodyBytesRead_];

    ssize_t n = read(fd_, dest, bytesToRead);
    if (n > 0) {
        bodyBytesRead_ += static_cast<size_t>(n);
        if (bodyBytesRead_ != currentHeader_.bodyLength) {
            return ReadStep::PROGRESSED;
        }

        outMessages.push_back({
            currentHeader_,
            std::move(currentBodyBuffer_)
        });
        ResetReadState();
        return ReadStep::PROGRESSED;
    }

    if (n == 0) {
        SANDBOX_LOGI("Socket fd %{public}d closed by peer during body read", fd_);
        readError_ = SANDBOX_ERR_SOCKET_CLOSED;
        return ReadStep::FAILED;
    }

    int readErrno = errno;
    if (readErrno == EINTR) {
        return ReadStep::PROGRESSED;
    }
    if (readErrno == EAGAIN || readErrno == EWOULDBLOCK) {
        return ReadStep::DRAINED;
    }
    SANDBOX_LOGE("Failed to read socket body from fd %{public}d: %{public}s",
        fd_, strerror(readErrno));
    readError_ = SANDBOX_ERR_SOCKET_IO;
    return ReadStep::FAILED;
}

void SandboxSocket::ResetReadState()
{
    readState_ = SOCKET_STATE_READING_HEADER;
    currentHeader_ = {};
    headerBytesRead_ = 0;
    currentBodyBuffer_.clear();
    bodyBytesRead_ = 0;
    bodyBytesToDiscard_ = 0;
}

/*
 * requestId 0 means "monitor originated, do not correlate". Only the app picks
 * a requestId, and the monitor only echoes it back in a RESPONSE; what the
 * monitor sends on its own is a notification, answered by a separate
 * EVENT_ANSWER correlated by "event_id" in the body instead.
 */
int SandboxSocket::SendMessage(uint32_t msgType, const std::string &body)
{
    return QueueMessage(msgType, body, 0, SANDBOX_SUCCESS);
}

int SandboxSocket::SendResponse(uint32_t requestId, int32_t result, const std::string &body)
{
    return QueueMessage(SANDBOX_SOCKET_MSG_RESPONSE, body, requestId, result);
}

int SandboxSocket::QueueMessage(uint32_t msgType, const std::string &body,
    uint32_t requestId, int32_t result)
{
    if (body.size() > MAX_BODY_LENGTH) {
        SANDBOX_LOGE("Socket message body too large: %{public}d",
            static_cast<int>(body.size()));
        return SANDBOX_ERR_SOCKET_MSG_TOO_LARGE;
    }

    size_t messageLength = sizeof(MessageHeader) + body.size();
    size_t pendingLength = txBuffer_.size() - txOffset_;
    if (messageLength > MAX_TX_BUFFER_SIZE ||
        pendingLength > MAX_TX_BUFFER_SIZE - messageLength) {
        SANDBOX_LOGW("Socket Tx buffer is full, pending %{public}d bytes",
            static_cast<int>(pendingLength));
        return SANDBOX_ERR_SOCKET_TX_FULL;
    }

    CompactTxBuffer(messageLength);

    MessageHeader header = {
        .magic = SANDBOX_SOCKET_MAGIC,
        .version = SANDBOX_SOCKET_VERSION,
        .bodyLength = static_cast<uint32_t>(body.size()),
        .msgType = msgType,
        .requestId = requestId,
        .result = result
    };

    txBuffer_.append(
        reinterpret_cast<const char *>(&header),
        sizeof(MessageHeader));

    if (!body.empty()) {
        txBuffer_.append(body);
    }

    return FlushTxBuffer();
}

void SandboxSocket::CompactTxBuffer(size_t appendLength)
{
    if (txOffset_ == 0 || txBuffer_.size() <= MAX_TX_BUFFER_SIZE - appendLength) {
        return;
    }

    txBuffer_.erase(0, txOffset_);
    txOffset_ = 0;
}

int SandboxSocket::FlushTxBuffer()
{
    while (HasPendingTxData()) {
        const char *data = txBuffer_.data() + txOffset_;
        size_t length = txBuffer_.size() - txOffset_;

        ssize_t n = send(fd_, data, length, MSG_NOSIGNAL);
        if (n > 0) {
            txOffset_ += static_cast<size_t>(n);
            continue;
        } else if (n == 0) {
            SANDBOX_LOGW("Socket fd %{public}d sent zero bytes", fd_);
            return SANDBOX_ERR_SOCKET_IO;
        }

        int error = errno;
        if (error == EINTR) {
            continue;
        }

        if (error == EAGAIN || error == EWOULDBLOCK) {
            // The kernel is full, not broken. The rest stays buffered for the
            // next EPOLLOUT, which HasPendingTxData reports.
            return SANDBOX_SUCCESS;
        } else if (error == EPIPE || error == ECONNRESET || error == ENOTCONN) {
            SANDBOX_LOGI("Socket fd %{public}d closed by peer: %{public}s", fd_, strerror(error));
            return SANDBOX_ERR_SOCKET_CLOSED;
        }
        SANDBOX_LOGE("Failed to write socket fd %{public}d: %{public}s", fd_, strerror(error));
        return SANDBOX_ERR_SOCKET_IO;
    }

    txBuffer_.clear();
    txOffset_ = 0;

    return SANDBOX_SUCCESS;
}

int SandboxSocket::OnWritable()
{
    return FlushTxBuffer();
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
