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

#include "sandbox_monitor.h"
#include "sandbox_device_ioctl.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <thread>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

#include "cJSON.h"
#include "sandbox_limits.h"
#include "securec.h"
#include "sandbox_log.h"
#include "sandbox_policy.h"
#include "sandbox_response.h"
#include "sandbox_device_event.h"
#include "sandbox_utils.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

constexpr int MAX_EPOLL_EVENTS = 10;
/*
 * Not a connect timeout - an AF_UNIX connect() cannot hang. It is the exit
 * condition of the retry loop below, and the only retryable condition is a full
 * listen backlog. Retrying absorbs a burst of concurrent launches against an app
 * that accepts one at a time; every genuine failure is reported on the first
 * attempt and never spends any of this budget.
 */
constexpr std::chrono::milliseconds MONITOR_CONNECT_RETRY_BUDGET{200};
constexpr std::chrono::milliseconds MONITOR_CONNECT_RETRY_INTERVAL{10};
// Reconnect budget once the peer goes away mid-run. Kept short on purpose: the
// buffered-event table fills while the channel is down.
constexpr int MONITOR_RECONNECT_MAX_ATTEMPTS = 3;
constexpr std::chrono::milliseconds MONITOR_RECONNECT_INTERVAL{200};

// How much of a failing event to dump, and the "xx " each byte turns into.
constexpr size_t EVENT_DUMP_BYTES = 64;
constexpr size_t HEX_CHARS_PER_BYTE = 3;
// The table caps live in sandbox_limits.h; the tests assert against them.
/*
 * One read has to be able to hold one whole event.
 *
 * The device is record oriented: one read runs the kernel hook once and returns
 * one whole event. A short buffer would get a prefix and lose the rest, so this
 * is sized to the largest event the TLV table allows and cannot grow on demand.
 */
constexpr size_t DEVICE_READ_CHUNK_SIZE = MAX_DEVICE_EVENT_LENGTH;

// Layout of the kernel's SO_PEERCRED result (struct ucred). Declared locally so
// the check does not depend on _GNU_SOURCE being defined by the toolchain.
struct SocketPeerCredential {
    pid_t pid;
    uid_t uid;
    gid_t gid;
};

/*
 * DEC event-answer wire payload. Keep this layout synchronized with the DEC UAPI.
 *
 * Deliberately not packed, so the kernel can read the fields in place. That
 * leaves four bytes of tail padding, and the whole struct is handed to write()
 * - reserved2 names those bytes so they are initialised rather than whatever
 * was on the stack.
 */
struct DecEventAnswer {
    uint32_t size;
    uint32_t reserved1;
    uint64_t eventId;
    DEC_POLICY_ACTION action;
    uint32_t reserved2;
};

static_assert(sizeof(DecEventAnswer) == 24, "Invalid DEC event answer size");
static_assert(offsetof(DecEventAnswer, eventId) == 8, "eventId must stay 8-byte aligned");
static_assert(alignof(DecEventAnswer) == 8, "DecEventAnswer must stay naturally aligned");

/*
 * Dump the bytes where parsing gave up.
 *
 * Without this a parse failure is undiagnosable. The hex is what tells a human
 * whether the stream slipped by a few bytes, whether a field moved, or whether
 * this is not a DEC event at all - none of which the error code can express.
 */
static void LogEventBytes(const uint8_t *data, size_t size)
{
    const size_t dumpSize = std::min(size, EVENT_DUMP_BYTES);
    std::string hex;
    hex.reserve(dumpSize * HEX_CHARS_PER_BYTE);

    for (size_t i = 0; i < dumpSize; ++i) {
        char byte[HEX_CHARS_PER_BYTE + 1] = {};
        if (snprintf_s(byte, sizeof(byte), sizeof(byte) - 1, "%02x ", data[i]) < 0) {
            break;
        }
        hex += byte;
    }

    SANDBOX_LOGE("Device event parse failed, first %{public}d bytes: %{public}s",
        static_cast<int>(dumpSize), hex.c_str());
}

static bool IsSocketChannelError(int ret)
{
    return ret == SANDBOX_ERR_SOCKET_CLOSED || ret == SANDBOX_ERR_SOCKET_IO;
}

/*
 * Connect a non-blocking AF_UNIX socket.
 *
 * AF_UNIX connect() never reports EINPROGRESS, so the TCP-style "wait for
 * EPOLLOUT then check SO_ERROR" dance does not apply. A full listen backlog
 * surfaces as EAGAIN and is retried by calling connect() again; that is the only
 * retryable case, ENOENT and ECONNREFUSED are final.
 *
 * WAIT_FOR_BACKLOG waits it out within MONITOR_CONNECT_RETRY_BUDGET;
 * SINGLE_ATTEMPT returns SANDBOX_ERR_SOCKET_WOULD_BLOCK for the caller's own
 * loop to retry.
 */
static int AttemptConnect(int fd, const struct sockaddr_un &addr, socklen_t addrLength,
    const std::string &socketPath, MonitorConnectMode mode)
{
    const auto deadline = std::chrono::steady_clock::now() + MONITOR_CONNECT_RETRY_BUDGET;

    while (true) {
        if (connect(fd, reinterpret_cast<const struct sockaddr *>(&addr), addrLength) == 0) {
            return SANDBOX_SUCCESS;
        }

        int error = errno;
        if (error == EISCONN) {
            // A retry raced with the previous attempt completing.
            return SANDBOX_SUCCESS;
        }
        if (error == EINTR) {
            continue;
        }
        if (error != EAGAIN && error != EWOULDBLOCK) {
            SANDBOX_LOGE("Failed to connect Unix Domain Socket %{public}s: %{public}s",
                socketPath.c_str(), strerror(error));
            return SANDBOX_ERR_SOCKET_CONNECT_FAILED;
        }

        if (mode == MONITOR_CONNECT_SINGLE_ATTEMPT) {
            return SANDBOX_ERR_SOCKET_WOULD_BLOCK;
        }

        if (std::chrono::steady_clock::now() >= deadline) {
            SANDBOX_LOGE("Gave up after %{public}dms connecting Unix Domain Socket %{public}s; "
                "the peer is listening but is not accepting",
                static_cast<int>(MONITOR_CONNECT_RETRY_BUDGET.count()), socketPath.c_str());
            return SANDBOX_ERR_SOCKET_CONNECT_TIMEOUT;
        }

        std::this_thread::sleep_for(MONITOR_CONNECT_RETRY_INTERVAL);
    }
}

SandboxMonitor::SandboxMonitor(MonitorConfig config)
    : childPid_(config.childPid),
      socketPath_(std::move(config.socketPath)),
      deviceFd_(config.deviceFd)
{
    if (config.socketFd >= 0) {
        // SandboxSocket takes ownership of socketFd. From this point on,
        // SandboxMonitor must not close socketFd directly.
        socket_ = std::make_unique<SandboxSocket>(config.socketFd);
        sockCtx_.fd = config.socketFd;
    }
    deviceReadBuffer_.resize(DEVICE_READ_CHUNK_SIZE);
}

SandboxMonitor::~SandboxMonitor()
{
    CloseSocket();

    SafeCloseFd(deviceFd_);
    SafeCloseFd(childFd_);
    SafeCloseFd(epollFd_);
}

void SandboxMonitor::SafeCloseFd(int &fd)
{
    if (fd < 0) {
        return;
    }

    int closeFd = fd;
    fd = -1;
    if (close(closeFd) < 0) {
        SANDBOX_LOGW("Failed to close fd %{public}d: %{public}s",
            closeFd, strerror(errno));
    }
}

void SandboxMonitor::CloseSocket()
{
    if (socket_ == nullptr) {
        return;
    }

    int socketFd = socket_->GetFd();
    if (epollFd_ >= 0 && socketFd >= 0) {
        if (epoll_ctl(epollFd_, EPOLL_CTL_DEL, socketFd, nullptr) < 0) {
            int error = errno;
            if (error != ENOENT && error != EBADF) {
                SANDBOX_LOGW("Failed to remove socket fd %{public}d from epoll: %{public}s",
                    socketFd, strerror(error));
            }
        }
    }

    // SandboxSocket owns the fd and closes it in its destructor.
    socket_.reset();
    sockCtx_.fd = -1;
    socketWriteEnabled_ = false;
}


void SandboxMonitor::PushEventReport(uint64_t eventId, bool needsAnswer, std::string body)
{
    PendingSocketMessage message = {
        .msgType = SANDBOX_SOCKET_MSG_EVENT_REPORT,
        .eventId = eventId,
        .needsAnswer = needsAnswer,
        .body = std::move(body)
    };
    PushSocketMessage(std::move(message));
}

void SandboxMonitor::PushResponse(uint32_t requestId, int32_t result, std::string body)
{
    PendingSocketMessage message = {
        .msgType = SANDBOX_SOCKET_MSG_RESPONSE,
        .requestId = requestId,
        .result = result,
        .body = std::move(body)
    };
    PushSocketMessage(std::move(message));
}

void SandboxMonitor::PushSocketMessage(PendingSocketMessage message)
{
    const size_t bodySize = message.body.size();
    if (bodySize > MAX_SOCKET_TX_QUEUE_BYTES) {
        SANDBOX_LOGE("Message for event id %{public}llu does not fit the queue on its own, "
            "dropping it", static_cast<unsigned long long>(message.eventId));
        return;
    }

    /*
     * Evict oldest first. Reading an event off the device never unblocks the
     * sandboxed thread that triggered it - only an answer does - so holding the
     * device back would not shorten anyone's wait, it would only make the
     * monitor depend on how the kernel behaves when its own queue fills.
     * Dropping here instead leaves the evicted event to the kernel's per-rule
     * silence policy.
     */
    while (!socketTxQueue_.empty() &&
        (socketTxQueue_.size() >= MAX_SOCKET_TX_QUEUE_COUNT ||
         socketTxBytes_ > MAX_SOCKET_TX_QUEUE_BYTES - bodySize)) {
        SANDBOX_LOGE("Socket queue is full, dropping message type %{public}u for event id "
            "%{public}llu", socketTxQueue_.front().msgType,
            static_cast<unsigned long long>(socketTxQueue_.front().eventId));
        socketTxBytes_ -= socketTxQueue_.front().body.size();
        socketTxQueue_.pop_front();
    }

    socketTxBytes_ += bodySize;
    socketTxQueue_.push_back(std::move(message));
}

void SandboxMonitor::PushPendingAnswer(uint64_t eventId)
{
    if (pendingAnswers_.size() >= MAX_PENDING_ANSWER_COUNT) {
        SANDBOX_LOGE("Pending answer table is full, forgetting event id %{public}llu; "
            "a late answer for it will be rejected",
            static_cast<unsigned long long>(pendingAnswers_.front()));
        pendingAnswers_.pop_front();
    }

    pendingAnswers_.push_back(eventId);
}

/*
 * Hand messages to the socket one at a time, and only while it has nothing left
 * over from the last one.
 *
 * A message in txBuffer_ is bytes, not a message: it cannot be dropped any more,
 * because there is no way to take one out of the middle of a stream. So every
 * message moved over gives up the eviction this queue exists to provide - and
 * the queue deliberately keeps the newest events, since only an answer unblocks
 * the sandboxed thread, never a read.
 *
 * The socket keeping up is unaffected: each send drains the buffer, the
 * condition holds, and the loop batches as before. Only a backed-up socket sees
 * the difference, and there this is exactly what should happen.
 */
int SandboxMonitor::FlushSocketTxQueue()
{
    while (!socketTxQueue_.empty()) {
        if (socket_ == nullptr) {
            return SANDBOX_SUCCESS;
        }
        if (socket_->HasPendingTxData()) {
            // The previous message is still going out. Resume on EPOLLOUT.
            return SANDBOX_SUCCESS;
        }

        PendingSocketMessage &front = socketTxQueue_.front();
        int ret = (front.msgType == SANDBOX_SOCKET_MSG_RESPONSE) ?
            socket_->SendResponse(front.requestId, front.result, front.body) :
            socket_->SendMessage(front.msgType, front.body);
        if (ret == SANDBOX_ERR_SOCKET_TX_FULL) {
            // Keep the rest queued in order and resume on the next EPOLLOUT.
            return SANDBOX_SUCCESS;
        }
        if (ret == SANDBOX_ERR_SOCKET_MSG_TOO_LARGE) {
            socketTxBytes_ -= front.body.size();
            if (front.msgType == SANDBOX_SOCKET_MSG_RESPONSE) {
                SANDBOX_LOGE("Response body for request %{public}u is too large, sending it bare",
                    front.requestId);
                front.body.clear();
                continue;
            }
            SANDBOX_LOGE("Dropping oversized queued message for event id %{public}llu",
                static_cast<unsigned long long>(front.eventId));
            socketTxQueue_.pop_front();
            continue;
        }
        if (ret != SANDBOX_SUCCESS) {
            SANDBOX_LOGE("Failed to send queued socket message, ret %{public}d", ret);
            return ret;
        }

        if (front.needsAnswer) {
            PushPendingAnswer(front.eventId);
        }
        socketTxBytes_ -= front.body.size();
        socketTxQueue_.pop_front();
    }

    return SANDBOX_SUCCESS;
}

void SandboxMonitor::DiscardAllEvents()
{
    if (!socketTxQueue_.empty() || !pendingAnswers_.empty()) {
        SANDBOX_LOGE("Discarding %{public}d queued messages and %{public}d pending answers",
            static_cast<int>(socketTxQueue_.size()), static_cast<int>(pendingAnswers_.size()));
    }

    socketTxQueue_.clear();
    socketTxBytes_ = 0;
    pendingAnswers_.clear();
}

static const char *StateName(MonitorState state)
{
    switch (state) {
        case MONITOR_STATE_ACTIVE:       return "active";
        case MONITOR_STATE_RECONNECTING: return "reconnecting";
        case MONITOR_STATE_DEGRADED:     return "degraded";
        default:                         return "unknown";
    }
}

/*
 * Every transition is logged with what caused it.
 *
 * Without this the answer to "why did monitoring stop working" has to be pieced
 * together from a socket pointer, a retry counter and two error members. One
 * line per transition makes it a fact in the log instead.
 */
void SandboxMonitor::SetState(MonitorState state)
{
    if (state_ == state) {
        return;
    }

    // Why it happened was logged where it was detected, on the line before this
    // one. Together the two read as cause and effect.
    SANDBOX_LOGW("Monitor state %{public}s -> %{public}s", StateName(state_), StateName(state));
    state_ = state;
}

/*
 * Give up the app channel without giving up the monitor.
 *
 * Only the first connection is allowed to fail the sandbox launch (see
 * SandboxManager::ConnectMonitorSocket). Once the child is running, losing the
 * peer must not terminate it: the monitor logs the error and starts a bounded
 * reconnect sequence, holding on to both tables so that a peer that comes back
 * is handed everything it missed.
 */
void SandboxMonitor::DropSocketChannel()
{
    CloseSocket();

    if (socketPath_.empty()) {
        Degrade();
        return;
    }

    reconnectAttemptsLeft_ = MONITOR_RECONNECT_MAX_ATTEMPTS;
    reconnectDeadline_ = std::chrono::steady_clock::now() + MONITOR_RECONNECT_INTERVAL;
    SetState(MONITOR_STATE_RECONNECTING);
    SANDBOX_LOGE("Queueing DEC events and retrying the connection %{public}d times",
        MONITOR_RECONNECT_MAX_ATTEMPTS);
}

/*
 * The end of the line: no channel, no reconnect, nothing left to forward.
 *
 * The child is untouched - it keeps running and is still reaped. What is gone is
 * the security function, which is why an EVENT_ANSWER arriving now is answered
 * with SANDBOX_ERR_MONITOR_DEGRADED rather than a per-event error.
 */
void SandboxMonitor::Degrade()
{
    CloseSocket();
    reconnectAttemptsLeft_ = 0;
    DiscardAllEvents();
    SetState(MONITOR_STATE_DEGRADED);
}

int SandboxMonitor::AdoptSocket(int socketFd)
{
    socket_ = std::make_unique<SandboxSocket>(socketFd);
    sockCtx_.fd = socketFd;
    socketWriteEnabled_ = false;

    int ret = RegisterFdToEpoll(socketFd, &sockCtx_, EPOLLIN | EPOLLRDHUP);
    if (ret != SANDBOX_SUCCESS) {
        CloseSocket();
        return ret;
    }

    return SANDBOX_SUCCESS;
}

void SandboxMonitor::TryReconnect()
{
    reconnectAttemptsLeft_--;

    /*
     * One attempt per tick. The epoll timeout below is what paces the retries,
     * so this must not run its own retry loop - that would block the event loop
     * and make the "MONITOR_RECONNECT_MAX_ATTEMPTS x MONITOR_RECONNECT_INTERVAL"
     * window much longer than it reads.
     */
    int socketFd = -1;
    int ret = SandboxMonitor::ConnectToApp(socketPath_, socketFd,
        MONITOR_CONNECT_SINGLE_ATTEMPT);
    if (ret != SANDBOX_SUCCESS) {
        if (reconnectAttemptsLeft_ > 0) {
            reconnectDeadline_ = std::chrono::steady_clock::now() + MONITOR_RECONNECT_INTERVAL;
            SANDBOX_LOGW("Monitor socket reconnect failed, ret %{public}d, %{public}d attempts left",
                ret, reconnectAttemptsLeft_);
            return;
        }

        SANDBOX_LOGE("Monitor socket reconnect gave up after %{public}d attempts",
            MONITOR_RECONNECT_MAX_ATTEMPTS);
        monitorError_ = ret;
        Degrade();
        return;
    }

    int adoptRet = AdoptSocket(socketFd);
    if (adoptRet != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Reconnected but failed to re-arm the socket");
        monitorError_ = adoptRet;
        Degrade();
        return;
    }

    reconnectAttemptsLeft_ = 0;
    monitorError_ = SANDBOX_SUCCESS;
    SetState(MONITOR_STATE_ACTIVE);
    SANDBOX_LOGI("Monitor socket reconnected, replaying %{public}d buffered events",
        static_cast<int>(socketTxQueue_.size()));

    /*
     * pendingAnswers_ is deliberately kept across a reconnect: the peer that
     * comes back is normally the same app restarting its monitor thread, and it
     * still remembers those ids. Clearing them would reject every answer for
     * events reported before the drop, which would defeat the whole point of
     * riding out a brief outage.
     */
    int flushRet = FlushSocketTxQueue();
    if (flushRet != SANDBOX_SUCCESS) {
        monitorError_ = flushRet;
        DropSocketChannel();
        return;
    }

    int epollRet = UpdateSocketEpollEvents();
    if (epollRet != SANDBOX_SUCCESS) {
        monitorError_ = epollRet;
        DropSocketChannel();
    }
}

int SandboxMonitor::NextEpollTimeout() const
{
    if (reconnectAttemptsLeft_ <= 0) {
        return -1;
    }

    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        reconnectDeadline_ - std::chrono::steady_clock::now());
    return remaining.count() <= 0 ? 0 : static_cast<int>(remaining.count());
}

int SandboxMonitor::SetNonBlock(int fd)
{
    if (fd < 0) {
        SANDBOX_LOGE("Invalid fd %{public}d when setting non-blocking mode", fd);
        return SANDBOX_ERR_BAD_PARAMETERS;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        SANDBOX_LOGE("Failed to get fd %{public}d flags: %{public}s",
            fd, strerror(errno));
        return SANDBOX_ERR_SOCKET_IO;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        SANDBOX_LOGE("Failed to set fd %{public}d non-blocking: %{public}s",
            fd, strerror(errno));
        return SANDBOX_ERR_SOCKET_IO;
    }

    return SANDBOX_SUCCESS;
}

/*
 * Record who is on the other end. This is diagnostics only, not a check.
 *
 * The trust root is "whoever may launch the sandbox is trusted", so the peer's
 * pid is not compared against anything. What keeps an unrelated process off this
 * channel is the socket path itself - its location and its file permissions.
 */
void SandboxMonitor::LogSocketPeer(int socketFd)
{
    SocketPeerCredential credential = {};
    socklen_t credentialLength = sizeof(credential);

    if (getsockopt(socketFd, SOL_SOCKET, SO_PEERCRED,
        &credential, &credentialLength) < 0 || credentialLength != sizeof(credential)) {
        SANDBOX_LOGW("Failed to read socket peer credential: %{public}s", strerror(errno));
        return;
    }

    SANDBOX_LOGI("Monitor socket peer pid %{public}d uid %{public}d",
        static_cast<int>(credential.pid), static_cast<int>(credential.uid));
}

int SandboxMonitor::ConnectToApp(const std::string &socketPath, int &socketFd,
    MonitorConnectMode mode)
{
    socketFd = -1;

    if (socketPath.empty() || socketPath.front() != '/') {
        SANDBOX_LOGE("Monitor socket path must be a non-empty absolute path");
        return SANDBOX_ERR_PATH_INVALID;
    }

    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    if (socketPath.length() >= sizeof(addr.sun_path)) {
        SANDBOX_LOGE("Socket path is too long, length %{public}d",
            static_cast<int>(socketPath.length()));
        return SANDBOX_ERR_PATH_INVALID;
    }

    if (memcpy_s(addr.sun_path, sizeof(addr.sun_path),
        socketPath.c_str(), socketPath.length() + 1) != 0) {
        SANDBOX_LOGE("Failed to copy the monitor socket path");
        return SANDBOX_ERR_GENERIC;
    }

    /*
     * The socket is non-blocking from creation, so neither the connect below nor
     * the monitor's later reads and writes can park the process. The app is
     * expected to be listening before the sandbox starts; AttemptConnect only
     * covers the case where it is listening but slow to accept.
     */
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        SANDBOX_LOGE("Failed to create Unix Domain Socket: %{public}s",
            strerror(errno));
        return SANDBOX_ERR_SOCKET_CREATE_FAILED;
    }

    const socklen_t addrLength = static_cast<socklen_t>(
        offsetof(struct sockaddr_un, sun_path) + socketPath.length() + 1);
    int ret = AttemptConnect(fd, addr, addrLength, socketPath, mode);
    if (ret != SANDBOX_SUCCESS) {
        SafeCloseFd(fd);
        return ret;
    }

    LogSocketPeer(fd);

    socketFd = fd;
    return SANDBOX_SUCCESS;
}

/*
 * A pidfd, not a signalfd, and the difference is not cosmetic.
 *
 * SIGCHLD is process directed and sigprocmask() only changes the calling
 * thread's mask. This process is already multi threaded here - the OHOS IPC
 * clients used earlier leave workers behind, and fork() copies only the caller -
 * so a signalfd loses the notification outright: a worker takes SIGCHLD, its
 * default action discards it, nothing becomes pending, and the monitor sleeps in
 * epoll_wait() forever beside an unreaped zombie.
 *
 * A pidfd becomes readable on exit, with no signal delivery in the way.
 */
int SandboxMonitor::SetupChildExitFd()
{
    // pidfd_open() always sets close-on-exec, so there is no flag to pass.
    long fd = syscall(__NR_pidfd_open, childPid_, 0);
    if (fd < 0) {
        SANDBOX_LOGE("Failed to open a pidfd for child process %{public}d: %{public}s",
            static_cast<int>(childPid_), strerror(errno));
        return SANDBOX_ERR_CHILD_WATCH_FAILED;
    }

    childFd_ = static_cast<int>(fd);
    childCtx_.fd = childFd_;
    return SANDBOX_SUCCESS;
}

int SandboxMonitor::RegisterFdToEpoll(
    int fd, MonitorEventContext *ctx, uint32_t events)
{
    if (fd < 0 || ctx == nullptr) {
        SANDBOX_LOGE("Invalid parameters when registering fd to epoll");
        return SANDBOX_ERR_BAD_PARAMETERS;
    }

    struct epoll_event event = {
        .events = events,
        .data = { .ptr = ctx }
    };

    if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, fd, &event) < 0) {
        SANDBOX_LOGE("Failed to register fd %{public}d to epoll: %{public}s",
            fd, strerror(errno));
        return SANDBOX_ERR_EPOLL_FAILED;
    }

    return SANDBOX_SUCCESS;
}

int SandboxMonitor::UpdateSocketEpollEvents()
{
    if (socket_ == nullptr) {
        return SANDBOX_SUCCESS;
    }

    bool enableWrite = socket_->HasPendingTxData() || !socketTxQueue_.empty();
    if (enableWrite == socketWriteEnabled_) {
        return SANDBOX_SUCCESS;
    }

    uint32_t events = EPOLLIN | EPOLLRDHUP;
    if (enableWrite) {
        events |= EPOLLOUT;
    }
    struct epoll_event event = {
        .events = events,
        .data = { .ptr = &sockCtx_ }
    };
    if (epoll_ctl(epollFd_, EPOLL_CTL_MOD,
        socket_->GetFd(), &event) < 0) {
        SANDBOX_LOGE("Failed to update socket epoll events: %{public}s",
            strerror(errno));
        return SANDBOX_ERR_EPOLL_FAILED;
    }
    socketWriteEnabled_ = enableWrite;
    return SANDBOX_SUCCESS;
}

int SandboxMonitor::Init()
{
    if (childPid_ <= 0) {
        SANDBOX_LOGE("Invalid monitor initialization parameters");
        return SANDBOX_ERR_BAD_PARAMETERS;
    }
    if (deviceFd_ < 0) {
        SANDBOX_LOGW("Daemon-initialized DEC fd is unavailable; disable optional monitor");
        return SANDBOX_ERR_DEVICE_OPEN_FAILED;
    }

    if (epollFd_ >= 0) {
        SANDBOX_LOGE("SandboxMonitor has already been initialized");
        return SANDBOX_ERR_BAD_PARAMETERS;
    }

    /*
     * Watch the child first. Unlike the signalfd this replaced, a pidfd has no
     * race to lose: it is bound to the child from here on, and an exit that
     * happens before the rest of the setup finishes still shows up as EPOLLIN.
     */
    int ret = SetupChildExitFd();
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    ret = SetNonBlock(deviceFd_);
    if (ret != SANDBOX_SUCCESS) {
        return SANDBOX_ERR_DEVICE_IO;
    }
    devCtx_.fd = deviceFd_;

    if (socket_ == nullptr) {
        SANDBOX_LOGW("No monitor socket was handed over; DEC events will be discarded");
    }

    epollFd_ = epoll_create1(EPOLL_CLOEXEC);
    if (epollFd_ < 0) {
        SANDBOX_LOGE("Failed to create epoll fd: %{public}s",
            strerror(errno));
        return SANDBOX_ERR_EPOLL_FAILED;
    }

    ret = RegisterFdToEpoll(childFd_, &childCtx_, EPOLLIN);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    if (socket_ != nullptr) {
        ret = RegisterFdToEpoll(socket_->GetFd(), &sockCtx_, EPOLLIN | EPOLLRDHUP);
        if (ret != SANDBOX_SUCCESS) {
            return ret;
        }
    }
    // Always armed. The buffered-event table, not the device fd, is what bounds
    // how much the monitor holds on to.
    ret = RegisterFdToEpoll(deviceFd_, &devCtx_, EPOLLIN);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    return SANDBOX_SUCCESS;
}

MonitorAction SandboxMonitor::CheckChildExit(int waitOptions)
{
    int status = 0;
    pid_t ret;
    do {
        ret = waitpid(childPid_, &status, waitOptions);
    } while (ret < 0 && errno == EINTR);

    if (ret == 0) {
        return MONITOR_ACTION_NONE;
    }

    if (ret == childPid_) {
        if (WIFEXITED(status)) {
            childExitCode_ = WEXITSTATUS(status);
            SANDBOX_LOGI("Child process %{public}d exited normally, status %{public}d",
                static_cast<int>(childPid_), childExitCode_);
            monitorError_ = SANDBOX_SUCCESS;
            return MONITOR_ACTION_CHILD_EXITED;
        }

        if (WIFSIGNALED(status)) {
            int signal = WTERMSIG(status);
            childExitCode_ = SIGNAL_EXIT_BASE + signal;
            SANDBOX_LOGI("Child process %{public}d killed by signal %{public}d",
                static_cast<int>(childPid_), signal);
            monitorError_ = SANDBOX_SUCCESS;
            return MONITOR_ACTION_CHILD_EXITED;
        }

        /*
         * Unreachable: waitpid is not given WUNTRACED or WCONTINUED, so a
         * reaped child is always either exited or signalled. Reported as a
         * failure anyway, because a fallthrough with no reason at all is how
         * Run() used to end up returning a meaningless SANDBOX_ERR_GENERIC.
         */
        SANDBOX_LOGE("Unexpected child process state for pid %{public}d, status %{public}d",
            static_cast<int>(childPid_), status);
        monitorError_ = SANDBOX_ERR_CHILD_WAIT_FAILED;
        return MONITOR_ACTION_STOP;
    }

    SANDBOX_LOGE("Failed to wait for child process %{public}d: %{public}s",
        static_cast<int>(childPid_), strerror(errno));
    monitorError_ = SANDBOX_ERR_CHILD_WAIT_FAILED;
    return MONITOR_ACTION_STOP;
}

MonitorAction SandboxMonitor::HandleChildExitEvent(uint32_t events)
{
    if ((events & (EPOLLERR | EPOLLHUP)) != 0) {
        SANDBOX_LOGE("Unexpected pidfd epoll event %{public}d",
            static_cast<int>(events));
        monitorError_ = SANDBOX_ERR_CHILD_WATCH_FAILED;
        return MONITOR_ACTION_STOP;
    }

    if ((events & EPOLLIN) != 0) {
        /*
         * A pidfd wakes earlier than SIGCHLD did: its queue is woken while the
         * task is still inside exit_notify(), where SIGCHLD arrived only once
         * the task was reapable. So a WNOHANG reap here can legitimately find
         * nothing.
         *
         * Hence the second, blocking call - once EPOLLIN is set the process is
         * gone, so it can only wait for an exit already committed to. Returning
         * NONE is not an option: nothing clears a pidfd's readiness, so the loop
         * would spin.
         */
        MonitorAction action = CheckChildExit(WNOHANG);
        if (action == MONITOR_ACTION_NONE) {
            action = CheckChildExit(0);
        }
        return action;
    }

    return MONITOR_ACTION_NONE;
}

/*
 * Gate a message before anything reads its body.
 *
 * Order matters: a request that reuses requestId 0 is answered as such even when
 * its body was also refused, because a response it cannot correlate is no use to
 * it whatever the reason says.
 */
int SandboxMonitor::ValidateMessage(const ParsedMessage &message)
{
    // requestId 0 is reserved for messages the monitor originates, so a caller
    // reusing it cannot tell which request a response belongs to.
    if (message.header.requestId == 0) {
        SANDBOX_LOGE("Request of type %{public}u used the reserved requestId 0",
            message.header.msgType);
        return SANDBOX_ERR_REQUEST_ID_INVALID;
    }

    // The socket layer read this frame and threw its body away. There is nothing
    // to dispatch, only its verdict to pass on - deriving one from the empty
    // body instead would answer a size problem as a format problem.
    if (message.rejectReason != SANDBOX_SUCCESS) {
        SANDBOX_LOGW("Rejected socket message type %{public}u, request %{public}u, ret %{public}d",
            message.header.msgType, message.header.requestId, message.rejectReason);
        return message.rejectReason;
    }

    return SANDBOX_SUCCESS;
}

int SandboxMonitor::DispatchSocketMessage(const ParsedMessage &message, std::string *detail)
{
    SANDBOX_LOGI("Dispatching socket message, type %{public}u, request id %{public}u, body length %{public}u",
        message.header.msgType, message.header.requestId, message.header.bodyLength);

    switch (message.header.msgType) {
        case SANDBOX_SOCKET_MSG_ADD_POLICY: {
            return HandleAddPolicy(message.body, detail);
        }
        case SANDBOX_SOCKET_MSG_EVENT_ANSWER: {
            return HandleEventAnswer(message.body);
        }
        default: {
            SANDBOX_LOGE("Unknown socket message type %{public}u",
                message.header.msgType);
            return SANDBOX_ERR_SOCKET_PROTOCOL;
        }
    }
}

int SandboxMonitor::HandleEventAnswer(const std::string &jsonBody)
{
    /*
     * Once degraded there is nothing left to answer with, and every id is
     * unknown because the table was cleared. Saying so explicitly matters:
     * SANDBOX_ERR_EVENT_UNKNOWN means "that id is wrong, try another", which
     * would send the app round a loop that can never succeed.
     */
    if (state_ == MONITOR_STATE_DEGRADED || deviceFd_ < 0) {
        SANDBOX_LOGE("Refusing event answer, monitoring is no longer available");
        return SANDBOX_ERR_MONITOR_DEGRADED;
    }

    uint64_t eventId = 0;
    enum DEC_POLICY_ACTION action = DEC_POLICY_ACTION_DENY;

    int ret = ParseEventAnswer(jsonBody, eventId, action);
    if (ret != SANDBOX_SUCCESS) {
        // Retryable: the app can send a well formed answer for the same event.
        return SANDBOX_ERR_EVENT_ANSWER_INVALID;
    }

    /*
     * Only events this monitor actually reported may be answered. Without this
     * the app could push a verdict for any id it cares to invent. An id that is
     * not here was never reported, was already answered, or has been evicted -
     * all permanent, so the app must not retry.
     */
    auto pending = std::find(pendingAnswers_.begin(), pendingAnswers_.end(), eventId);
    if (pending == pendingAnswers_.end()) {
        SANDBOX_LOGE("Answer for unknown event id %{public}llu",
            static_cast<unsigned long long>(eventId));
        return SANDBOX_ERR_EVENT_UNKNOWN;
    }

    ret = WriteEventAnswer(eventId, action);
    if (ret != SANDBOX_SUCCESS) {
        // Keep the entry so the app can retry once the device recovers.
        return ret;
    }

    pendingAnswers_.erase(pending);
    return SANDBOX_SUCCESS;
}

int SandboxMonitor::ParseEventAnswer(const std::string &jsonBody,
    uint64_t &eventId, enum DEC_POLICY_ACTION &action)
{
    if (jsonBody.size() > MAX_EVENT_ANSWER_JSON_LENGTH) {
        SANDBOX_LOGE("Event answer JSON exceeds maximum length");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    cJSON *root = cJSON_Parse(jsonBody.c_str());
    if (root == nullptr) {
        SANDBOX_LOGE("Failed to parse event answer JSON");
        return SANDBOX_ERR_CONFIG_INVALID;
    }

    cJSON *eventIdObj = cJSON_GetObjectItemCaseSensitive(root, "event_id");
    cJSON *actionObj = cJSON_GetObjectItemCaseSensitive(root, "action");
    if (!cJSON_IsString(eventIdObj) || eventIdObj->valuestring == nullptr ||
        !cJSON_IsString(actionObj) || actionObj->valuestring == nullptr) {
        SANDBOX_LOGE("Invalid event answer JSON format");
        cJSON_Delete(root);
        return SANDBOX_ERR_CONFIG_INVALID;
    }

    int ret = ParseEventId(eventIdObj->valuestring, eventId);
    if (ret == SANDBOX_SUCCESS) {
        ret = ParseEventAction(actionObj->valuestring, action);
    }
    cJSON_Delete(root);
    return ret;
}

int SandboxMonitor::ParseEventId(const char *eventIdStr, uint64_t &eventId)
{
    if (eventIdStr == nullptr) {
        SANDBOX_LOGE("Event id is missing");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    if (!ParseDecimalU64(eventIdStr, eventId)) {
        SANDBOX_LOGE("Invalid event id %{public}s", eventIdStr);
        return SANDBOX_ERR_CONFIG_INVALID;
    }

    return SANDBOX_SUCCESS;
}

int SandboxMonitor::ParseEventAction(const char *actionStr,
    enum DEC_POLICY_ACTION &action)
{
    if (actionStr == nullptr) {
        SANDBOX_LOGE("Event action is null");
        return SANDBOX_ERR_CONFIG_INVALID;
    }

    if (strcmp(actionStr, "allow") == 0) {
        action = DEC_POLICY_ACTION_ALLOW;
        return SANDBOX_SUCCESS;
    }

    if (strcmp(actionStr, "deny") == 0) {
        action = DEC_POLICY_ACTION_DENY;
        return SANDBOX_SUCCESS;
    }

    SANDBOX_LOGE("Unknown event answer action %{public}s", actionStr);
    return SANDBOX_ERR_CONFIG_INVALID;
}

/*
 * An answer to an ASK event, so allow and deny are the whole domain - ASK itself
 * would be circular and NONE means "not configured". ParseEventAction accepts
 * nothing else, so "unknown" marks a bug rather than an unhandled case.
 */
static const char *EventAnswerActionToStr(enum DEC_POLICY_ACTION action)
{
    switch (action) {
        case DEC_POLICY_ACTION_ALLOW: return "allow";
        case DEC_POLICY_ACTION_DENY: return "deny";
        default: return "unknown";
    }
}

int SandboxMonitor::WriteEventAnswer(uint64_t eventId, enum DEC_POLICY_ACTION action)
{
    DecEventAnswer answer = {
        .size = sizeof(answer),
        .reserved1 = 0,
        .eventId = eventId,
        .action = action,
        .reserved2 = 0
    };

    SANDBOX_LOGI("Write event answer, event id %{public}llu, action %{public}s",
        static_cast<unsigned long long>(eventId),
        EventAnswerActionToStr(action));

    ssize_t size;
    do {
        size = write(deviceFd_, &answer, sizeof(answer));
    } while (size < 0 && errno == EINTR);

    if (size < 0) {
        int error = errno;

        /*
         * Only a full device is worth retrying. Everything else - a rejected
         * answer comes back as EINVAL - fails identically no matter how often
         * the app resends, so the two must not share a return code: the app has
         * no other way to tell "try again" from "stop trying".
         */
        if (error == EAGAIN || error == EWOULDBLOCK) {
            SANDBOX_LOGW("Device is full, event answer for id %{public}llu can be resent",
                static_cast<unsigned long long>(eventId));
            return SANDBOX_ERR_DEVICE_BUSY;
        }

        SANDBOX_LOGE("Device rejected the event answer for id %{public}llu: %{public}s",
            static_cast<unsigned long long>(eventId), strerror(error));
        return SANDBOX_ERR_DEVICE_IO;
    }

    if (static_cast<size_t>(size) != sizeof(answer)) {
        SANDBOX_LOGE("Device accepted only %{public}d of %{public}d answer bytes; it is no "
            "longer in a known state", static_cast<int>(size), static_cast<int>(sizeof(answer)));
        return SANDBOX_ERR_DEVICE_IO;
    }

    return SANDBOX_SUCCESS;
}


int SandboxMonitor::HandleAddPolicy(const std::string &jsonBody, std::string *detail)
{
    if (state_ == MONITOR_STATE_DEGRADED || deviceFd_ < 0) {
        SANDBOX_LOGE("Refusing add policy, monitoring is no longer available");
        return SANDBOX_ERR_MONITOR_DEGRADED;
    }

    std::vector<SandboxPolicyRuleGroup> ruleGroups;

    int ret = ParseAddPolicy(jsonBody, ruleGroups);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    if (ruleGroups.empty()) {
        SANDBOX_LOGI("No operation control rule groups, skip add policy");
        return SANDBOX_SUCCESS;
    }

    /*
     * One shot at the whole policy: modules are independent, so a rule the
     * monitor refuses and a module the kernel rejects both cost their own module
     * and nothing else. Only a partial result carries a body, so this is also
     * the only path that produces one.
     */
    std::vector<PolicyScopeResult> results;
    ret = AddOperationControlPolicies(deviceFd_, ruleGroups, socketPath_, &results);
    if (detail != nullptr && ret == SANDBOX_ERR_SET_POLICY_PARTIAL) {
        *detail = ResponseBody::BuildAddPolicyResult(results);
    }
    return ret;
}

int SandboxMonitor::ParseAddPolicy(const std::string &jsonBody,
    std::vector<SandboxPolicyRuleGroup> &ruleGroups)
{
    int ret = CmdParser::ParseOperationControlPolicy(jsonBody, ruleGroups);
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Failed to parse operation control rule groups, ret %{public}d",
            ret);
        return ret;
    }
    if (ruleGroups.empty()) {
        SANDBOX_LOGE("Add policy message contains no operation control rule groups");
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    return SANDBOX_SUCCESS;
}

/*
 * Answer one app request.
 *
 * The response is queued rather than sent, so a full Tx buffer cannot cost the
 * app its answer: leaving it unanswered would strand a request the app still
 * believes is in flight. FlushSocketTxQueue sends it once EPOLLOUT arrives.
 *
 * The internal code stays in the log; the app gets the translated one.
 */
void SandboxMonitor::QueueResponse(const ParsedMessage &message)
{
    std::string detail;
    int ret = ValidateMessage(message);
    if (ret == SANDBOX_SUCCESS) {
        ret = DispatchSocketMessage(message, &detail);
        if (ret != SANDBOX_SUCCESS) {
            SANDBOX_LOGW("Failed to dispatch socket message type %{public}u, request %{public}u, "
                "ret %{public}d", message.header.msgType, message.header.requestId, ret);
        }
    }

    /*
     * Only a partial result carries a body. Every other code says all there is
     * to say on its own, and enforcing that here rather than trusting each
     * handler is what keeps the rule true as handlers are added.
     */
    const int32_t code = ToResponseCode(ret);
    if (code != SANDBOX_RSP_PARTIAL) {
        detail.clear();
    }

    PushResponse(message.header.requestId, code, std::move(detail));
}

MonitorAction SandboxMonitor::HandleSocketReadable()
{
    std::vector<ParsedMessage> messages;

    int ret = socket_->OnReadable(messages);

    // Whatever parsed is answered even when the read then failed: those requests
    // arrived, and their responses stay queued for the reconnect.
    for (const ParsedMessage &message : messages) {
        QueueResponse(message);
    }

    if (ret == SANDBOX_ERR_SOCKET_CLOSED) {
        SANDBOX_LOGE("Socket fd %{public}d closed by peer", socket_->GetFd());
        monitorError_ = ret;
        return MONITOR_ACTION_RECONNECT;
    }
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Failed to receive socket message, ret %{public}d", ret);
        monitorError_ = ret;
        return MONITOR_ACTION_RECONNECT;
    }

    return MONITOR_ACTION_NONE;
}

MonitorAction SandboxMonitor::HandleSocketWritable()
{
    int ret = socket_->OnWritable();
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Failed to flush socket Tx buffer, ret %{public}d", ret);
        monitorError_ = ret;
        return MONITOR_ACTION_RECONNECT;
    }

    return MONITOR_ACTION_NONE;
}

/*
 * EPOLLERR and EPOLLHUP are reported whether or not they were asked for, so the
 * fd is already unusable by the time either shows up. SO_ERROR is read purely to
 * name the cause; the action is the same either way.
 */
MonitorAction SandboxMonitor::CheckSocketFailureEvents(uint32_t events)
{
    if ((events & EPOLLERR) != 0) {
        int socketError = 0;
        socklen_t errorLength = sizeof(socketError);

        if (getsockopt(socket_->GetFd(), SOL_SOCKET, SO_ERROR, &socketError, &errorLength) == 0) {
            SANDBOX_LOGE("Socket fd %{public}d epoll error: %{public}s", socket_->GetFd(), strerror(socketError));
        } else {
            SANDBOX_LOGE("Failed to get socket fd %{public}d error: %{public}s", socket_->GetFd(), strerror(errno));
        }
        monitorError_ = SANDBOX_ERR_SOCKET_IO;
        return MONITOR_ACTION_RECONNECT;
    }

    if ((events & (EPOLLHUP | EPOLLRDHUP)) != 0) {
        SANDBOX_LOGE("Socket fd %{public}d disconnected", socket_->GetFd());
        monitorError_ = SANDBOX_ERR_SOCKET_CLOSED;
        return MONITOR_ACTION_RECONNECT;
    }

    return MONITOR_ACTION_NONE;
}

MonitorAction SandboxMonitor::ResumeSocketTx()
{
    // The Tx buffer may have drained, so hand it whatever is still queued. A
    // failure here leaves the front entry in place for the reconnect to replay.
    int ret = FlushSocketTxQueue();
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Failed to forward queued socket messages, ret %{public}d", ret);
        monitorError_ = ret;
        return MONITOR_ACTION_RECONNECT;
    }

    ret = UpdateSocketEpollEvents();
    if (ret != SANDBOX_SUCCESS) {
        monitorError_ = ret;
        return MONITOR_ACTION_STOP;
    }

    return MONITOR_ACTION_NONE;
}

/*
 * Four stages, stopping at the first that reports anything.
 *
 * The order is the contract, not a preference: one wakeup can carry EPOLLIN and
 * EPOLLRDHUP together when the peer sent a request and closed straight after, so
 * the data bits must be drained before the failure bits are allowed to tear the
 * channel down. ResumeSocketTx runs last because only it sees the buffer state
 * the first three stages left behind.
 */
MonitorAction SandboxMonitor::HandleSocketEvent(uint32_t events)
{
    if (socket_ == nullptr) {
        return MONITOR_ACTION_NONE;
    }

    if ((events & EPOLLIN) != 0) {
        MonitorAction action = HandleSocketReadable();
        if (action != MONITOR_ACTION_NONE) {
            return action;
        }
    }

    if ((events & EPOLLOUT) != 0) {
        MonitorAction action = HandleSocketWritable();
        if (action != MONITOR_ACTION_NONE) {
            return action;
        }
    }

    MonitorAction action = CheckSocketFailureEvents(events);
    if (action != MONITOR_ACTION_NONE) {
        return action;
    }

    return ResumeSocketTx();
}

/*
 * Handle the one event a read produced.
 *
 * Records are independent, so an unusable one costs only itself - there is no
 * stream position to recover and nothing queued behind it to discard.
 */
MonitorAction SandboxMonitor::ConsumeDeviceEvent(const uint8_t *data, size_t size)
{
    std::string jsonOutput;
    TlvEventParser parser;
    if (parser.ParseEvent(data, size, jsonOutput) != ParseStep::DONE) {
        LogEventBytes(data, size);
        SANDBOX_LOGE("Dropping unusable device event, ret %{public}d", parser.Error());
        return MONITOR_ACTION_SKIP;
    }

    int ret = DeliverDeviceEvent(parser.Header(), std::move(jsonOutput));
    if (ret == SANDBOX_SUCCESS) {
        return MONITOR_ACTION_NONE;
    }
    if (IsSocketChannelError(ret)) {
        // Peer loss found while sending rather than through EPOLLRDHUP.
        monitorError_ = ret;
        return MONITOR_ACTION_RECONNECT;
    }
    SANDBOX_LOGE("Failed to handle device message, ret %{public}d", ret);
    monitorError_ = ret;
    return MONITOR_ACTION_STOP;
}

MonitorAction SandboxMonitor::ReadDeviceEvents()
{
    while (true) {
        ssize_t size = read(deviceFd_, deviceReadBuffer_.data(),
            deviceReadBuffer_.size());
        if (size > 0) {
            MonitorAction action = ConsumeDeviceEvent(deviceReadBuffer_.data(),
                static_cast<size_t>(size));
            if (action != MONITOR_ACTION_NONE && action != MONITOR_ACTION_SKIP) {
                return action;
            }
            continue;
        }

        if (size == 0) {
            SANDBOX_LOGE("Device fd %{public}d reached EOF", deviceFd_);
            monitorError_ = SANDBOX_ERR_DEVICE_IO;
            return MONITOR_ACTION_DEGRADE;
        }

        if (errno == EINTR) {
            continue;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MONITOR_ACTION_NONE;
        }

        SANDBOX_LOGE("Failed to read device fd %{public}d: %{public}s",
            deviceFd_, strerror(errno));
        monitorError_ = SANDBOX_ERR_DEVICE_IO;
        return MONITOR_ACTION_DEGRADE;
    }
}

MonitorAction SandboxMonitor::HandleDeviceEvent(uint32_t events)
{
    // Reachable once the device has been closed by a DEGRADE.
    if (deviceFd_ < 0) {
        return MONITOR_ACTION_NONE;
    }

    /*
     * A dead device costs the monitor its whole purpose, but not the child's
     * life: it keeps running and still has to be reaped. So this degrades
     * instead of stopping, which also means the socket is closed for good
     * rather than reconnected - there would be nothing left to send over it.
     */
    if ((events & (EPOLLERR | EPOLLHUP)) != 0) {
        SANDBOX_LOGE("Device fd %{public}d epoll error, events %{public}u",
            deviceFd_, events);
        monitorError_ = SANDBOX_ERR_DEVICE_IO;
        return MONITOR_ACTION_DEGRADE;
    }

    if ((events & EPOLLIN) != 0) {
        MonitorAction action = ReadDeviceEvents();
        if (action != MONITOR_ACTION_NONE) {
            return action;
        }

        // Events parsed above may have queued messages, so the socket's EPOLLOUT
        // interest has to be brought up to date before going back to sleep.
        int ret = UpdateSocketEpollEvents();
        if (ret != SANDBOX_SUCCESS) {
            monitorError_ = ret;
            return MONITOR_ACTION_STOP;
        }
    }

    return MONITOR_ACTION_NONE;
}

/*
 * Hand one event to the socket, dealing with every way that can go wrong.
 *
 * Returns SANDBOX_SUCCESS whenever the caller may carry on, including when the
 * event was deliberately dropped. A non-success return means the channel itself
 * is suspect and the caller has to stop.
 */
int SandboxMonitor::SendEventReport(const DeviceEventHeader &header, bool needsAnswer,
    std::string jsonOutput)
{
    int ret = socket_->SendMessage(SANDBOX_SOCKET_MSG_EVENT_REPORT, jsonOutput);
    if (ret == SANDBOX_ERR_SOCKET_TX_FULL) {
        PushEventReport(header.eventId, needsAnswer, std::move(jsonOutput));
        return SANDBOX_SUCCESS;
    }
    if (ret == SANDBOX_ERR_SOCKET_MSG_TOO_LARGE) {
        // One malformed or oversized event must not take down the channel.
        SANDBOX_LOGE("Dropping oversized device event id %{public}llu",
            static_cast<unsigned long long>(header.eventId));
        return SANDBOX_SUCCESS;
    }
    if (ret != SANDBOX_SUCCESS) {
        SANDBOX_LOGE("Failed to send device event to socket, ret %{public}d", ret);
        // The peer may have died mid-send. Keep the event so a reconnect can
        // still deliver it, and let the caller tear the channel down.
        PushEventReport(header.eventId, needsAnswer, std::move(jsonOutput));
        return ret;
    }

    if (needsAnswer) {
        PushPendingAnswer(header.eventId);
    }

    return SANDBOX_SUCCESS;
}

/*
 * Decide where one parsed event goes: dropped, queued, or sent straight out.
 *
 * Same return contract as SendEventReport - success means the stream can carry
 * on, whether or not this particular event survived.
 */
int SandboxMonitor::DeliverDeviceEvent(const DeviceEventHeader &header, std::string jsonOutput)
{
    bool needsAnswer = false;
    switch (header.eventClass) {
        case DEC_EVENT_CLASS_ASK:
            needsAnswer = true;
            break;
        default:
            SANDBOX_LOGE("Rejecting event id %{public}llu of unsupported class %{public}u",
                static_cast<unsigned long long>(header.eventId), header.eventClass);
            return SANDBOX_SUCCESS;
    }

    /*
     * Straight to the socket only when there is nothing ahead of this event:
     * nothing queued, and nothing still draining from the last message. The
     * first keeps the app's stream in order; the second keeps txBuffer_ down to
     * one message, so backlog stays where it can still be evicted.
     */
    if (socket_ == nullptr || !socketTxQueue_.empty() || socket_->HasPendingTxData()) {
        if (reconnectAttemptsLeft_ <= 0 && socket_ == nullptr) {
            // No peer and no way back to one: nothing to buffer for.
            return SANDBOX_SUCCESS;
        }
        PushEventReport(header.eventId, needsAnswer, std::move(jsonOutput));
        return SANDBOX_SUCCESS;
    }

    return SendEventReport(header, needsAnswer, std::move(jsonOutput));
}


/*
 * The whole state machine, in one place.
 *
 * Handlers never change state themselves - they report what happened and this
 * decides what it means. Anyone asking "when can the monitor degrade" only has
 * to read this switch.
 *
 * Returns false when the loop should stop.
 */
bool SandboxMonitor::ApplyAction(MonitorAction action)
{
    switch (action) {
        case MONITOR_ACTION_NONE:
        case MONITOR_ACTION_SKIP:
            return true;

        case MONITOR_ACTION_RECONNECT:
            DropSocketChannel();
            return true;

        case MONITOR_ACTION_DEGRADE:
            // The device is what died, so stop listening to it as well.
            if (epollFd_ >= 0 && deviceFd_ >= 0) {
                (void)epoll_ctl(epollFd_, EPOLL_CTL_DEL, deviceFd_, nullptr);
            }
            SafeCloseFd(deviceFd_);
            devCtx_.fd = -1;
            Degrade();
            return true;

        case MONITOR_ACTION_CHILD_EXITED:
            return false;

        case MONITOR_ACTION_STOP:
            return false;

        default:
            SANDBOX_LOGW("Unknown monitor action %{public}d", static_cast<int>(action));
            return true;
    }
}

/*
 * Route one epoll event to its handler.
 *
 * Anything unroutable reports NONE rather than a failure: a null context or an
 * unknown type is the monitor's own bookkeeping being wrong, and dropping that
 * one event is better than tearing down a channel that still works.
 */
MonitorAction SandboxMonitor::DispatchEpollEvent(const struct epoll_event &event)
{
    MonitorEventContext *ctx = static_cast<MonitorEventContext *>(event.data.ptr);
    if (ctx == nullptr) {
        SANDBOX_LOGW("Received epoll event with null context");
        return MONITOR_ACTION_NONE;
    }

    switch (ctx->type) {
        case MONITOR_EVENT_CHILD_FD:
            return HandleChildExitEvent(event.events);

        case MONITOR_EVENT_SOCKET_FD:
            return HandleSocketEvent(event.events);

        case MONITOR_EVENT_DEVICE_FD:
            return HandleDeviceEvent(event.events);

        default:
            SANDBOX_LOGW("Unknown monitor event type %{public}d",
                static_cast<int>(ctx->type));
            return MONITOR_ACTION_NONE;
    }
}

// Handle one epoll_wait batch, stopping at the first event that ends the loop.
bool SandboxMonitor::ProcessEpollBatch(const struct epoll_event *events, int eventCount)
{
    for (int i = 0; i < eventCount; ++i) {
        if (!ApplyAction(DispatchEpollEvent(events[i]))) {
            return false;
        }
    }

    return true;
}

/*
 * Decide what Run() reports.
 *
 * childExitCode_ wins, so a failure the monitor recovered from - a reconnect, a
 * resync - can never leak into the return once the child has been reaped.
 *
 * Monitoring is an optional security enhancement: the parent falls back to
 * waiting for the child whenever this is negative, so the code exists only to
 * classify the exit. What actually happened was logged where it was detected.
 */
int SandboxMonitor::ResolveRunResult() const
{
    if (childExitCode_ != -1) {
        return childExitCode_;
    }

    if (monitorError_ != SANDBOX_SUCCESS) {
        return monitorError_;
    }

    return SANDBOX_ERR_MONITOR_STOPPED;
}

int SandboxMonitor::Run()
{
    if (epollFd_ < 0) {
        SANDBOX_LOGE("SandboxMonitor has not been initialized");
        return SANDBOX_ERR_BAD_PARAMETERS;
    }

    /*
     * The pidfd already covers an exit that happened during Init(), so this is
     * belt and braces: one non blocking reap before the loop, costing a syscall.
     */
    bool isRunning = ApplyAction(CheckChildExit(WNOHANG));

    struct epoll_event events[MAX_EPOLL_EVENTS] = {};

    while (isRunning) {
        // Blocks indefinitely unless a reconnect attempt is due.
        int eventCount = epoll_wait(epollFd_, events, MAX_EPOLL_EVENTS, NextEpollTimeout());
        if (eventCount < 0) {
            if (errno == EINTR) {
                continue;
            }

            SANDBOX_LOGE("epoll_wait failed: %{public}s", strerror(errno));
            monitorError_ = SANDBOX_ERR_EPOLL_FAILED;
            break;
        }

        isRunning = ProcessEpollBatch(events, eventCount);
        if (isRunning && reconnectAttemptsLeft_ > 0 && NextEpollTimeout() == 0) {
            TryReconnect();
        }
    }

    return ResolveRunResult();
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
