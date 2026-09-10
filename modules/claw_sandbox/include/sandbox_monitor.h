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

#ifndef SANDBOX_MONITOR_H
#define SANDBOX_MONITOR_H

#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <sys/epoll.h>
#include <sys/types.h>
#include <vector>

#include "sandbox_cmd_parser.h"
#include "sandbox_error.h"
// Directly, for the same reason as in sandbox_policy.h: sandbox_cmd_parser.h
// only pulls it in under CONFIG_SHELL_SANDBOX, and the declarations below name
// SandboxPolicyRuleGroup and DEC_POLICY_ACTION outright.
#include "sandbox_op_control_policy.h"
#include "sandbox_socket.h"
#include "sandbox_device_event.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

enum MonitorEventType {
    MONITOR_EVENT_CHILD_FD,       // Pidfd that becomes readable when the child process exits
    MONITOR_EVENT_SOCKET_FD,      // Socket fd for communicating with upper-layer apps
    MONITOR_EVENT_DEVICE_FD       // Device fd for communicating with kernel device node
};

struct MonitorEventContext {
    MonitorEventType type;
    int fd;
};

// What ConnectToApp should do about a full listen backlog, the one condition an
// AF_UNIX connect() can report as retryable.
enum MonitorConnectMode {
    // Pre-fork: wait it out, there is no event loop to starve yet.
    MONITOR_CONNECT_WAIT_FOR_BACKLOG,
    // Reconnect: report it and let the caller's event loop pace the retries.
    MONITOR_CONNECT_SINGLE_ATTEMPT,
};

/*
 * What the loop should do about something that went wrong, decided where the
 * failure is understood rather than inferred later from an error code.
 *
 * Keeping this separate from the reason is what stops one return value from
 * having to mean "result" and "what now" at the same time.
 */
enum MonitorAction {
    MONITOR_ACTION_NONE,          // nothing to do, carry on
    MONITOR_ACTION_SKIP,          // drop this one event, the rest is fine
    MONITOR_ACTION_RECONNECT,     // peer is gone, buffer and reconnect
    MONITOR_ACTION_DEGRADE,       // security function is gone for good
    MONITOR_ACTION_CHILD_EXITED,  // the job is done, childExitCode_ is valid
    MONITOR_ACTION_STOP,          // the monitor's own plumbing broke
};

/*
 * How much of its job the monitor can still do.
 *
 * DEGRADED is the "just wait for the child" state: no channel, no forwarding,
 * nothing left but reaping. It is reached either by exhausting the reconnect
 * budget or by losing the device.
 */
enum MonitorState {
    MONITOR_STATE_ACTIVE,
    MONITOR_STATE_RECONNECTING,
    MONITOR_STATE_DEGRADED,
};

/*
 * A message the monitor owes the app but could not hand to the socket yet,
 * because the peer is gone or its Tx buffer is full.
 */
struct PendingSocketMessage {
    uint32_t msgType = 0;       // EVENT_REPORT or RESPONSE
    uint32_t requestId = 0;     // echoed for RESPONSE, always 0 for EVENT_REPORT
    int32_t result = 0;         // RESPONSE only
    uint64_t eventId = 0;       // ASK reports only, moves to pendingAnswers_ on send
    bool needsAnswer = false;
    std::string body;
};

// Everything SandboxMonitor needs to run. Grouped into a struct because the
// two pids and the two fds are trivially transposable as positional arguments.
struct MonitorConfig {
    pid_t childPid = -1;
    // Reconnect target. Empty when the caller opted out of the monitor channel.
    std::string socketPath;
    // Already connected by SandboxManager::ConnectMonitorSocket, or -1.
    int socketFd = -1;
    int deviceFd = -1;
};

class SandboxMonitor {
public:
    /*
     * Connect to the Unix Domain Socket the upper-layer app listens on. Runs
     * before the fork, so a bad path or a refused connection still fails the
     * launch.
     */
    static int ConnectToApp(const std::string &socketPath, int &socketFd,
        MonitorConnectMode mode = MONITOR_CONNECT_WAIT_FOR_BACKLOG);

    // Takes ownership of config.socketFd and config.deviceFd. socketFd may be -1:
    // the monitor then runs without a peer to forward DEC events to (see Init).
    explicit SandboxMonitor(MonitorConfig config);
    ~SandboxMonitor();

    /*
     * Initializes the child pidfd and epoll around the inherited, daemon-initialized
     * device fd and the already connected socket.
     *
     * A socket fd of -1 is not an error: the caller deliberately started the
     * sandbox without a monitor channel.
     */
    int Init();

    // Blocks and runs the event loop until the child process exits
    // or an unrecoverable monitor error occurs.
    int Run();

private:
    static void SafeCloseFd(int &fd);
    void CloseSocket();
    // Tolerate the loss of the peer mid-run: close the socket, keep both tables,
    // and start the bounded reconnect sequence. Only the first connect (in
    // SandboxManager, before the fork) is allowed to fail the sandbox launch.
    void DropSocketChannel();
    // No channel, no reconnect: the security function is gone for good.
    void Degrade();
    // Adopt a freshly connected fd and re-arm the socket half of the loop.
    int AdoptSocket(int socketFd);
    // One reconnect attempt. Gives up for good once the budget runs out.
    void TryReconnect();
    // Milliseconds until the next reconnect attempt, or -1 to block in epoll.
    int NextEpollTimeout() const;

    // Resource initialization.
    // Records the peer's pid and uid. Diagnostics only, never a gate.
    static void LogSocketPeer(int socketFd);
    int SetupChildExitFd();
    static int SetNonBlock(int fd);

    // Epoll management.
    int RegisterFdToEpoll(int fd, MonitorEventContext *ctx, uint32_t events);
    int UpdateSocketEpollEvents();

    /*
     * Event handlers report, Run() acts.
     *
     * Nothing in here changes state on its own - that all happens in one switch
     * in Run(), which is therefore the whole state machine and the only place
     * that has to be read to know when the monitor degrades.
     */
    MonitorAction HandleChildExitEvent(uint32_t events);
    MonitorAction HandleSocketEvent(uint32_t events);
    MonitorAction HandleDeviceEvent(uint32_t events);

    // The stages of HandleSocketEvent, declared in the order it runs them.
    // All four assume socket_ is non-null, which is its first check.
    MonitorAction HandleSocketReadable();
    MonitorAction HandleSocketWritable();
    MonitorAction CheckSocketFailureEvents(uint32_t events);
    MonitorAction ResumeSocketTx();

    // The stages of HandleDeviceEvent. Both assume deviceFd_ is open, which is
    // its first check. Not to be confused with the device read loop, which
    // throws the bytes away instead of parsing them.
    MonitorAction ReadDeviceEvents();
    // Handle the one event a read produced.
    MonitorAction ConsumeDeviceEvent(const uint8_t *data, size_t size);

    // The stages of Run's loop body.
    MonitorAction DispatchEpollEvent(const struct epoll_event &event);
    bool ProcessEpollBatch(const struct epoll_event *events, int eventCount);
    // Which of childExitCode_ / monitorError_ Run reports, once the loop ends.
    int ResolveRunResult() const;

    /*
     * Reap the child if it is reapable. waitOptions is passed straight to
     * waitpid: WNOHANG to ask, 0 to insist. See HandleChildExitEvent for why
     * both are needed.
     */
    MonitorAction CheckChildExit(int waitOptions);

    // Dispatch one app request and queue its response.
    void QueueResponse(const ParsedMessage &message);

    /*
     * Apply one action. The single point where state transitions happen.
     *
     * Only the action is consulted - never monitorError_. If a new failure path
     * ever needs the same action to behave differently, the fix is another
     * action, not a second input here.
     *
     * Returns false when the loop should stop.
     */
    bool ApplyAction(MonitorAction action);
    // Record a transition. The cause was already logged where it was detected.
    void SetState(MonitorState state);

    /*
     * Business routing.
     *
     * Everything reachable from here returns a plain int, and every one of those
     * ints becomes the result field of a RESPONSE. That is the rule for which
     * errors the app gets told about: not the value of the code, but whether it
     * came from processing something the app sent.
     */
    // The message-level half of validation, to the socket's frame-level half.
    int ValidateMessage(const ParsedMessage &message);
    // detail is optional and only ever set on failure: it carries the response
    // body explaining what was wrong, which the result code alone cannot.
    int DispatchSocketMessage(const ParsedMessage &message, std::string *detail = nullptr);
    int HandleAddPolicy(const std::string &jsonBody, std::string *detail = nullptr);
    int HandleEventAnswer(const std::string &jsonBody);

private:
    int ParseEventAnswer(const std::string &jsonBody,
        uint64_t &eventId, enum DEC_POLICY_ACTION &action);
    int ParseEventId(const char *eventIdStr, uint64_t &eventId);
    int ParseEventAction(const char *actionStr,
        enum DEC_POLICY_ACTION &action);
    int WriteEventAnswer(uint64_t eventId,
        enum DEC_POLICY_ACTION action);

    int ParseAddPolicy(const std::string &jsonBody,
        std::vector<SandboxPolicyRuleGroup> &ruleGroups);
    // Both return success whenever the monitor can carry on.
    int DeliverDeviceEvent(const DeviceEventHeader &header, std::string jsonOutput);
    int SendEventReport(const DeviceEventHeader &header, bool needsAnswer,
        std::string jsonOutput);

    // Queue a message for later delivery, evicting the oldest entry when either
    // the count or the byte budget is exceeded.
    void PushSocketMessage(PendingSocketMessage message);
    // Queue an event report for the app.
    void PushEventReport(uint64_t eventId, bool needsAnswer, std::string body);
    // Queue the response to one app request, with optional detail in the body.
    void PushResponse(uint32_t requestId, int32_t result, std::string body = "");
    // Record an ASK event as outstanding, evicting the oldest id when full.
    void PushPendingAnswer(uint64_t eventId);
    // Hand buffered events to the socket in order, stopping at the first one the
    // Tx buffer cannot absorb. Called on EPOLLOUT and after a reconnect.
    int FlushSocketTxQueue();
    // Drop both tables and stop tracking events. Entered when the reconnect
    // budget runs out, or when the caller never provided a socket at all.
    void DiscardAllEvents();

    pid_t childPid_ = -1;
    std::string socketPath_;

    // Null while the peer is gone. Events are then buffered rather than sent.
    std::unique_ptr<SandboxSocket> socket_;

    // Messages owed to the app but not handed to the socket yet, oldest first.
    std::deque<PendingSocketMessage> socketTxQueue_;
    size_t socketTxBytes_ = 0;
    // Ids of ASK events already reported and still waiting for an answer. Only
    // ids in here are accepted by HandleEventAnswer.
    std::deque<uint64_t> pendingAnswers_;

    // Reconnect state. reconnectDeadline_ is only meaningful while attempts
    // remain; once the budget is spent the monitor discards events for good.
    int reconnectAttemptsLeft_ = 0;
    std::chrono::steady_clock::time_point reconnectDeadline_{};

    MonitorState state_ = MONITOR_STATE_ACTIVE;

    int deviceFd_ = -1;
    int epollFd_ = -1;
    int childFd_ = -1;

    /*
     * Carriers for Run()'s return value only. MonitorAction is what drives the
     * loop; these just let the parent log a code on the way out.
     *
     * Failure sites record monitorError_ where they detect the failure, next to
     * the log line that explains it. childExitCode_ takes precedence in Run(),
     * so a value left behind by a failure the monitor recovered from - a
     * reconnect, a resync - can never leak into the return.
     */
    int childExitCode_ = -1;
    int monitorError_ = SANDBOX_SUCCESS;

    bool socketWriteEnabled_ = false;

    std::vector<uint8_t> deviceReadBuffer_;

    // Epoll contexts.
    MonitorEventContext childCtx_{MONITOR_EVENT_CHILD_FD, -1};
    MonitorEventContext sockCtx_{MONITOR_EVENT_SOCKET_FD, -1};
    MonitorEventContext devCtx_{MONITOR_EVENT_DEVICE_FD, -1};
};

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS

#endif // SANDBOX_MONITOR_H
