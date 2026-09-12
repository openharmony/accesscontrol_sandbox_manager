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

#ifndef CLAW_SANDBOX_SANDBOX_ERROR_H
#define CLAW_SANDBOX_SANDBOX_ERROR_H

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

/**
 * @brief claw_sandbox error code definitions
 *
 * All internal functions return these error codes, and main() returns them
 * as the process exit code. Error descriptions are printed to hilog via
 * SANDBOX_LOGE and to stderr via std::cerr.
 *
 * A code that can reach the app over the monitor socket also needs an entry in
 * RESPONSE_CODE_TABLE (sandbox_socket.h); without one it is reported as
 * SANDBOX_RSP_INTERNAL.
 *
 * The values are the process exit code and, through that table, what the app
 * sees. Renumbering is fine until this ships; after that a number stays put and
 * a freed one is not reused.
 */
enum SandboxError : int {
    SANDBOX_SUCCESS                = 0,    // Success
    SANDBOX_ERR_GENERIC            = -1,   // Generic error
    SANDBOX_ERR_BAD_PARAMETERS     = -2,   // Command line argument error
    SANDBOX_ERR_CMD_INVALID        = -3,   // --cmd argument invalid
    SANDBOX_ERR_CONFIG_INVALID     = -4,   // --config JSON invalid (format/field error)
    SANDBOX_ERR_TEMPLATE_INVALID   = -5,   // Built-in template config load or parse failed
    SANDBOX_ERR_PATH_EXISTS        = -6,   // Path already exists
    SANDBOX_ERR_PATH_CREATE_FAILED = -7,   // Directory creation failed
    SANDBOX_ERR_PATH_INVALID       = -8,   // Invalid path
    SANDBOX_ERR_NS_FAILED          = -9,   // Namespace operation failed (setns/unshare)
    SANDBOX_ERR_MOUNT_FAILED       = -10,  // Mount operation failed
    SANDBOX_ERR_UMOUNT_FAILED      = -11,  // Umount operation failed
    SANDBOX_ERR_CHDIR_FAILED       = -12,  // chdir failed
    SANDBOX_ERR_SET_TOKENID_FAILED = -13,  // SetSelfTokenId failed
    SANDBOX_ERR_SET_UGID_FAILED    = -14,  // Set UID/GID failed
    SANDBOX_ERR_SET_SECCOMP_FAILED = -15,  // Set Seccomp rules failed
    SANDBOX_ERR_SET_SELINUX_FAILED = -16,  // Set Selinux label failed
    SANDBOX_ERR_SET_CAP_FAILED     = -17,  // Drop Capability failed
    SANDBOX_ERR_SANDBOX_PATH_EXHAUSTED = -18,  // Sandbox path creation exhausted (all retries failed)
    SANDBOX_ERR_GEN_TOKENID_FAILED = -19,  // Generate tokenid failed
    SANDBOX_ERR_SET_PRCTL_FAILED   = -20,  // prctl operation failed
    SANDBOX_ERR_SET_POLICY_FAILED  = -21,  // Failed to deliver AgentLock policy to kernel
    SANDBOX_ERR_SET_PTOKENID_FAILED = -22,  // Set Parent Hap TokenID failed
    SANDBOX_ERR_SYMLINK_FAILED     = -23,  // Symlink failed
    SANDBOX_ERR_SET_AINFO_FAILED   = -24,  // Set ainfo failed
    SANDBOX_ERR_SET_XPM_FAILED     = -25,  // Set xpm owner id failed
    SANDBOX_ERR_SET_DEC_FAILED     = -26,  // Set dec policy failed
    SANDBOX_ERR_SET_ENCAPS_FAILED  = -27,  // Set encaps failed

    /* ---- socket transport and protocol: -28 .. -37 ---------------------- */
    SANDBOX_ERR_SOCKET_CLOSED          = -28,  // Socket closed by peer
    SANDBOX_ERR_SOCKET_IO              = -29,  // Socket read/write failed
    // Only ConnectToApp; the read and write paths report it as state, not error.
    SANDBOX_ERR_SOCKET_WOULD_BLOCK     = -30,  // connect would block, retry is up to the caller
    SANDBOX_ERR_SOCKET_MSG_TOO_LARGE   = -31,  // Socket message body too large
    SANDBOX_ERR_SOCKET_TX_FULL         = -32,  // Socket transmit buffer is full
    SANDBOX_ERR_SOCKET_PROTOCOL        = -33,  // Invalid socket protocol message
    SANDBOX_ERR_SOCKET_CREATE_FAILED   = -34,  // Failed to create Unix Domain Socket
    SANDBOX_ERR_SOCKET_CONNECT_FAILED  = -35,  // Failed to connect Unix Domain Socket
    SANDBOX_ERR_SOCKET_CONNECT_TIMEOUT = -36,  // Peer is listening but did not accept in time
    // A request arrived with requestId 0, which is reserved for messages the
    // monitor originates. Responses carry no body, so without a distinct
    // requestId the caller cannot tell which request a response belongs to.
    SANDBOX_ERR_REQUEST_ID_INVALID     = -37,

    /* ---- the DEC device: opening it, talking to it, reading its events --- */
    /*      -38 .. -42                                                       */
    SANDBOX_ERR_DEVICE_OPEN_FAILED     = -38,  // Failed to open sandbox device node
    // The device rejected the operation. Permanent as far as the caller is
    // concerned: the same request will be rejected again (see
    // SANDBOX_ERR_DEVICE_BUSY for the transient case).
    SANDBOX_ERR_DEVICE_IO              = -39,
    // The device had no room for the answer. Transient: resending the same
    // answer later is expected to work, which is why the pending-answer entry
    // is kept. Distinct from SANDBOX_ERR_DEVICE_IO, where resending cannot help.
    SANDBOX_ERR_DEVICE_BUSY            = -40,
    SANDBOX_ERR_DATA_CORRUPT           = -41,  // Invalid or incomplete device event data
    // A device event whose frame is fine but whose fields are not: a field over
    // its own length limit, or a tag that appeared twice. Distinct from
    // SANDBOX_ERR_DATA_CORRUPT because valLen still frames the event, so the
    // caller skips this one rather than resynchronising the whole stream.
    SANDBOX_ERR_EVENT_FIELD_INVALID    = -42,

    /* ---- the monitor's own lifecycle, and the child it watches: -43 .. -47  */
    SANDBOX_ERR_CHILD_WATCH_FAILED     = -43,  // could not watch the child process for exit
    SANDBOX_ERR_CHILD_WAIT_FAILED      = -44,  // waitpid failed
    SANDBOX_ERR_EPOLL_FAILED           = -45,  // epoll operation failed
    // Monitoring is gone for good: the device died or the reconnect budget ran
    // out. Unlike SANDBOX_ERR_EVENT_UNKNOWN this is not about one event id, so
    // the caller should stop sending answers rather than retry with another.
    SANDBOX_ERR_MONITOR_DEGRADED       = -46,
    // The monitor stopped without recording why. Only reached if a failure path
    // returns MONITOR_ACTION_STOP without setting monitorError_ first.
    SANDBOX_ERR_MONITOR_STOPPED        = -47,

    /* ---- what the app asks the monitor for: answers and policy: -48 .. -50 */
    // Malformed event answer payload. The caller may retry with a fixed payload.
    SANDBOX_ERR_EVENT_ANSWER_INVALID   = -48,
    // Answer refers to an event that was never reported, was already answered,
    // or has been evicted. This is permanent; retrying cannot succeed.
    SANDBOX_ERR_EVENT_UNKNOWN          = -49,
    // Some modules of an add-policy request reached the kernel and some did not.
    // Distinct from SANDBOX_ERR_SET_POLICY_FAILED (-21, in the launch block
    // above, which that path also uses) because the device state is now a mix of
    // old and new; the caller has to be told which is which.
    SANDBOX_ERR_SET_POLICY_PARTIAL     = -50,
};

/*
 * Process exit codes, as opposed to the internal error codes above. Here rather
 * than file local because two translation units and the unit tests all have to
 * agree on them - SIGNAL_EXIT_BASE used to be defined separately in
 * sandbox_manager.cpp and sandbox_monitor.cpp.
 */
// 128 + signal number, following the shell convention.
constexpr int SIGNAL_EXIT_BASE = 128;

// Reported when the sandbox refused to start the program because its monitor
// could not be brought up. EX_UNAVAILABLE from sysexits.h, picked so it cannot
// be confused with a code the program chose for itself (0-125), with the shell
// conventions (126/127), or with SIGNAL_EXIT_BASE + N.
constexpr int EXIT_MONITOR_UNAVAILABLE = 69;

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS

#endif // CLAW_SANDBOX_SANDBOX_ERROR_H
