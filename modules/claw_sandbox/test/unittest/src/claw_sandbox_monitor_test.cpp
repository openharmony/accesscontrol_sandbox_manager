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

#include "claw_sandbox_monitor_test.h"
#include "cJSON.h"
#include "sandbox_error.h"
#include "sandbox_limits.h"
#include "sandbox_mock_state.h"

#include <cerrno>
#include <securec.h>
#include <climits>
#include <csignal>
#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <string>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

#define private public
#include "sandbox_monitor.h"
#include "sandbox_device_ioctl.h"
#include "sandbox_response.h"
#undef private

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
constexpr size_t MESSAGE_HEADER_SIZE = sizeof(MessageHeader);
constexpr size_t EVENT_HEADER_SIZE = sizeof(DeviceEventHeader);

// Send buffer FillSocketTxBuffer pins the socket to. Any value well under
// MAX_BODY_LENGTH does; the kernel enforces its own floor.
constexpr int SHRUNK_SNDBUF_BYTES = 4096;
constexpr size_t TLV_HEADER_SIZE = sizeof(TlvHeader);
constexpr uint16_t TAG_EVENT_NAME = 1;
constexpr uint64_t TEST_EVENT_ID = 0x1234;      // 4660 in decimal
constexpr int PEER_EXIT_OK = 7;
// Mirrors MONITOR_CONNECT_RETRY_BUDGET in sandbox_monitor.cpp.
constexpr int64_t CONNECT_RETRY_BUDGET_MS = 200;
constexpr int64_t CONNECT_BUDGET_SLACK_MS = 50;
constexpr int MAX_BACKLOG_FILL_ATTEMPTS = 16;
constexpr int RECONNECT_MAX_ATTEMPTS = 3;
constexpr int CHILD_WAIT_POLLS = 2000;
constexpr size_t PIPE_FILL_CHUNK = 4096;
constexpr int PEER_ALARM_SECONDS = 20;

// Mirrors DecEventAnswer in sandbox_monitor.cpp, which is file local there.
// Both reserved fields are part of the wire layout, not alignment slack:
// leaving reserved1 out would silently shift eventId and action by four bytes
// and every field comparison below would read the wrong offset.
struct TestDecEventAnswer {
    uint32_t size;
    uint32_t reserved1;
    uint64_t eventId;
    int32_t action;
    uint32_t reserved2;
};

static_assert(sizeof(TestDecEventAnswer) == 24, "Unexpected DEC event answer size");

/*
 * Scope.Type is the only recognized Scope field, and self_session the only value
 * it accepts.
 *
 * Process rather than Network: everything the socket delivers parses as
 * SANDBOX_POLICY_PARSE_DYNAMIC, which refuses a Network module outright.
 */
const char *VALID_POLICY_JSON = R"({"AddOperationControlRuleGroups":)"
    R"([{"Scope":{"Type":"self_session"},)"
    R"("Process":{"DefaultAction":"ask","DenyExecCmd":["rm"]}}]})";

// One rule group that disagrees with itself about the same path under the same
// operation. Within a group, not across: groups deliver independently and the
// object map does not span them, so a cross-group overlap is legal - and a
// second group would be rejected anyway for repeating self_session.
const char *CONFLICTING_POLICY_JSON = R"({"AddOperationControlRuleGroups":)"
    R"([{"Scope":{"Type":"self_session"},)"
    R"("File":{"DenyDelete":["/data/conflict"],)"
    R"("AllowDelete":["/data/conflict"]}}]})";

/*
 * Picks a directory the test can actually bind a Unix Domain Socket in.
 *
 * Probing by creating a file, not by access(W_OK): access() answers for the real
 * uid while the test then runs under the effective one, so it can refuse a
 * directory that is perfectly writable. Creating the file also covers a missing
 * directory in one step.
 *
 * TMPDIR and the binary's own directory lead the candidate list because both are
 * evidence rather than guesswork. sun_path is bounded here too, so an over-long
 * path fails as a bad temp directory instead of as a bind or connect error.
 */
std::string MakeSocketPath(const std::string &tag)
{
    const std::string leaf = "/claw_ut_mon_" + std::to_string(getpid()) + "_" + tag;

    std::vector<std::string> candidates;
    const char *tmpDir = getenv("TMPDIR");
    if (tmpDir != nullptr && tmpDir[0] == '/') {
        candidates.emplace_back(tmpDir);
    }

    char self[PATH_MAX] = {0};
    ssize_t selfLen = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (selfLen > 0) {
        const std::string exePath(self, static_cast<size_t>(selfLen));
        const size_t slash = exePath.rfind('/');
        if (slash != std::string::npos && slash > 0) {
            candidates.emplace_back(exePath.substr(0, slash));
        }
    }

    candidates.emplace_back("/data/test");
    candidates.emplace_back("/data/local/tmp");
    candidates.emplace_back("/data");
    candidates.emplace_back("/tmp");
    candidates.emplace_back(".");

    std::string attempts;
    for (const std::string &dir : candidates) {
        const std::string path = dir + leaf;
        if (path.length() >= sizeof(sockaddr_un::sun_path)) {
            attempts += dir + ": path too long for sun_path; ";
            continue;
        }

        int fd = open(path.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            attempts += dir + ": " + strerror(errno) + "; ";
            continue;
        }
        close(fd);
        // The socket has to bind this name itself, so hand it back unoccupied.
        unlink(path.c_str());
        return path;
    }

    ADD_FAILURE() << "No writable directory for a test socket. uid=" << getuid() <<
                     " euid=" << geteuid() << ". Tried " << attempts;
    return "";
}

/*
 * Fills the socket Tx buffer until it refuses a message of any size at all.
 *
 * The descending stride is the point. The cap is a byte budget, so "a 1 MB
 * message no longer fits" leaves almost a megabyte free and "a 1 KB one no
 * longer fits" still leaves room for the event JSON the callers send next -
 * both look full and behave empty. Only after a header-only message is refused
 * is the free space smaller than any message can be.
 *
 * Returns false rather than asserting, so the caller decides if that is fatal.
 */
bool FillSocketTxBuffer(SandboxSocket &socket)
{
    constexpr size_t TOP_UP_BODY_LENGTH = 1024;
    static const size_t BODY_SIZES[] = {MAX_BODY_LENGTH, TOP_UP_BODY_LENGTH, 0};

    /*
     * Nothing queues in txBuffer_ until the kernel stops accepting, so how many
     * sends this takes depends on the socket send buffer - and leaving that to
     * the host makes the bound below a guess. On a stock Linux wmem_default is
     * around 208 KB and the first pass needs three sends; raise it past ~900 KB
     * and the pass runs out of attempts with everything still accepted, which
     * surfaces as an unexplained ASSERT_TRUE failure in three callers. Pin it
     * instead. The kernel doubles the value and clamps it to its own floor, so
     * the effective buffer is a few KB either way - always under one message.
     */
    int sendBufferBytes = SHRUNK_SNDBUF_BYTES;
    if (setsockopt(socket.GetFd(), SOL_SOCKET, SO_SNDBUF,
        &sendBufferBytes, sizeof(sendBufferBytes)) != 0) {
        return false;
    }

    // Bounds the next pass: after a refusal at one stride, less than that stride
    // is left free.
    size_t headroom = MAX_TX_BUFFER_SIZE;

    for (size_t bodySize : BODY_SIZES) {
        const std::string body(bodySize, 'z');
        const size_t stride = sizeof(MessageHeader) + bodySize;
        // Twice what the headroom alone accounts for, plus slack: with the send
        // buffer pinned above, the kernel absorbs less than one message before
        // anything starts queueing, so the slack has a known bound.
        const int attempts = static_cast<int>(headroom / stride) * 2 + 8;

        int i = 0;
        for (; i < attempts; ++i) {
            int ret = socket.SendMessage(SANDBOX_SOCKET_MSG_EVENT_REPORT, body);
            if (ret == SANDBOX_ERR_SOCKET_TX_FULL) {
                break;
            }
            if (ret != SANDBOX_SUCCESS) {
                return false;
            }
        }
        if (i == attempts) {
            return false;
        }
        headroom = stride;
    }

    return socket.HasPendingTxData();
}

// Keeps the many SandboxMonitor constructions in this file readable.
MonitorConfig MakeConfig(pid_t childPid, int socketFd, int deviceFd,
    std::string socketPath = "")
{
    MonitorConfig config = {
        .childPid = childPid,
        .socketPath = std::move(socketPath),
        .socketFd = socketFd,
        .deviceFd = deviceFd
    };
    return config;
}

int64_t NowMs()
{
    struct timespec now = {};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    return static_cast<int64_t>(now.tv_sec) * 1000 + now.tv_nsec / 1000000;
}

// Listening Unix Domain Socket standing in for the upper layer application.
class UdsListener {
public:
    explicit UdsListener(const std::string &path, int backlog = 4) : path_(path)
    {
        if (path_.empty() || path_.length() >= sizeof(sockaddr_un::sun_path)) {
            return;
        }
        unlink(path_.c_str());

        fd_ = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd_ < 0) {
            return;
        }

        struct sockaddr_un addr = {};
        addr.sun_family = AF_UNIX;
        if (memcpy_s(addr.sun_path, sizeof(addr.sun_path),
            path_.c_str(), path_.length() + 1) != 0) {
            close(fd_);
            fd_ = -1;
            return;
        }
        socklen_t addrLength = static_cast<socklen_t>(
            offsetof(struct sockaddr_un, sun_path) + path_.length() + 1);

        if (bind(fd_, reinterpret_cast<struct sockaddr *>(&addr), addrLength) < 0 ||
            listen(fd_, backlog) < 0) {
            close(fd_);
            fd_ = -1;
            return;
        }
        valid_ = true;
    }

    ~UdsListener()
    {
        if (fd_ >= 0) {
            close(fd_);
        }
        if (!path_.empty()) {
            unlink(path_.c_str());
        }
    }

    bool Valid() const
    {
        return valid_;
    }

    int Fd() const
    {
        return fd_;
    }

private:
    std::string path_;
    int fd_ = -1;
    bool valid_ = false;
};

bool WriteAllFd(int fd, const void *data, size_t length)
{
    const char *cursor = static_cast<const char *>(data);
    size_t offset = 0;
    while (offset < length) {
        ssize_t n = write(fd, cursor + offset, length - offset);
        if (n > 0) {
            offset += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

bool ReadExactFd(int fd, void *data, size_t length)
{
    char *cursor = static_cast<char *>(data);
    size_t offset = 0;
    while (offset < length) {
        ssize_t n = read(fd, cursor + offset, length - offset);
        if (n > 0) {
            offset += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

std::string BuildValidMessage(uint32_t msgType, const std::string &body, uint32_t requestId)
{
    MessageHeader header = {};
    header.magic = SANDBOX_SOCKET_MAGIC;
    header.version = SANDBOX_SOCKET_VERSION;
    header.bodyLength = static_cast<uint32_t>(body.size());
    header.msgType = msgType;
    header.requestId = requestId;
    header.result = 0;

    std::string raw(reinterpret_cast<const char *>(&header), MESSAGE_HEADER_SIZE);
    raw += body;
    return raw;
}

bool ReadMessage(int fd, MessageHeader &header, std::string &body)
{
    if (!ReadExactFd(fd, &header, MESSAGE_HEADER_SIZE)) {
        return false;
    }
    body.assign(header.bodyLength, '\0');
    if (header.bodyLength == 0) {
        return true;
    }
    return ReadExactFd(fd, &body[0], header.bodyLength);
}

// One device event carrying a single event_name string TLV.
std::vector<uint8_t> BuildDeviceEvent(uint64_t eventId, const std::string &eventName,
    uint32_t eventClass = DEC_EVENT_CLASS_ASK, uint32_t version = DEVICE_EVENT_VERSION)
{
    std::vector<uint8_t> payload;
    TlvHeader tlv = {};
    tlv.tag = TAG_EVENT_NAME;
    tlv.length = static_cast<uint16_t>(eventName.size());

    const uint8_t *tlvBytes = reinterpret_cast<const uint8_t *>(&tlv);
    payload.insert(payload.end(), tlvBytes, tlvBytes + TLV_HEADER_SIZE);
    payload.insert(payload.end(), eventName.begin(), eventName.end());

    DeviceEventHeader header = {};
    header.version = version;
    header.eventClass = eventClass;
    header.eventType = 1;
    header.valLen = static_cast<uint32_t>(payload.size());
    header.eventId = eventId;

    std::vector<uint8_t> event;
    const uint8_t *headerBytes = reinterpret_cast<const uint8_t *>(&header);
    event.insert(event.end(), headerBytes, headerBytes + EVENT_HEADER_SIZE);
    event.insert(event.end(), payload.begin(), payload.end());
    return event;
}

// The request ids the peer stamps on the two requests it sends; the monitor
// must echo each one back on its response.
constexpr uint32_t PEER_POLICY_REQUEST_ID = 101;
constexpr uint32_t PEER_ANSWER_REQUEST_ID = 102;

/*
 * Which step of the peer flow failed, carried out through the child's exit code.
 * Named rather than bare numbers: the parent prints this when the run fails, and
 * a bare "step 22" meant counting return statements to find out what broke.
 * Starts past PEER_EXIT_OK so a failed step can never read as success.
 */
enum PeerStep : int {
    // Internal only: a phase that passed. RunPeerSide never returns it, so it
    // never becomes an exit code and cannot be confused with PEER_EXIT_OK.
    PEER_STEP_OK = 0,
    PEER_STEP_ACCEPT = PEER_EXIT_OK + 1,
    PEER_STEP_SEND_EVENT,
    PEER_STEP_READ_REPORT,
    PEER_STEP_REPORT_TYPE,
    PEER_STEP_REPORT_BODY,
    PEER_STEP_SEND_POLICY,
    PEER_STEP_READ_POLICY_REPLY,
    PEER_STEP_POLICY_REPLY,
    PEER_STEP_SEND_ANSWER,
    PEER_STEP_READ_DEVICE_ANSWER,
    PEER_STEP_DEVICE_ANSWER,
    PEER_STEP_READ_ANSWER_REPLY,
    PEER_STEP_ANSWER_REPLY,
    PEER_STEP_RESUMED_FROM_PAUSE,
};

const char *PeerStepName(int step)
{
    switch (step) {
        case PEER_STEP_ACCEPT: return "accept the monitor connection";
        case PEER_STEP_SEND_EVENT: return "write the device event";
        case PEER_STEP_READ_REPORT: return "read the event report";
        case PEER_STEP_REPORT_TYPE: return "event report message type";
        case PEER_STEP_REPORT_BODY: return "event report body";
        case PEER_STEP_SEND_POLICY: return "send the add policy request";
        case PEER_STEP_READ_POLICY_REPLY: return "read the add policy response";
        case PEER_STEP_POLICY_REPLY: return "add policy response contents";
        case PEER_STEP_SEND_ANSWER: return "send the event answer";
        case PEER_STEP_READ_DEVICE_ANSWER: return "read the answer off the device";
        case PEER_STEP_DEVICE_ANSWER: return "answer contents at the device";
        case PEER_STEP_READ_ANSWER_REPLY: return "read the event answer response";
        case PEER_STEP_ANSWER_REPLY: return "event answer response contents";
        case PEER_STEP_RESUMED_FROM_PAUSE: return "pause() returned unexpectedly";
        default: return "unknown step";
    }
}

// Application side of the full flow test. Runs in a forked child and returns
// a distinct exit code per failing step so a broken run is diagnosable.
// 1. The kernel reports an event; it must arrive as an EVENT_REPORT.
static int PeerCheckEventReport(int conn, int devFd)
{
    std::vector<uint8_t> event = BuildDeviceEvent(TEST_EVENT_ID, "file_open");
    if (!WriteAllFd(devFd, event.data(), event.size())) {
        return PEER_STEP_SEND_EVENT;
    }

    MessageHeader header = {};
    std::string body;
    if (!ReadMessage(conn, header, body)) {
        return PEER_STEP_READ_REPORT;
    }
    if (header.msgType != SANDBOX_SOCKET_MSG_EVENT_REPORT) {
        return PEER_STEP_REPORT_TYPE;
    }
    if (body.find("file_open") == std::string::npos ||
        body.find("4660") == std::string::npos) {
        return PEER_STEP_REPORT_BODY;
    }
    return PEER_STEP_OK;
}

// 2. An add policy request must be answered with a success response.
static int PeerCheckAddPolicy(int conn)
{
    std::string request = BuildValidMessage(SANDBOX_SOCKET_MSG_ADD_POLICY,
        VALID_POLICY_JSON, PEER_POLICY_REQUEST_ID);
    if (!WriteAllFd(conn, request.data(), request.size())) {
        return PEER_STEP_SEND_POLICY;
    }

    MessageHeader header = {};
    std::string body;
    if (!ReadMessage(conn, header, body)) {
        return PEER_STEP_READ_POLICY_REPLY;
    }
    if (header.msgType != SANDBOX_SOCKET_MSG_RESPONSE ||
        header.requestId != PEER_POLICY_REQUEST_ID ||
        header.result != SANDBOX_SUCCESS) {
        return PEER_STEP_POLICY_REPLY;
    }
    return PEER_STEP_OK;
}

// 3. An event answer must reach the device and be acknowledged.
static int PeerCheckEventAnswer(int conn, int devFd)
{
    std::string request = BuildValidMessage(SANDBOX_SOCKET_MSG_EVENT_ANSWER,
        R"({"event_id":"4660","action":"allow"})", PEER_ANSWER_REQUEST_ID);
    if (!WriteAllFd(conn, request.data(), request.size())) {
        return PEER_STEP_SEND_ANSWER;
    }

    TestDecEventAnswer answer = {};
    if (!ReadExactFd(devFd, &answer, sizeof(answer))) {
        return PEER_STEP_READ_DEVICE_ANSWER;
    }
    if (answer.size != sizeof(answer) || answer.eventId != TEST_EVENT_ID ||
        answer.action != static_cast<int32_t>(DEC_POLICY_ACTION_ALLOW)) {
        return PEER_STEP_DEVICE_ANSWER;
    }

    MessageHeader header = {};
    std::string body;
    if (!ReadMessage(conn, header, body)) {
        return PEER_STEP_READ_ANSWER_REPLY;
    }
    if (header.msgType != SANDBOX_SOCKET_MSG_RESPONSE ||
        header.requestId != PEER_ANSWER_REQUEST_ID ||
        header.result != SANDBOX_SUCCESS) {
        return PEER_STEP_ANSWER_REPLY;
    }
    return PEER_STEP_OK;
}

int RunPeerSide(int listenFd, int devFd, int releaseFd)
{
    int conn = accept(listenFd, nullptr, nullptr);
    if (conn < 0) {
        return PEER_STEP_ACCEPT;
    }

    int step = PeerCheckEventReport(conn, devFd);
    if (step != PEER_STEP_OK) {
        return step;
    }
    step = PeerCheckAddPolicy(conn);
    if (step != PEER_STEP_OK) {
        return step;
    }
    step = PeerCheckEventAnswer(conn, devFd);
    if (step != PEER_STEP_OK) {
        return step;
    }

    // 4. Release the monitored child and keep the connection open, so the
    //    monitor stops because the child exited and not because of a hangup.
    close(releaseFd);
    pause();
    return PEER_STEP_RESUMED_FROM_PAUSE;
}

// Opens a socket pair, returning false when the platform refuses.
bool MakeSocketPairFds(int &first, int &second)
{
    int fds[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        return false;
    }
    first = fds[0];
    second = fds[1];
    return true;
}
} // namespace

void ClawSandboxMonitorTest::SetUpTestCase() {}
void ClawSandboxMonitorTest::TearDownTestCase() {}

/*
 * Reset the whole struct, not the fields that happen to matter today.
 *
 * These used to miss mockFd: a test points it at a real fd, the fd is closed,
 * and the stale number survives into the next test - where any open() that gets
 * it back has its ioctls silently answered by the mock. A default-constructed
 * value also cannot forget a field added later.
 */
void ClawSandboxMonitorTest::SetUp()
{
    g_ioctlMockState = IoctlMockState{};
}

void ClawSandboxMonitorTest::TearDown()
{
    g_ioctlMockState = IoctlMockState{};
}

/**
 * @tc.name: MonitorConstruct001
 * @tc.desc: The monitor adopts the socket it is handed, and tolerates not getting one
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorConstruct001, TestSize.Level0)
{
    int first = -1;
    int second = -1;
    ASSERT_TRUE(MakeSocketPairFds(first, second));

    {
        SandboxMonitor monitor(MakeConfig(4321, first, -1));
        EXPECT_EQ(4321, monitor.childPid_);
        EXPECT_EQ(-1, monitor.deviceFd_);
        EXPECT_TRUE(monitor.socket_ != nullptr);
        EXPECT_EQ(first, monitor.sockCtx_.fd);
        EXPECT_EQ(SANDBOX_SUCCESS, monitor.monitorError_);
        EXPECT_EQ(-1, monitor.childExitCode_);
    }

    close(second);

    // No socket at all is a valid state: the caller opted out of the channel.
    SandboxMonitor without(MakeConfig(4321, -1, -1));
    EXPECT_TRUE(without.socket_ == nullptr);
    EXPECT_EQ(-1, without.sockCtx_.fd);
}

/**
 * @tc.name: MonitorInit001
 * @tc.desc: Init rejects an invalid child pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorInit001, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(0, -1, -1));
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, monitor.Init());

    SandboxMonitor negative(MakeConfig(-5, -1, -1));
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, negative.Init());
}

/**
 * @tc.name: MonitorInit002
 * @tc.desc: Init reports the device as unavailable when no DEC fd was handed over
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorInit002, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));
    EXPECT_EQ(SANDBOX_ERR_DEVICE_OPEN_FAILED, monitor.Init());
    // Nothing must have been wired up on this early exit.
    EXPECT_LT(monitor.childFd_, 0);
}

/**
 * @tc.name: MonitorInit003
 * @tc.desc: Without a socket the monitor still runs and drains the device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorInit003, TestSize.Level0)
{
    int deviceFd = -1;
    int kernelFd = -1;
    ASSERT_TRUE(MakeSocketPairFds(deviceFd, kernelFd));

    {
        SandboxMonitor monitor(MakeConfig(getpid(), -1, deviceFd));
        EXPECT_EQ(SANDBOX_SUCCESS, monitor.Init());
        EXPECT_TRUE(monitor.socket_ == nullptr);
        EXPECT_GE(monitor.childFd_, 0);
        // No socket and no path to reconnect to, so nothing is tracked.
        EXPECT_TRUE(monitor.socketTxQueue_.empty());
        EXPECT_TRUE(monitor.pendingAnswers_.empty());
    }

    close(kernelFd);
}

/**
 * @tc.name: MonitorInit004
 * @tc.desc: Init refuses to run twice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorInit004, TestSize.Level0)
{
    int deviceFd = open("/dev/null", O_RDWR | O_CLOEXEC);
    ASSERT_GE(deviceFd, 0);
    int epollFd = epoll_create1(EPOLL_CLOEXEC);
    ASSERT_GE(epollFd, 0);

    SandboxMonitor monitor(MakeConfig(getpid(), -1, deviceFd));
    monitor.epollFd_ = epollFd;  // pretend a previous Init already succeeded
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, monitor.Init());
}

/**
 * @tc.name: MonitorConnectToApp001
 * @tc.desc: ConnectToApp rejects an unusable path and a listener that is not there
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorConnectToApp001, TestSize.Level0)
{
    int socketFd = 0;
    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, SandboxMonitor::ConnectToApp("", socketFd));
    EXPECT_EQ(-1, socketFd);

    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID, SandboxMonitor::ConnectToApp("relative.socket", socketFd));
    EXPECT_EQ(-1, socketFd);

    EXPECT_EQ(SANDBOX_ERR_PATH_INVALID,
        SandboxMonitor::ConnectToApp("/" + std::string(sizeof(sockaddr_un::sun_path), 'a'), socketFd));
    EXPECT_EQ(-1, socketFd);

    // A well formed path that nobody listens on must fail the connect, which is
    // what lets SandboxManager abort the launch before forking.
    std::string path = MakeSocketPath("absent");
    ASSERT_FALSE(path.empty());
    int64_t start = NowMs();
    EXPECT_EQ(SANDBOX_ERR_SOCKET_CONNECT_FAILED, SandboxMonitor::ConnectToApp(path, socketFd));
    EXPECT_EQ(-1, socketFd);
    // ENOENT is final on the first attempt, so none of the retry budget is spent.
    EXPECT_LT(NowMs() - start, CONNECT_RETRY_BUDGET_MS / 2);
}

/**
 * @tc.name: MonitorConnectToApp003
 * @tc.desc: A listener that never accepts fails the connect once the deadline expires
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorConnectToApp003, TestSize.Level1)
{
    std::string path = MakeSocketPath("backlog");
    ASSERT_FALSE(path.empty());

    // Smallest backlog the kernel will take, and nobody ever calls accept().
    UdsListener listener(path, 1);
    ASSERT_TRUE(listener.Valid());

    // Hold every successful connection open, otherwise the backlog slot is freed.
    std::vector<int> pending;
    int ret = SANDBOX_SUCCESS;
    int64_t elapsed = 0;
    for (int i = 0; i < MAX_BACKLOG_FILL_ATTEMPTS; ++i) {
        int socketFd = -1;
        int64_t start = NowMs();
        ret = SandboxMonitor::ConnectToApp(path, socketFd);
        elapsed = NowMs() - start;
        if (ret != SANDBOX_SUCCESS) {
            break;
        }
        pending.push_back(socketFd);
    }

    EXPECT_EQ(SANDBOX_ERR_SOCKET_CONNECT_TIMEOUT, ret);
    // The retry budget must actually have been spent before giving up.
    EXPECT_GE(elapsed, CONNECT_RETRY_BUDGET_MS - CONNECT_BUDGET_SLACK_MS);

    for (int fd : pending) {
        close(fd);
    }
}

/**
 * @tc.name: MonitorConnectToApp004
 * @tc.desc: Single attempt mode reports a full backlog immediately instead of waiting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorConnectToApp004, TestSize.Level0)
{
    std::string path = MakeSocketPath("single_attempt");
    ASSERT_FALSE(path.empty());

    UdsListener listener(path, 1);
    ASSERT_TRUE(listener.Valid());

    std::vector<int> pending;
    int ret = SANDBOX_SUCCESS;
    int64_t elapsed = 0;
    for (int i = 0; i < MAX_BACKLOG_FILL_ATTEMPTS; ++i) {
        int socketFd = -1;
        int64_t start = NowMs();
        ret = SandboxMonitor::ConnectToApp(path, socketFd,
            MONITOR_CONNECT_SINGLE_ATTEMPT);
        elapsed = NowMs() - start;
        if (ret != SANDBOX_SUCCESS) {
            break;
        }
        pending.push_back(socketFd);
    }

    // The reconnect loop paces its own retries, so a busy backlog must come back
    // at once rather than blocking the event loop for the whole budget.
    EXPECT_EQ(SANDBOX_ERR_SOCKET_WOULD_BLOCK, ret);
    EXPECT_LT(elapsed, CONNECT_RETRY_BUDGET_MS / 2);

    for (int fd : pending) {
        close(fd);
    }
}

/**
 * @tc.name: MonitorConnectToApp002
 * @tc.desc: ConnectToApp hands back a non-blocking, close-on-exec fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorConnectToApp002, TestSize.Level0)
{
    std::string path = MakeSocketPath("connect");
    ASSERT_FALSE(path.empty());
    UdsListener listener(path);
    ASSERT_TRUE(listener.Valid());

    int socketFd = -1;
    ASSERT_EQ(SANDBOX_SUCCESS, SandboxMonitor::ConnectToApp(path, socketFd));
    ASSERT_GE(socketFd, 0);
    // Non-blocking so the event loop can never be parked, close-on-exec so the
    // sandboxed program never inherits the app channel.
    EXPECT_NE(0, fcntl(socketFd, F_GETFL, 0) & O_NONBLOCK);
    EXPECT_NE(0, fcntl(socketFd, F_GETFD, 0) & FD_CLOEXEC);
    close(socketFd);
}

/**
 * @tc.name: MonitorInit007
 * @tc.desc: Init wires up the child pidfd, socket, device and epoll when the peer matches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorInit007, TestSize.Level0)
{
    std::string path = MakeSocketPath("init");
    ASSERT_FALSE(path.empty());
    UdsListener listener(path);
    ASSERT_TRUE(listener.Valid());

    int deviceFd = -1;
    int kernelFd = -1;
    ASSERT_TRUE(MakeSocketPairFds(deviceFd, kernelFd));

    int socketFd = -1;
    ASSERT_EQ(SANDBOX_SUCCESS, SandboxMonitor::ConnectToApp(path, socketFd));

    {
        SandboxMonitor monitor(MakeConfig(getpid(), socketFd, deviceFd));
        ASSERT_EQ(SANDBOX_SUCCESS, monitor.Init());

        EXPECT_GE(monitor.epollFd_, 0);
        EXPECT_GE(monitor.childFd_, 0);
        EXPECT_TRUE(monitor.socket_ != nullptr);
        EXPECT_FALSE(monitor.socketWriteEnabled_);
        EXPECT_EQ(monitor.deviceFd_, monitor.devCtx_.fd);
        EXPECT_EQ(monitor.childFd_, monitor.childCtx_.fd);
        // The device fd must have been switched to non blocking mode.
        EXPECT_NE(0, fcntl(monitor.deviceFd_, F_GETFL, 0) & O_NONBLOCK);
    }

    close(kernelFd);
}

/**
 * @tc.name: MonitorSetNonBlock001
 * @tc.desc: SetNonBlock validates the fd and applies O_NONBLOCK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorSetNonBlock001, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, monitor.SetNonBlock(-1));

    int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    ASSERT_GE(fd, 0);
    EXPECT_EQ(SANDBOX_SUCCESS, monitor.SetNonBlock(fd));
    EXPECT_NE(0, fcntl(fd, F_GETFL, 0) & O_NONBLOCK);
    close(fd);

    // A closed fd can no longer be configured.
    EXPECT_EQ(SANDBOX_ERR_SOCKET_IO, monitor.SetNonBlock(fd));
}

/**
 * @tc.name: MonitorLogSocketPeer001
 * @tc.desc: Reading the peer credential never gates the connection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorLogSocketPeer001, TestSize.Level0)
{
    int first = -1;
    int second = -1;
    ASSERT_TRUE(MakeSocketPairFds(first, second));

    // Diagnostics only: it must tolerate both a real socket and an fd that has
    // no peer credential at all, without reporting anything back.
    SandboxMonitor::LogSocketPeer(first);

    int pipeFds[2] = {-1, -1};
    ASSERT_EQ(0, pipe(pipeFds));
    SandboxMonitor::LogSocketPeer(pipeFds[0]);

    close(pipeFds[0]);
    close(pipeFds[1]);
    close(first);
    close(second);
}

/**
 * @tc.name: MonitorSafeCloseFd001
 * @tc.desc: SafeCloseFd ignores an unset fd and clears the one it closes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorSafeCloseFd001, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));

    int unset = -1;
    monitor.SafeCloseFd(unset);
    EXPECT_EQ(-1, unset);

    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    ASSERT_GE(fd, 0);
    int copy = fd;
    monitor.SafeCloseFd(fd);
    EXPECT_EQ(-1, fd);
    EXPECT_EQ(-1, fcntl(copy, F_GETFL, 0));
}

/**
 * @tc.name: MonitorCloseSocket001
 * @tc.desc: CloseSocket is a no-op without a socket and clears the state with one
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorCloseSocket001, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));
    monitor.CloseSocket();
    EXPECT_TRUE(monitor.socket_ == nullptr);

    int first = -1;
    int second = -1;
    ASSERT_TRUE(MakeSocketPairFds(first, second));

    monitor.socket_ = std::make_unique<SandboxSocket>(first);
    monitor.sockCtx_.fd = first;
    monitor.socketWriteEnabled_ = true;

    monitor.CloseSocket();
    EXPECT_TRUE(monitor.socket_ == nullptr);
    EXPECT_EQ(-1, monitor.sockCtx_.fd);
    EXPECT_FALSE(monitor.socketWriteEnabled_);

    close(second);
}

/**
 * @tc.name: MonitorParseEventId001
 * @tc.desc: ParseEventId accepts plain decimal ids including the 64 bit maximum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorParseEventId001, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));
    uint64_t eventId = 1;

    EXPECT_EQ(SANDBOX_SUCCESS, monitor.ParseEventId("0", eventId));
    EXPECT_EQ(0u, eventId);

    EXPECT_EQ(SANDBOX_SUCCESS, monitor.ParseEventId("4660", eventId));
    EXPECT_EQ(4660u, eventId);

    EXPECT_EQ(SANDBOX_SUCCESS, monitor.ParseEventId("18446744073709551615", eventId));
    EXPECT_EQ(18446744073709551615ULL, eventId);
}

/**
 * @tc.name: MonitorParseEventId002
 * @tc.desc: ParseEventId rejects empty, non numeric, signed and overflowing ids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorParseEventId002, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));
    uint64_t eventId = 0;

    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, monitor.ParseEventId(nullptr, eventId));
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, monitor.ParseEventId("", eventId));
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, monitor.ParseEventId("12a", eventId));
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, monitor.ParseEventId(" 12", eventId));
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, monitor.ParseEventId("-1", eventId));
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, monitor.ParseEventId("0x10", eventId));
    // One past the 64 bit maximum.
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, monitor.ParseEventId("18446744073709551616", eventId));
}

/**
 * @tc.name: MonitorParseEventAction001
 * @tc.desc: ParseEventAction maps allow and deny and rejects anything else
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorParseEventAction001, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));
    enum DEC_POLICY_ACTION action = DEC_POLICY_ACTION_ASK;

    EXPECT_EQ(SANDBOX_SUCCESS, monitor.ParseEventAction("allow", action));
    EXPECT_EQ(DEC_POLICY_ACTION_ALLOW, action);

    EXPECT_EQ(SANDBOX_SUCCESS, monitor.ParseEventAction("deny", action));
    EXPECT_EQ(DEC_POLICY_ACTION_DENY, action);

    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, monitor.ParseEventAction(nullptr, action));
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, monitor.ParseEventAction("ask", action));
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, monitor.ParseEventAction("Allow", action));
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, monitor.ParseEventAction("", action));
}

/**
 * @tc.name: MonitorParseEventAnswer001
 * @tc.desc: ParseEventAnswer accepts a well formed answer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorParseEventAnswer001, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));
    uint64_t eventId = 0;
    enum DEC_POLICY_ACTION action = DEC_POLICY_ACTION_ASK;

    EXPECT_EQ(SANDBOX_SUCCESS, monitor.ParseEventAnswer(
        R"({"event_id":"4660","action":"deny"})", eventId, action));
    EXPECT_EQ(4660u, eventId);
    EXPECT_EQ(DEC_POLICY_ACTION_DENY, action);
}

/**
 * @tc.name: MonitorParseEventAnswer002
 * @tc.desc: ParseEventAnswer rejects oversized, malformed and mistyped answers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorParseEventAnswer002, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));
    uint64_t eventId = 0;
    enum DEC_POLICY_ACTION action = DEC_POLICY_ACTION_ASK;

    std::string oversize(MAX_EVENT_ANSWER_JSON_LENGTH + 1, 'a');
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, monitor.ParseEventAnswer(oversize, eventId, action));
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, monitor.ParseEventAnswer("{bad", eventId, action));
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, monitor.ParseEventAnswer("{}", eventId, action));
    // event_id must be a string, not a number.
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, monitor.ParseEventAnswer(
        R"({"event_id":4660,"action":"allow"})", eventId, action));
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, monitor.ParseEventAnswer(
        R"({"event_id":"4660"})", eventId, action));
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, monitor.ParseEventAnswer(
        R"({"event_id":"4660","action":"maybe"})", eventId, action));
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, monitor.ParseEventAnswer(
        R"({"event_id":"abc","action":"allow"})", eventId, action));
}

/**
 * @tc.name: MonitorWriteEventAnswer001
 * @tc.desc: WriteEventAnswer emits the DEC answer on the device fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorWriteEventAnswer001, TestSize.Level0)
{
    int pipeFds[2] = {-1, -1};
    ASSERT_EQ(0, pipe(pipeFds));

    {
        SandboxMonitor monitor(MakeConfig(getpid(), -1, pipeFds[1]));
        EXPECT_EQ(SANDBOX_SUCCESS, monitor.WriteEventAnswer(4660, DEC_POLICY_ACTION_DENY));
    }

    TestDecEventAnswer answer = {};
    EXPECT_TRUE(ReadExactFd(pipeFds[0], &answer, sizeof(answer)));
    EXPECT_EQ(sizeof(answer), static_cast<size_t>(answer.size));
    EXPECT_EQ(4660u, answer.eventId);
    EXPECT_EQ(static_cast<int32_t>(DEC_POLICY_ACTION_DENY), answer.action);

    close(pipeFds[0]);
}

/**
 * @tc.name: MonitorWriteEventAnswer002
 * @tc.desc: WriteEventAnswer reports a device error when the fd is not writable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorWriteEventAnswer002, TestSize.Level0)
{
    int pipeFds[2] = {-1, -1};
    ASSERT_EQ(0, pipe(pipeFds));

    {
        // The read end of a pipe cannot be written to.
        SandboxMonitor monitor(MakeConfig(getpid(), -1, pipeFds[0]));
        EXPECT_EQ(SANDBOX_ERR_DEVICE_IO, monitor.WriteEventAnswer(1, DEC_POLICY_ACTION_ALLOW));
    }

    close(pipeFds[1]);
}

/**
 * @tc.name: MonitorWriteEventAnswer003
 * @tc.desc: A full device is reported as retryable, distinctly from a rejection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorWriteEventAnswer003, TestSize.Level0)
{
    int pipeFds[2] = {-1, -1};
    ASSERT_EQ(0, pipe(pipeFds));
    ASSERT_EQ(SANDBOX_SUCCESS, SandboxMonitor::SetNonBlock(pipeFds[1]));

    // Nobody drains the read end, so the pipe fills and further writes get
    // EAGAIN - the one write failure that resending can actually recover from.
    std::vector<uint8_t> filler(PIPE_FILL_CHUNK, 'x');
    while (write(pipeFds[1], filler.data(), filler.size()) > 0) {
    }
    ASSERT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);

    {
        SandboxMonitor monitor(MakeConfig(getpid(), -1, pipeFds[1]));
        // Must not be SANDBOX_ERR_DEVICE_IO: that code tells the app to give up,
        // and here the very same answer is expected to go through later.
        EXPECT_EQ(SANDBOX_ERR_DEVICE_BUSY, monitor.WriteEventAnswer(1, DEC_POLICY_ACTION_ALLOW));
    }

    close(pipeFds[0]);
}

/**
 * @tc.name: MonitorHandleEventAnswer001
 * @tc.desc: Without a device there is nothing to answer with, and the app is told to stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorHandleEventAnswer001, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));
    // Not SANDBOX_ERR_DEVICE_IO: that would read as "this write failed, retry",
    // when in fact no answer can ever be delivered.
    EXPECT_EQ(SANDBOX_ERR_MONITOR_DEGRADED,
        monitor.HandleEventAnswer(R"({"event_id":"1","action":"allow"})"));
}

/**
 * @tc.name: MonitorHandleEventAnswer002
 * @tc.desc: An answer for an outstanding event is forwarded and clears the entry
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorHandleEventAnswer002, TestSize.Level0)
{
    int pipeFds[2] = {-1, -1};
    ASSERT_EQ(0, pipe(pipeFds));

    {
        SandboxMonitor monitor(MakeConfig(getpid(), -1, pipeFds[1]));
        monitor.pendingAnswers_.push_back(9);

        EXPECT_EQ(SANDBOX_SUCCESS,
            monitor.HandleEventAnswer(R"({"event_id":"9","action":"allow"})"));
        EXPECT_TRUE(monitor.pendingAnswers_.empty());

        // Answering the same event twice must not reach the kernel again.
        EXPECT_EQ(SANDBOX_ERR_EVENT_UNKNOWN,
            monitor.HandleEventAnswer(R"({"event_id":"9","action":"allow"})"));
    }

    TestDecEventAnswer answer = {};
    EXPECT_TRUE(ReadExactFd(pipeFds[0], &answer, sizeof(answer)));
    uint64_t answerEventId = answer.eventId;
    EXPECT_EQ(9u, answerEventId);

    close(pipeFds[0]);
}

/**
 * @tc.name: MonitorHandleEventAnswer003
 * @tc.desc: A malformed answer is rejected as retryable and leaves the entry alone
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorHandleEventAnswer003, TestSize.Level0)
{
    int pipeFds[2] = {-1, -1};
    ASSERT_EQ(0, pipe(pipeFds));

    {
        SandboxMonitor monitor(MakeConfig(getpid(), -1, pipeFds[1]));
        monitor.pendingAnswers_.push_back(9);

        EXPECT_EQ(SANDBOX_ERR_EVENT_ANSWER_INVALID, monitor.HandleEventAnswer("{"));
        EXPECT_EQ(SANDBOX_ERR_EVENT_ANSWER_INVALID,
            monitor.HandleEventAnswer(R"({"event_id":"9","action":"maybe"})"));
        EXPECT_EQ(SANDBOX_ERR_EVENT_ANSWER_INVALID,
            monitor.HandleEventAnswer(R"({"event_id":"nine","action":"allow"})"));

        // The event is still answerable, so the app can retry with a fixed body.
        EXPECT_EQ(1u, monitor.pendingAnswers_.size());
        EXPECT_EQ(SANDBOX_SUCCESS,
            monitor.HandleEventAnswer(R"({"event_id":"9","action":"deny"})"));
    }

    close(pipeFds[0]);
}

/**
 * @tc.name: MonitorHandleEventAnswer004
 * @tc.desc: An answer for an event that was never reported never reaches the kernel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorHandleEventAnswer004, TestSize.Level0)
{
    int pipeFds[2] = {-1, -1};
    ASSERT_EQ(0, pipe(pipeFds));

    {
        SandboxMonitor monitor(MakeConfig(getpid(), -1, pipeFds[1]));
        monitor.pendingAnswers_.push_back(9);

        // Without this check the app could push a verdict for any id it invents.
        EXPECT_EQ(SANDBOX_ERR_EVENT_UNKNOWN,
            monitor.HandleEventAnswer(R"({"event_id":"12345","action":"allow"})"));
        EXPECT_EQ(1u, monitor.pendingAnswers_.size());

        // An ASK still sitting in the buffered table was never reported either.
        monitor.PushEventReport(777, true, "{}");
        EXPECT_EQ(SANDBOX_ERR_EVENT_UNKNOWN,
            monitor.HandleEventAnswer(R"({"event_id":"777","action":"allow"})"));
    }

    // The monitor closed the write end, so an empty pipe reads EOF rather than
    // blocking: nothing at all was written to the device.
    TestDecEventAnswer answer = {};
    EXPECT_FALSE(ReadExactFd(pipeFds[0], &answer, sizeof(answer)));

    close(pipeFds[0]);
}

/**
 * @tc.name: MonitorHandleAddPolicy001
 * @tc.desc: Without a device a policy cannot be delivered, and the app is told to stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorHandleAddPolicy001, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));
    EXPECT_EQ(SANDBOX_ERR_MONITOR_DEGRADED, monitor.HandleAddPolicy(VALID_POLICY_JSON));
}

/**
 * @tc.name: MonitorHandleAddPolicy002
 * @tc.desc: HandleAddPolicy rejects malformed policy JSON and policies with no rule groups
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorHandleAddPolicy002, TestSize.Level0)
{
    int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    ASSERT_GE(fd, 0);

    SandboxMonitor monitor(MakeConfig(getpid(), -1, fd));
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, monitor.HandleAddPolicy("{bad"));
    // A well formed object without the rule group array carries nothing to add.
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID, monitor.HandleAddPolicy("{\"Other\":1}"));
    EXPECT_EQ(SANDBOX_ERR_CONFIG_INVALID,
        monitor.HandleAddPolicy("{\"AddOperationControlRuleGroups\":[]}"));
}

/**
 * @tc.name: MonitorHandleAddPolicy003
 * @tc.desc: HandleAddPolicy delivers parsed rule groups to the device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorHandleAddPolicy003, TestSize.Level0)
{
    int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    ASSERT_GE(fd, 0);

    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.mockFd = fd;
    g_ioctlMockState.failOnCallIndex = -1;
    g_ioctlMockState.ioctlCallCount = 0;

    SandboxMonitor monitor(MakeConfig(getpid(), -1, fd));
    EXPECT_EQ(SANDBOX_SUCCESS, monitor.HandleAddPolicy(VALID_POLICY_JSON));
    EXPECT_EQ(1, g_ioctlMockState.ioctlCallCount);

    g_ioctlMockState.failOnCallIndex = 0;
    g_ioctlMockState.ioctlCallCount = 0;
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_PARTIAL, monitor.HandleAddPolicy(VALID_POLICY_JSON));
}

/**
 * @tc.name: MonitorHandleAddPolicy005
 * @tc.desc: A policy naming the monitor socket loses the file module, so it
 *           cannot displace the sandbox's own protection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorHandleAddPolicy005, TestSize.Level0)
{
    int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    ASSERT_GE(fd, 0);

    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.mockFd = fd;
    g_ioctlMockState.failOnCallIndex = -1;
    g_ioctlMockState.ioctlCallCount = 0;

    /*
     * The protected path has to exist. The check compares inodes, so it needs
     * something to stat, and the rule's own O_PATH open has to succeed for the
     * rule to reach the check at all - a path that will not open is refused
     * earlier as open_failed, which is the right answer for a broken path but
     * not what this case is about.
     */
    const std::string socketPath = MakeSocketPath("protected");
    ASSERT_FALSE(socketPath.empty());
    int stand_in = open(socketPath.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, S_IRUSR | S_IWUSR);
    ASSERT_GE(stand_in, 0);
    close(stand_in);

    SandboxMonitor monitor(MakeConfig(getpid(), -1, fd, socketPath));

    const std::string policy = R"({"AddOperationControlRuleGroups":)"
        R"([{"Scope":{"Type":"self_session"},)"
        R"("File":{"AllowDelete":[")" + socketPath + R"("]}}]})";

    std::string detail;
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_PARTIAL, monitor.HandleAddPolicy(policy, &detail));

    // File is the only module this policy configures, so nothing reached the
    // device - but the reason is per module, not a rejection of the request.
    EXPECT_EQ(0, g_ioctlMockState.ioctlCallCount);

    ASSERT_FALSE(detail.empty());
    cJSON *root = cJSON_Parse(detail.c_str());
    ASSERT_NE(nullptr, root);
    cJSON *group = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(root, "groups"), 0);
    ASSERT_NE(nullptr, group);
    cJSON *errors = cJSON_GetObjectItemCaseSensitive(group, "errors");
    ASSERT_TRUE(cJSON_IsArray(errors));
    ASSERT_EQ(1, cJSON_GetArraySize(errors));
    cJSON *first = cJSON_GetArrayItem(errors, 0);
    EXPECT_STREQ("protected_object",
        cJSON_GetObjectItemCaseSensitive(first, "reason")->valuestring);
    EXPECT_STREQ(socketPath.c_str(),
        cJSON_GetObjectItemCaseSensitive(first, "object")->valuestring);
    cJSON_Delete(root);

    // A policy that does not name it is unaffected.
    g_ioctlMockState.ioctlCallCount = 0;
    EXPECT_EQ(SANDBOX_SUCCESS, monitor.HandleAddPolicy(VALID_POLICY_JSON));
    EXPECT_EQ(1, g_ioctlMockState.ioctlCallCount);

    unlink(socketPath.c_str());
}

/**
 * @tc.name: MonitorHandleAddPolicy004
 * @tc.desc: A rejected policy explains itself in the response body
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorHandleAddPolicy004, TestSize.Level0)
{
    int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    ASSERT_GE(fd, 0);

    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.mockFd = fd;
    g_ioctlMockState.failOnCallIndex = -1;
    g_ioctlMockState.ioctlCallCount = 0;

    SandboxMonitor monitor(MakeConfig(getpid(), -1, fd));

    std::string detail;
    EXPECT_EQ(SANDBOX_ERR_SET_POLICY_PARTIAL,
        monitor.HandleAddPolicy(CONFLICTING_POLICY_JSON, &detail));

    // The file module never reached the device, and it is the only one here.
    EXPECT_EQ(0, g_ioctlMockState.ioctlCallCount);

    ASSERT_FALSE(detail.empty());
    cJSON *root = cJSON_Parse(detail.c_str());
    ASSERT_NE(nullptr, root);

    cJSON *type = cJSON_GetObjectItemCaseSensitive(root, "type");
    ASSERT_TRUE(cJSON_IsString(type));
    EXPECT_STREQ(SANDBOX_RESPONSE_TYPE_ADD_POLICY, type->valuestring);

    cJSON *version = cJSON_GetObjectItemCaseSensitive(root, "version");
    ASSERT_TRUE(cJSON_IsNumber(version));
    EXPECT_EQ(static_cast<int>(SANDBOX_RESPONSE_BODY_VERSION),
        static_cast<int>(cJSON_GetNumberValue(version)));

    // errors and delivered live inside the rule group they belong to.
    cJSON *group = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(root, "groups"), 0);
    ASSERT_NE(nullptr, group);
    EXPECT_STREQ("self_session",
        cJSON_GetObjectItemCaseSensitive(group, "scope")->valuestring);

    cJSON *errors = cJSON_GetObjectItemCaseSensitive(group, "errors");
    ASSERT_TRUE(cJSON_IsArray(errors));
    ASSERT_EQ(1, cJSON_GetArraySize(errors));

    cJSON *first = cJSON_GetArrayItem(errors, 0);
    ASSERT_NE(nullptr, first);
    EXPECT_STREQ("action_conflict",
        cJSON_GetObjectItemCaseSensitive(first, "reason")->valuestring);
    EXPECT_STREQ("FileDelete",
        cJSON_GetObjectItemCaseSensitive(first, "operation")->valuestring);
    EXPECT_STREQ("/data/conflict",
        cJSON_GetObjectItemCaseSensitive(first, "object")->valuestring);
    EXPECT_EQ(2, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(first, "actions")));

    // delivered is unconditional, so the app never has to test for it.
    cJSON *delivered = cJSON_GetObjectItemCaseSensitive(group, "delivered");
    ASSERT_TRUE(cJSON_IsArray(delivered));
    ASSERT_EQ(1, cJSON_GetArraySize(delivered));
    cJSON *entry = cJSON_GetArrayItem(delivered, 0);
    EXPECT_STREQ("file", cJSON_GetObjectItemCaseSensitive(entry, "module")->valuestring);
    EXPECT_EQ(SANDBOX_RSP_BAD_REQUEST,
        static_cast<int32_t>(cJSON_GetNumberValue(
            cJSON_GetObjectItemCaseSensitive(entry, "result"))));

    cJSON_Delete(root);
}

/**
 * @tc.name: MonitorDispatch001
 * @tc.desc: DispatchSocketMessage routes by message type and rejects unknown types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorDispatch001, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));

    ParsedMessage message = {};
    // Realistic value. The requestId check lives in ValidateMessage, which
    // QueueResponse runs first; DispatchSocketMessage itself only routes.
    message.header.requestId = 7;
    message.header.msgType = SANDBOX_SOCKET_MSG_ADD_POLICY;
    message.body = VALID_POLICY_JSON;
    // Routed to HandleAddPolicy, which has no device to deliver to.
    EXPECT_EQ(SANDBOX_ERR_MONITOR_DEGRADED, monitor.DispatchSocketMessage(message));

    message.header.msgType = SANDBOX_SOCKET_MSG_EVENT_ANSWER;
    message.body = R"({"event_id":"1","action":"allow"})";
    EXPECT_EQ(SANDBOX_ERR_MONITOR_DEGRADED, monitor.DispatchSocketMessage(message));

    message.header.msgType = SANDBOX_SOCKET_MSG_RESPONSE;
    EXPECT_EQ(SANDBOX_ERR_SOCKET_PROTOCOL, monitor.DispatchSocketMessage(message));

    message.header.msgType = 99;
    EXPECT_EQ(SANDBOX_ERR_SOCKET_PROTOCOL, monitor.DispatchSocketMessage(message));
}

/**
 * @tc.name: MonitorCheckChildExit001
 * @tc.desc: CheckChildExit reports a wait failure for a process that is not our child
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorCheckChildExit001, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(999998, -1, -1));
    EXPECT_EQ(MONITOR_ACTION_STOP, monitor.CheckChildExit(WNOHANG));
    EXPECT_EQ(SANDBOX_ERR_CHILD_WAIT_FAILED, monitor.monitorError_);
    EXPECT_EQ(-1, monitor.childExitCode_);
}

/**
 * @tc.name: MonitorCheckChildExit002
 * @tc.desc: CheckChildExit records a normal exit status
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorCheckChildExit002, TestSize.Level0)
{
    pid_t child = fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        _exit(3);
    }

    SandboxMonitor monitor(MakeConfig(child, -1, -1));
    MonitorAction action = MONITOR_ACTION_NONE;
    for (int i = 0; i < CHILD_WAIT_POLLS && action == MONITOR_ACTION_NONE; i++) {
        action = monitor.CheckChildExit(WNOHANG);
        if (action == MONITOR_ACTION_NONE) {
            usleep(1000);
        }
    }

    // A normal exit is a success, not a failure: no error is recorded.
    EXPECT_EQ(MONITOR_ACTION_CHILD_EXITED, action);
    EXPECT_EQ(SANDBOX_SUCCESS, monitor.monitorError_);
    EXPECT_EQ(3, monitor.childExitCode_);
}

/**
 * @tc.name: MonitorCheckChildExit003
 * @tc.desc: CheckChildExit maps a fatal signal to the 128 based exit code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorCheckChildExit003, TestSize.Level0)
{
    pid_t child = fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        pause();
        _exit(0);
    }

    // Give the child a moment to reach pause() before killing it.
    usleep(20000);
    ASSERT_EQ(0, kill(child, SIGKILL));

    SandboxMonitor monitor(MakeConfig(child, -1, -1));
    MonitorAction action = MONITOR_ACTION_NONE;
    for (int i = 0; i < CHILD_WAIT_POLLS && action == MONITOR_ACTION_NONE; i++) {
        action = monitor.CheckChildExit(WNOHANG);
        if (action == MONITOR_ACTION_NONE) {
            usleep(1000);
        }
    }

    EXPECT_EQ(MONITOR_ACTION_CHILD_EXITED, action);
    EXPECT_EQ(128 + SIGKILL, monitor.childExitCode_);
}

/**
 * @tc.name: MonitorRunUninitialized001
 * @tc.desc: Run refuses to start before Init has succeeded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorRunUninitialized001, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));
    EXPECT_EQ(SANDBOX_ERR_BAD_PARAMETERS, monitor.Run());
}

/**
 * @tc.name: MonitorHandleChildExitEvent001
 * @tc.desc: HandleChildExitEvent stops the loop on an epoll error and ignores empty events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorHandleChildExitEvent001, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));

    EXPECT_EQ(MONITOR_ACTION_NONE, monitor.HandleChildExitEvent(0));
    EXPECT_EQ(SANDBOX_SUCCESS, monitor.monitorError_);

    // The child pidfd is the monitor's own plumbing: losing it is one of the few
    // things left that still stops the loop.
    EXPECT_EQ(MONITOR_ACTION_STOP, monitor.HandleChildExitEvent(EPOLLERR));
    EXPECT_EQ(SANDBOX_ERR_CHILD_WATCH_FAILED, monitor.monitorError_);

    EXPECT_EQ(MONITOR_ACTION_STOP, monitor.HandleChildExitEvent(EPOLLHUP));
    EXPECT_EQ(SANDBOX_ERR_CHILD_WATCH_FAILED, monitor.monitorError_);
}

/**
 * @tc.name: MonitorHandleChildExitEvent002
 * @tc.desc: A readable pidfd whose reap fails stops the loop instead of spinning on it
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorHandleChildExitEvent002, TestSize.Level0)
{
    // childPid_ is this process, so waitpid() can only fail with ECHILD. The
    // pidfd would stay readable for good, so NONE must never come back here.
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));

    EXPECT_EQ(MONITOR_ACTION_STOP, monitor.HandleChildExitEvent(EPOLLIN));
    EXPECT_EQ(SANDBOX_ERR_CHILD_WAIT_FAILED, monitor.monitorError_);
}

/**
 * @tc.name: MonitorHandleSocketEvent001
 * @tc.desc: HandleSocketEvent keeps the loop alive when there is no socket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorHandleSocketEvent001, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));
    EXPECT_EQ(MONITOR_ACTION_NONE, monitor.HandleSocketEvent(EPOLLIN));
    EXPECT_EQ(MONITOR_ACTION_NONE, monitor.HandleSocketEvent(EPOLLHUP));
    EXPECT_EQ(SANDBOX_SUCCESS, monitor.monitorError_);
}

/**
 * @tc.name: MonitorHandleSocketEvent002
 * @tc.desc: A hangup starts the reconnect sequence and keeps both tables
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorHandleSocketEvent002, TestSize.Level0)
{
    int first = -1;
    int second = -1;
    ASSERT_TRUE(MakeSocketPairFds(first, second));

    SandboxMonitor monitor(MakeConfig(getpid(), first, -1, "/data/local/tmp/app.socket"));
    monitor.pendingAnswers_.push_back(TEST_EVENT_ID);

    // The handler only reports; nothing has changed yet.
    MonitorAction action = monitor.HandleSocketEvent(EPOLLRDHUP);
    EXPECT_EQ(MONITOR_ACTION_RECONNECT, action);
    EXPECT_EQ(SANDBOX_ERR_SOCKET_CLOSED, monitor.monitorError_);
    EXPECT_TRUE(monitor.socket_ != nullptr);

    // Only the first connect may fail the launch. Afterwards the child is
    // already running, so the loop must survive losing the peer.
    EXPECT_TRUE(monitor.ApplyAction(action));
    EXPECT_TRUE(monitor.socket_ == nullptr);
    EXPECT_EQ(MONITOR_STATE_RECONNECTING, monitor.state_);
    // A peer that comes back is the same process, so outstanding ids are kept.
    EXPECT_EQ(1u, monitor.pendingAnswers_.size());
    EXPECT_GT(monitor.reconnectAttemptsLeft_, 0);
    EXPECT_GE(monitor.NextEpollTimeout(), 0);

    close(second);
}

/**
 * @tc.name: MonitorHandleSocketEvent003
 * @tc.desc: Without a reconnect target a hangup drops everything immediately
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorHandleSocketEvent003, TestSize.Level0)
{
    int first = -1;
    int second = -1;
    ASSERT_TRUE(MakeSocketPairFds(first, second));

    SandboxMonitor monitor(MakeConfig(getpid(), first, -1));
    monitor.pendingAnswers_.push_back(TEST_EVENT_ID);

    MonitorAction action = monitor.HandleSocketEvent(EPOLLRDHUP);
    EXPECT_EQ(MONITOR_ACTION_RECONNECT, action);

    // No path to reconnect to, so the same action lands in DEGRADED instead.
    EXPECT_TRUE(monitor.ApplyAction(action));
    EXPECT_EQ(MONITOR_STATE_DEGRADED, monitor.state_);
    EXPECT_TRUE(monitor.socket_ == nullptr);
    EXPECT_EQ(0, monitor.reconnectAttemptsLeft_);
    EXPECT_TRUE(monitor.pendingAnswers_.empty());
    EXPECT_TRUE(monitor.socketTxQueue_.empty());
    // Nothing to wait for, so the loop goes back to blocking indefinitely.
    EXPECT_EQ(-1, monitor.NextEpollTimeout());

    close(second);
}

/**
 * @tc.name: MonitorHandleDeviceEvent001
 * @tc.desc: HandleDeviceEvent ignores events when there is no device and stops on errors
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorHandleDeviceEvent001, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));
    EXPECT_EQ(MONITOR_ACTION_NONE, monitor.HandleDeviceEvent(EPOLLIN));
    EXPECT_EQ(SANDBOX_SUCCESS, monitor.monitorError_);

    int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    ASSERT_GE(fd, 0);
    SandboxMonitor withDevice(MakeConfig(getpid(), -1, fd));

    // No EPOLLIN means there is nothing to read.
    EXPECT_EQ(MONITOR_ACTION_NONE, withDevice.HandleDeviceEvent(0));
    EXPECT_EQ(SANDBOX_SUCCESS, withDevice.monitorError_);

    // A dead device degrades the monitor rather than stopping it: the child is
    // still running and still has to be reaped.
    EXPECT_EQ(MONITOR_ACTION_DEGRADE, withDevice.HandleDeviceEvent(EPOLLERR));
    EXPECT_EQ(SANDBOX_ERR_DEVICE_IO, withDevice.monitorError_);
}

/**
 * @tc.name: MonitorConsumeDeviceEvent001
 * @tc.desc: A record too short to hold a header is dropped on its own
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorConsumeDeviceEvent001, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));
    EXPECT_EQ(MONITOR_ACTION_SKIP, monitor.ConsumeDeviceEvent(nullptr, 0));
}

/**
 * @tc.name: MonitorConsumeDeviceEvent002
 * @tc.desc: A record shorter than its own valLen is malformed, not partial:
 *           one read yields one whole event, so there is no rest to wait for
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorConsumeDeviceEvent002, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));
    std::vector<uint8_t> event = BuildDeviceEvent(TEST_EVENT_ID, "file_open");

    EXPECT_EQ(MONITOR_ACTION_SKIP,
        monitor.ConsumeDeviceEvent(event.data(), event.size() - 1));
    EXPECT_TRUE(monitor.socketTxQueue_.empty());
}

/**
 * @tc.name: MonitorConsumeDeviceEvent003
 * @tc.desc: A record whose header does not check out is dropped, and the
 *           monitor carries on
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorConsumeDeviceEvent003, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));

    DeviceEventHeader header = {};
    header.valLen = static_cast<uint32_t>(MAX_DEVICE_EVENT_LENGTH);
    const uint8_t *headerBytes = reinterpret_cast<const uint8_t *>(&header);

    EXPECT_EQ(MONITOR_ACTION_SKIP,
        monitor.ConsumeDeviceEvent(headerBytes, EVENT_HEADER_SIZE));
    // Records are independent, so nothing else is thrown away with it.
    EXPECT_EQ(SANDBOX_SUCCESS, monitor.monitorError_);
}

/**
 * @tc.name: MonitorConsumeDeviceEvent004
 * @tc.desc: While reconnecting, a complete event is queued rather than dropped
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorConsumeDeviceEvent004, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1, "/data/local/tmp/app.socket"));
    monitor.reconnectAttemptsLeft_ = 1;  // pretend a reconnect is in flight
    std::vector<uint8_t> event = BuildDeviceEvent(TEST_EVENT_ID, "file_open");

    EXPECT_EQ(MONITOR_ACTION_NONE, monitor.ConsumeDeviceEvent(event.data(), event.size()));
    ASSERT_EQ(1u, monitor.socketTxQueue_.size());
    EXPECT_EQ(TEST_EVENT_ID, monitor.socketTxQueue_.front().eventId);
    EXPECT_TRUE(monitor.socketTxQueue_.front().needsAnswer);
    // Not reported yet, so it must not be answerable.
    EXPECT_TRUE(monitor.pendingAnswers_.empty());
}

/**
 * @tc.name: MonitorConsumeDeviceEvent006
 * @tc.desc: With no peer and no reconnect target, complete events are discarded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorConsumeDeviceEvent006, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));
    std::vector<uint8_t> event = BuildDeviceEvent(TEST_EVENT_ID, "file_open");

    // Nothing to buffer for: the event is dropped and left to the kernel.
    EXPECT_EQ(MONITOR_ACTION_NONE, monitor.ConsumeDeviceEvent(event.data(), event.size()));
    EXPECT_TRUE(monitor.socketTxQueue_.empty());
    EXPECT_TRUE(monitor.pendingAnswers_.empty());
}

/**
 * @tc.name: MonitorConsumeDeviceEvent005
 * @tc.desc: Successive records are each forwarded in turn
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorConsumeDeviceEvent005, TestSize.Level0)
{
    int first = -1;
    int second = -1;
    ASSERT_TRUE(MakeSocketPairFds(first, second));

    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));
    monitor.socket_ = std::make_unique<SandboxSocket>(first);
    monitor.sockCtx_.fd = first;

    std::vector<uint8_t> firstEvent = BuildDeviceEvent(1, "one");
    std::vector<uint8_t> secondEvent = BuildDeviceEvent(2, "two");
    EXPECT_EQ(MONITOR_ACTION_NONE,
        monitor.ConsumeDeviceEvent(firstEvent.data(), firstEvent.size()));
    EXPECT_EQ(MONITOR_ACTION_NONE,
        monitor.ConsumeDeviceEvent(secondEvent.data(), secondEvent.size()));

    MessageHeader header = {};
    std::string body;
    ASSERT_TRUE(ReadMessage(second, header, body));
    uint32_t msgType = header.msgType;
    EXPECT_EQ(static_cast<uint32_t>(SANDBOX_SOCKET_MSG_EVENT_REPORT), msgType);
    EXPECT_NE(std::string::npos, body.find("one"));

    ASSERT_TRUE(ReadMessage(second, header, body));
    EXPECT_NE(std::string::npos, body.find("two"));

    close(second);
}

/**
 * @tc.name: MonitorUpdateEpollEvents001
 * @tc.desc: The socket epoll update is a no-op when there is no socket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorUpdateEpollEvents001, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));
    EXPECT_EQ(SANDBOX_SUCCESS, monitor.UpdateSocketEpollEvents());
}

/**
 * @tc.name: MonitorUpdateEpollEvents003
 * @tc.desc: A queued message keeps EPOLLOUT armed even when the socket buffer is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorUpdateEpollEvents003, TestSize.Level0)
{
    std::string path = MakeSocketPath("queue_armed");
    ASSERT_FALSE(path.empty());
    UdsListener listener(path);
    ASSERT_TRUE(listener.Valid());

    int deviceFd = -1;
    int kernelFd = -1;
    ASSERT_TRUE(MakeSocketPairFds(deviceFd, kernelFd));

    int socketFd = -1;
    ASSERT_EQ(SANDBOX_SUCCESS, SandboxMonitor::ConnectToApp(path, socketFd));

    {
        SandboxMonitor monitor(MakeConfig(getpid(), socketFd, deviceFd, path));
        ASSERT_EQ(SANDBOX_SUCCESS, monitor.Init());

        // Nothing pending at the socket level.
        ASSERT_FALSE(monitor.socket_->HasPendingTxData());
        ASSERT_EQ(SANDBOX_SUCCESS, monitor.UpdateSocketEpollEvents());
        ASSERT_FALSE(monitor.socketWriteEnabled_);

        // Something pending at the monitor level must still arm EPOLLOUT, or
        // FlushSocketTxQueue would never get the event that drains it.
        monitor.PushEventReport(TEST_EVENT_ID, true, R"({"event_id":"4660"})");
        EXPECT_EQ(SANDBOX_SUCCESS, monitor.UpdateSocketEpollEvents());
        EXPECT_TRUE(monitor.socketWriteEnabled_);

        // Draining the queue disarms it again.
        EXPECT_EQ(SANDBOX_SUCCESS, monitor.FlushSocketTxQueue());
        EXPECT_TRUE(monitor.socketTxQueue_.empty());
        EXPECT_EQ(SANDBOX_SUCCESS, monitor.UpdateSocketEpollEvents());
        EXPECT_FALSE(monitor.socketWriteEnabled_);
    }

    close(kernelFd);
}

/**
 * @tc.name: MonitorUpdateEpollEvents002
 * @tc.desc: A full Tx buffer diverts new events into the buffered table
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorUpdateEpollEvents002, TestSize.Level0)
{
    std::string path = MakeSocketPath("backpressure");
    ASSERT_FALSE(path.empty());
    UdsListener listener(path);
    ASSERT_TRUE(listener.Valid());

    int deviceFd = -1;
    int kernelFd = -1;
    ASSERT_TRUE(MakeSocketPairFds(deviceFd, kernelFd));

    int socketFd = -1;
    ASSERT_EQ(SANDBOX_SUCCESS, SandboxMonitor::ConnectToApp(path, socketFd));

    {
        SandboxMonitor monitor(MakeConfig(getpid(), socketFd, deviceFd));
        ASSERT_EQ(SANDBOX_SUCCESS, monitor.Init());
        ASSERT_TRUE(monitor.socket_ != nullptr);

        // Nobody accepts and drains, so reports pile up until the Tx buffer is
        // full. It has to be genuinely full, not merely non-empty: the event
        // below only reaches socketTxQueue_ if SendMessage answers TX_FULL.
        ASSERT_TRUE(FillSocketTxBuffer(*monitor.socket_));

        EXPECT_EQ(SANDBOX_SUCCESS, monitor.UpdateSocketEpollEvents());
        EXPECT_TRUE(monitor.socketWriteEnabled_);

        // The device is still drained; the event lands in the buffered table
        // instead of being forwarded, and is not yet awaiting an answer.
        std::vector<uint8_t> event = BuildDeviceEvent(TEST_EVENT_ID, "file_open");
        EXPECT_EQ(MONITOR_ACTION_NONE, monitor.ConsumeDeviceEvent(event.data(), event.size()));
        ASSERT_EQ(1u, monitor.socketTxQueue_.size());
        EXPECT_EQ(TEST_EVENT_ID, monitor.socketTxQueue_.front().eventId);
        EXPECT_TRUE(monitor.pendingAnswers_.empty());
    }

    close(kernelFd);
}

/**
 * @tc.name: MonitorPendingAnswers001
 * @tc.desc: The pending answer table evicts the oldest id once it is full
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorPendingAnswers001, TestSize.Level0)
{
    int pipeFds[2] = {-1, -1};
    ASSERT_EQ(0, pipe(pipeFds));

    {
        SandboxMonitor monitor(MakeConfig(getpid(), -1, pipeFds[1]));

        for (uint64_t id = 1; id <= MAX_PENDING_ANSWER_COUNT; ++id) {
            monitor.PushPendingAnswer(id);
        }
        EXPECT_EQ(MAX_PENDING_ANSWER_COUNT, monitor.pendingAnswers_.size());

        // One more evicts id 1 and keeps the table at capacity.
        monitor.PushPendingAnswer(MAX_PENDING_ANSWER_COUNT + 1);
        EXPECT_EQ(MAX_PENDING_ANSWER_COUNT, monitor.pendingAnswers_.size());
        EXPECT_EQ(2u, monitor.pendingAnswers_.front());

        // The evicted event can no longer be answered, and that is permanent.
        EXPECT_EQ(SANDBOX_ERR_EVENT_UNKNOWN,
            monitor.HandleEventAnswer(R"({"event_id":"1","action":"allow"})"));
        EXPECT_EQ(SANDBOX_SUCCESS,
            monitor.HandleEventAnswer(R"({"event_id":"2","action":"allow"})"));
    }

    close(pipeFds[0]);
}

/**
 * @tc.name: MonitorBufferedEvents001
 * @tc.desc: The buffered table evicts the oldest entry on either the count or the byte cap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorBufferedEvents001, TestSize.Level0)
{
    /*
     * ASSERT before every front(): on an empty queue front() is undefined, so a
     * wrong expectation here would take the whole binary down with a segfault
     * instead of failing this one case. That is exactly what a stale copy of
     * MAX_SOCKET_TX_QUEUE_BYTES in this file used to do.
     */
    SandboxMonitor byCount(MakeConfig(getpid(), -1, -1));
    for (uint64_t id = 1; id <= MAX_SOCKET_TX_QUEUE_COUNT; ++id) {
        byCount.PushEventReport(id, true, "{}");
    }
    ASSERT_EQ(MAX_SOCKET_TX_QUEUE_COUNT, byCount.socketTxQueue_.size());
    EXPECT_EQ(1u, byCount.socketTxQueue_.front().eventId);

    byCount.PushEventReport(MAX_SOCKET_TX_QUEUE_COUNT + 1, true, "{}");
    ASSERT_EQ(MAX_SOCKET_TX_QUEUE_COUNT, byCount.socketTxQueue_.size());
    EXPECT_EQ(2u, byCount.socketTxQueue_.front().eventId);

    /*
     * The byte cap bites well before the count cap for large payloads. Two
     * halves of the budget fit exactly: the eviction test is
     * "bytes > cap - incoming", so landing on the cap is still a fit.
     */
    SandboxMonitor byBytes(MakeConfig(getpid(), -1, -1));
    const std::string chunk(MAX_SOCKET_TX_QUEUE_BYTES / 2, 'x');
    byBytes.PushEventReport(1, true, chunk);
    byBytes.PushEventReport(2, true, chunk);
    ASSERT_EQ(2u, byBytes.socketTxQueue_.size());

    byBytes.PushEventReport(3, true, chunk);
    ASSERT_EQ(2u, byBytes.socketTxQueue_.size());
    EXPECT_EQ(2u, byBytes.socketTxQueue_.front().eventId);
    EXPECT_LE(byBytes.socketTxBytes_, MAX_SOCKET_TX_QUEUE_BYTES);

    // A single payload larger than the whole budget is refused without
    // evicting the entries that do fit.
    byBytes.PushEventReport(4, true, std::string(MAX_SOCKET_TX_QUEUE_BYTES + 1, 'y'));
    ASSERT_EQ(2u, byBytes.socketTxQueue_.size());
    EXPECT_EQ(2u, byBytes.socketTxQueue_.front().eventId);
}

/**
 * @tc.name: MonitorBufferedEvents002
 * @tc.desc: Flushing preserves order and only then makes ASK events answerable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorBufferedEvents002, TestSize.Level0)
{
    int first = -1;
    int second = -1;
    ASSERT_TRUE(MakeSocketPairFds(first, second));

    {
        SandboxMonitor monitor(MakeConfig(getpid(), first, -1));
        monitor.PushEventReport(1, true, R"({"event_id":"1","tag":"one"})");
        monitor.PushEventReport(2, false, R"({"event_id":"2","tag":"two"})");
        monitor.PushEventReport(3, true, R"({"event_id":"3","tag":"three"})");

        EXPECT_EQ(SANDBOX_SUCCESS, monitor.FlushSocketTxQueue());
        EXPECT_TRUE(monitor.socketTxQueue_.empty());
        EXPECT_EQ(0u, monitor.socketTxBytes_);

        // Only the two ASK events are now outstanding, in the order sent.
        ASSERT_EQ(2u, monitor.pendingAnswers_.size());
        EXPECT_EQ(1u, monitor.pendingAnswers_[0]);
        EXPECT_EQ(3u, monitor.pendingAnswers_[1]);
    }

    MessageHeader header = {};
    std::string body;
    ASSERT_TRUE(ReadMessage(second, header, body));
    EXPECT_NE(std::string::npos, body.find("one"));
    ASSERT_TRUE(ReadMessage(second, header, body));
    EXPECT_NE(std::string::npos, body.find("two"));
    ASSERT_TRUE(ReadMessage(second, header, body));
    EXPECT_NE(std::string::npos, body.find("three"));

    close(second);
}

/**
 * @tc.name: MonitorBufferedEvents003
 * @tc.desc: A non-empty buffer makes new events queue behind it instead of jumping ahead
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorBufferedEvents003, TestSize.Level0)
{
    int first = -1;
    int second = -1;
    ASSERT_TRUE(MakeSocketPairFds(first, second));

    {
        SandboxMonitor monitor(MakeConfig(getpid(), first, -1));
        monitor.PushEventReport(1, true, R"({"event_id":"1","tag":"one"})");

        // The socket is perfectly usable, but sending this straight out would
        // reorder the stream the app sees.
        std::vector<uint8_t> second2 = BuildDeviceEvent(2, "two");
        EXPECT_EQ(MONITOR_ACTION_NONE, monitor.ConsumeDeviceEvent(second2.data(), second2.size()));
        ASSERT_EQ(2u, monitor.socketTxQueue_.size());
        EXPECT_EQ(1u, monitor.socketTxQueue_[0].eventId);
        EXPECT_EQ(2u, monitor.socketTxQueue_[1].eventId);
        EXPECT_TRUE(monitor.pendingAnswers_.empty());

        EXPECT_EQ(SANDBOX_SUCCESS, monitor.FlushSocketTxQueue());
    }

    MessageHeader header = {};
    std::string body;
    ASSERT_TRUE(ReadMessage(second, header, body));
    EXPECT_NE(std::string::npos, body.find("one"));
    ASSERT_TRUE(ReadMessage(second, header, body));
    EXPECT_NE(std::string::npos, body.find("two"));

    close(second);
}

/**
 * @tc.name: MonitorUnknownEventClass001
 * @tc.desc: An unknown event class is dropped on its own, not treated as corruption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorUnknownEventClass001, TestSize.Level0)
{
    constexpr uint32_t UNKNOWN_EVENT_CLASS = DEC_EVENT_CLASS_ASK + 1;

    int first = -1;
    int second = -1;
    ASSERT_TRUE(MakeSocketPairFds(first, second));

    /*
     * The device fd is needed even though nothing is ever written to it.
     * HandleEventAnswer refuses everything with SANDBOX_ERR_MONITOR_DEGRADED
     * while deviceFd_ is -1, and that guard sits ahead of the pending-answer
     * lookup - so with no device the final assertion below would be answered by
     * the degraded check and never reach the thing this test exists to pin.
     * Event 2 is rejected at that lookup, before any write, so the pipe stays
     * empty.
     */
    int pipeFds[2] = {-1, -1};
    ASSERT_EQ(0, pipe(pipeFds));

    {
        SandboxMonitor monitor(MakeConfig(getpid(), first, pipeFds[1]));

        // An unknown class sandwiched between two ASK events: the frame is well
        // formed, so valLen lets us step over just it and keep the neighbours.
        std::vector<uint8_t> before = BuildDeviceEvent(1, "before");
        std::vector<uint8_t> unknown = BuildDeviceEvent(2, "unknown", UNKNOWN_EVENT_CLASS);
        std::vector<uint8_t> after = BuildDeviceEvent(3, "after");

        EXPECT_EQ(MONITOR_ACTION_NONE, monitor.ConsumeDeviceEvent(before.data(), before.size()));
        EXPECT_EQ(MONITOR_ACTION_NONE, monitor.ConsumeDeviceEvent(unknown.data(), unknown.size()));
        EXPECT_EQ(MONITOR_ACTION_NONE, monitor.ConsumeDeviceEvent(after.data(), after.size()));

        // Only the two ASK events became answerable.
        ASSERT_EQ(2u, monitor.pendingAnswers_.size());
        EXPECT_EQ(1u, monitor.pendingAnswers_[0]);
        EXPECT_EQ(3u, monitor.pendingAnswers_[1]);

        EXPECT_EQ(SANDBOX_ERR_EVENT_UNKNOWN,
            monitor.HandleEventAnswer(R"({"event_id":"2","action":"allow"})"));
    }

    // The unknown event must not have reached the app either.
    MessageHeader header = {};
    std::string body;
    ASSERT_TRUE(ReadMessage(second, header, body));
    EXPECT_NE(std::string::npos, body.find("before"));
    ASSERT_TRUE(ReadMessage(second, header, body));
    EXPECT_NE(std::string::npos, body.find("after"));

    close(second);
    close(pipeFds[0]);
}

/**
 * @tc.name: MonitorBadEventDropped001
 * @tc.desc: A record with an unusable header costs only itself - records are
 *           independent, so the next one still gets through
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorBadEventDropped001, TestSize.Level0)
{
    int first = -1;
    int second = -1;
    ASSERT_TRUE(MakeSocketPairFds(first, second));

    SandboxMonitor monitor(MakeConfig(getpid(), first, -1));

    std::vector<uint8_t> bad =
        BuildDeviceEvent(1, "bad_version", DEC_EVENT_CLASS_ASK, DEVICE_EVENT_VERSION + 1);
    EXPECT_EQ(MONITOR_ACTION_SKIP, monitor.ConsumeDeviceEvent(bad.data(), bad.size()));
    EXPECT_TRUE(monitor.socketTxQueue_.empty());

    std::vector<uint8_t> good = BuildDeviceEvent(2, "good");
    EXPECT_EQ(MONITOR_ACTION_NONE, monitor.ConsumeDeviceEvent(good.data(), good.size()));

    /*
     * Sent, not queued. DeliverDeviceEvent goes straight to the socket when
     * nothing is ahead of the event, and nothing is: the bad one never got far
     * enough to be buffered. The queue is where events wait out a busy channel,
     * which is what MonitorConsumeDeviceEvent004 covers instead.
     */
    EXPECT_TRUE(monitor.socketTxQueue_.empty());

    MessageHeader header = {};
    std::string body;
    ASSERT_TRUE(ReadMessage(second, header, body));
    EXPECT_EQ(static_cast<uint32_t>(SANDBOX_SOCKET_MSG_EVENT_REPORT), header.msgType);
    EXPECT_NE(std::string::npos, body.find("good"));
    // The dropped event reached nobody.
    EXPECT_EQ(std::string::npos, body.find("bad_version"));

    // Still alive: nothing was reported as a monitor failure.
    EXPECT_EQ(SANDBOX_SUCCESS, monitor.monitorError_);

    close(second);
}

/**
 * @tc.name: MonitorPeerLossOnSend001
 * @tc.desc: A peer that dies mid-send starts a reconnect and keeps the event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorPeerLossOnSend001, TestSize.Level0)
{
    int first = -1;
    int second = -1;
    ASSERT_TRUE(MakeSocketPairFds(first, second));

    // The peer is gone before the event is even parsed, so the failure shows up
    // as a send error rather than as an EPOLLRDHUP.
    close(second);

    SandboxMonitor monitor(MakeConfig(getpid(), first, -1, "/data/local/tmp/app.socket"));
    std::vector<uint8_t> event = BuildDeviceEvent(TEST_EVENT_ID, "file_open");

    EXPECT_EQ(MONITOR_ACTION_RECONNECT, monitor.ConsumeDeviceEvent(event.data(), event.size()));
    EXPECT_TRUE(monitor.monitorError_ == SANDBOX_ERR_SOCKET_CLOSED ||
        monitor.monitorError_ == SANDBOX_ERR_SOCKET_IO);
    // The event must survive so a reconnect can still deliver it, and it must
    // not have become answerable.
    ASSERT_EQ(1u, monitor.socketTxQueue_.size());
    EXPECT_EQ(TEST_EVENT_ID, monitor.socketTxQueue_.front().eventId);
    EXPECT_TRUE(monitor.pendingAnswers_.empty());

    // Losing the peer this way must reach the same reconnect path as a hangup.
    monitor.DropSocketChannel();
    EXPECT_TRUE(monitor.socket_ == nullptr);
    EXPECT_GT(monitor.reconnectAttemptsLeft_, 0);
    EXPECT_EQ(1u, monitor.socketTxQueue_.size());
}

/**
 * @tc.name: MonitorReconnect001
 * @tc.desc: A reconnect replays the buffered events and keeps the outstanding ids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorReconnect001, TestSize.Level0)
{
    std::string path = MakeSocketPath("reconnect");
    ASSERT_FALSE(path.empty());
    UdsListener listener(path);
    ASSERT_TRUE(listener.Valid());

    int deviceFd = -1;
    int kernelFd = -1;
    ASSERT_TRUE(MakeSocketPairFds(deviceFd, kernelFd));

    int socketFd = -1;
    ASSERT_EQ(SANDBOX_SUCCESS, SandboxMonitor::ConnectToApp(path, socketFd));

    {
        SandboxMonitor monitor(MakeConfig(getpid(), socketFd, deviceFd, path));
        ASSERT_EQ(SANDBOX_SUCCESS, monitor.Init());

        monitor.pendingAnswers_.push_back(TEST_EVENT_ID);
        monitor.DropSocketChannel();
        ASSERT_TRUE(monitor.socket_ == nullptr);
        EXPECT_GT(monitor.reconnectAttemptsLeft_, 0);

        // Events keep queueing while the channel is down.
        std::vector<uint8_t> event = BuildDeviceEvent(42, "while_down");
        EXPECT_EQ(MONITOR_ACTION_NONE, monitor.ConsumeDeviceEvent(event.data(), event.size()));
        ASSERT_EQ(1u, monitor.socketTxQueue_.size());

        monitor.TryReconnect();
        ASSERT_TRUE(monitor.socket_ != nullptr);
        EXPECT_EQ(0, monitor.reconnectAttemptsLeft_);
        // Replayed, and only now answerable.
        EXPECT_TRUE(monitor.socketTxQueue_.empty());
        EXPECT_EQ(2u, monitor.pendingAnswers_.size());
        EXPECT_EQ(42u, monitor.pendingAnswers_.back());
        // The peer is pinned to callerPid, so ids from before the drop survive.
        EXPECT_EQ(TEST_EVENT_ID, monitor.pendingAnswers_.front());
    }

    close(kernelFd);
}

/**
 * @tc.name: MonitorReconnect002
 * @tc.desc: Once the reconnect budget is spent both tables are dropped
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorReconnect002, TestSize.Level0)
{
    // Nobody ever listens here, so every attempt is refused immediately.
    std::string path = MakeSocketPath("reconnect_gone");
    ASSERT_FALSE(path.empty());

    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1, path));
    monitor.pendingAnswers_.push_back(TEST_EVENT_ID);
    monitor.PushEventReport(42, true, "{}");
    monitor.reconnectAttemptsLeft_ = RECONNECT_MAX_ATTEMPTS;

    for (int i = 0; i < RECONNECT_MAX_ATTEMPTS; ++i) {
        EXPECT_TRUE(monitor.socket_ == nullptr);
        monitor.TryReconnect();
    }

    EXPECT_EQ(0, monitor.reconnectAttemptsLeft_);
    EXPECT_TRUE(monitor.socket_ == nullptr);
    EXPECT_TRUE(monitor.socketTxQueue_.empty());
    EXPECT_TRUE(monitor.pendingAnswers_.empty());
    EXPECT_EQ(-1, monitor.NextEpollTimeout());
}

/**
 * @tc.name: MonitorDegradeOnDeviceLoss001
 * @tc.desc: Losing the device closes the channel for good but keeps reaping the child
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorDegradeOnDeviceLoss001, TestSize.Level0)
{
    std::string path = MakeSocketPath("degrade");
    ASSERT_FALSE(path.empty());
    UdsListener listener(path);
    ASSERT_TRUE(listener.Valid());

    int deviceFd = -1;
    int kernelFd = -1;
    ASSERT_TRUE(MakeSocketPairFds(deviceFd, kernelFd));

    int socketFd = -1;
    ASSERT_EQ(SANDBOX_SUCCESS, SandboxMonitor::ConnectToApp(path, socketFd));

    SandboxMonitor monitor(MakeConfig(getpid(), socketFd, deviceFd, path));
    ASSERT_EQ(SANDBOX_SUCCESS, monitor.Init());
    monitor.pendingAnswers_.push_back(TEST_EVENT_ID);

    // The device end goes away: read() will report EOF.
    close(kernelFd);

    MonitorAction action = monitor.HandleDeviceEvent(EPOLLIN);
    EXPECT_EQ(MONITOR_ACTION_DEGRADE, action);
    EXPECT_EQ(SANDBOX_ERR_DEVICE_IO, monitor.monitorError_);

    // Degrading must not stop the loop - the child still needs reaping.
    EXPECT_TRUE(monitor.ApplyAction(action));
    EXPECT_EQ(MONITOR_STATE_DEGRADED, monitor.state_);

    // No reconnect: without a device there would be nothing to send over it.
    EXPECT_TRUE(monitor.socket_ == nullptr);
    EXPECT_EQ(0, monitor.reconnectAttemptsLeft_);
    EXPECT_EQ(-1, monitor.NextEpollTimeout());
    EXPECT_LT(monitor.deviceFd_, 0);
    EXPECT_TRUE(monitor.pendingAnswers_.empty());
    EXPECT_TRUE(monitor.socketTxQueue_.empty());
}

/**
 * @tc.name: MonitorDegradedAnswer001
 * @tc.desc: A degraded monitor tells the app to stop rather than to try another id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorDegradedAnswer001, TestSize.Level0)
{
    int pipeFds[2] = {-1, -1};
    ASSERT_EQ(0, pipe(pipeFds));

    {
        SandboxMonitor monitor(MakeConfig(getpid(), -1, pipeFds[1]));
        monitor.pendingAnswers_.push_back(9);

        // While active the id is answerable.
        EXPECT_EQ(SANDBOX_SUCCESS,
            monitor.HandleEventAnswer(R"({"event_id":"9","action":"allow"})"));

        monitor.pendingAnswers_.push_back(10);
        monitor.state_ = MONITOR_STATE_DEGRADED;

        // Now the answer is refused with a code that means "stop", not
        // "wrong id" - the latter would send the app round a loop that can
        // never succeed.
        EXPECT_EQ(SANDBOX_ERR_MONITOR_DEGRADED,
            monitor.HandleEventAnswer(R"({"event_id":"10","action":"allow"})"));
        EXPECT_EQ(SANDBOX_ERR_MONITOR_DEGRADED, monitor.HandleAddPolicy(VALID_POLICY_JSON));
    }

    close(pipeFds[0]);
}

/**
 * @tc.name: MonitorRequestIdInvalid001
 * @tc.desc: A request reusing requestId 0 is answered, not disconnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorRequestIdInvalid001, TestSize.Level0)
{
    ParsedMessage message = {};
    message.header.msgType = SANDBOX_SOCKET_MSG_EVENT_ANSWER;
    message.header.requestId = 0;
    message.body = R"({"event_id":"9","action":"allow"})";

    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));
    monitor.pendingAnswers_.push_back(9);

    /*
     * requestId 0 is reserved for monitor-originated messages. ValidateMessage
     * turns it into a return code rather than a protocol violation, which is
     * what keeps the connection up - QueueResponse runs the same two steps.
     */
    EXPECT_EQ(SANDBOX_ERR_REQUEST_ID_INVALID, monitor.ValidateMessage(message));
    // Rejected before routing, so the answer never reached the handler.
    EXPECT_EQ(1u, monitor.pendingAnswers_.size());

    // A usable requestId passes validation and only then reaches the handler,
    // which has no device to answer on.
    message.header.requestId = 7;
    EXPECT_EQ(SANDBOX_SUCCESS, monitor.ValidateMessage(message));
    EXPECT_EQ(SANDBOX_ERR_MONITOR_DEGRADED, monitor.DispatchSocketMessage(message));
}

/**
 * @tc.name: MonitorResponseQueued001
 * @tc.desc: A full Tx buffer defers the response instead of dropping the channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorResponseQueued001, TestSize.Level0)
{
    std::string path = MakeSocketPath("resp_queue");
    ASSERT_FALSE(path.empty());
    UdsListener listener(path);
    ASSERT_TRUE(listener.Valid());

    int socketFd = -1;
    ASSERT_EQ(SANDBOX_SUCCESS, SandboxMonitor::ConnectToApp(path, socketFd));

    SandboxMonitor monitor(MakeConfig(getpid(), socketFd, -1));

    // Nobody accepts and drains, so reports pile up until the Tx buffer is full.
    ASSERT_TRUE(FillSocketTxBuffer(*monitor.socket_));

    ParsedMessage message = {};
    message.header.msgType = SANDBOX_SOCKET_MSG_ADD_POLICY;
    message.header.requestId = 11;
    message.body = VALID_POLICY_JSON;

    // Dropping the response would strand a request the app still believes is
    // in flight, so it has to be queued instead.
    monitor.QueueResponse(message);
    ASSERT_EQ(1u, monitor.socketTxQueue_.size());
    EXPECT_EQ(static_cast<uint32_t>(SANDBOX_SOCKET_MSG_RESPONSE),
        monitor.socketTxQueue_.front().msgType);
    EXPECT_EQ(11u, monitor.socketTxQueue_.front().requestId);
}

/**
 * @tc.name: MonitorResponseQueued004
 * @tc.desc: requestId 0 is answered as such even when the body was also refused:
 *           a response the app cannot correlate is no use to it either way
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorResponseQueued004, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));

    ParsedMessage message = {};
    message.header.msgType = SANDBOX_SOCKET_MSG_ADD_POLICY;
    message.header.requestId = 0;
    message.rejectReason = SANDBOX_ERR_SOCKET_MSG_TOO_LARGE;

    monitor.QueueResponse(message);

    ASSERT_EQ(1u, monitor.socketTxQueue_.size());
    EXPECT_EQ(SANDBOX_RSP_BAD_REQUEST_ID, monitor.socketTxQueue_.front().result);
}

/**
 * @tc.name: MonitorResponseQueued003
 * @tc.desc: A frame the socket layer rejected is answered from the verdict alone,
 *           without being dispatched
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorResponseQueued003, TestSize.Level0)
{
    SandboxMonitor monitor(MakeConfig(getpid(), -1, -1));

    // The body was consumed and thrown away by the socket layer, so there is
    // nothing to parse - only a verdict to relay.
    ParsedMessage message = {};
    message.header.msgType = SANDBOX_SOCKET_MSG_ADD_POLICY;
    message.header.requestId = 21;
    message.rejectReason = SANDBOX_ERR_SOCKET_MSG_TOO_LARGE;

    monitor.QueueResponse(message);

    ASSERT_EQ(1u, monitor.socketTxQueue_.size());
    const auto &queued = monitor.socketTxQueue_.front();
    EXPECT_EQ(static_cast<uint32_t>(SANDBOX_SOCKET_MSG_RESPONSE), queued.msgType);
    EXPECT_EQ(21u, queued.requestId);
    EXPECT_EQ(SANDBOX_RSP_BODY_TOO_LARGE, queued.result);
    // An empty body must not be mistaken for an empty policy and accepted.
    EXPECT_TRUE(queued.body.empty());
}

/**
 * @tc.name: MonitorResponseQueued002
 * @tc.desc: A response whose detail body is too large is sent without the body
 *           rather than dropped
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorResponseQueued002, TestSize.Level0)
{
    std::string path = MakeSocketPath("resp_big");
    ASSERT_FALSE(path.empty());
    UdsListener listener(path);
    ASSERT_TRUE(listener.Valid());

    int socketFd = -1;
    ASSERT_EQ(SANDBOX_SUCCESS, SandboxMonitor::ConnectToApp(path, socketFd));

    SandboxMonitor monitor(MakeConfig(getpid(), socketFd, -1));

    // Larger than one message may carry. Still queueable: the monitor's byte
    // budget is deliberately above MAX_BODY_LENGTH (static_assert in the .cpp).
    const std::string oversized(MAX_BODY_LENGTH + 1, 'x');

    monitor.PushResponse(77, SANDBOX_RSP_INTERNAL, oversized);
    ASSERT_EQ(1u, monitor.socketTxQueue_.size());

    // The result still has to reach the app: the body is shed, the response is not.
    EXPECT_EQ(SANDBOX_SUCCESS, monitor.FlushSocketTxQueue());
    EXPECT_TRUE(monitor.socketTxQueue_.empty());
    EXPECT_EQ(0u, monitor.socketTxBytes_);
}

/**
 * @tc.name: MonitorFlushOneAtATime001
 * @tc.desc: Nothing leaves the queue while the socket is still draining the
 *           previous message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorFlushOneAtATime001, TestSize.Level0)
{
    std::string path = MakeSocketPath("one_at_a_time");
    ASSERT_FALSE(path.empty());
    UdsListener listener(path);
    ASSERT_TRUE(listener.Valid());

    // UpdateSocketEpollEvents issues EPOLL_CTL_MOD, so the monitor has to be
    // initialised: without Init() there is no epoll fd and no registration to
    // modify, and the call fails with SANDBOX_ERR_EPOLL_FAILED. Init() needs a
    // real device fd, hence the socketpair standing in for /dev/dec.
    int deviceFd = -1;
    int kernelFd = -1;
    ASSERT_TRUE(MakeSocketPairFds(deviceFd, kernelFd));

    int socketFd = -1;
    ASSERT_EQ(SANDBOX_SUCCESS, SandboxMonitor::ConnectToApp(path, socketFd));

    {
        SandboxMonitor monitor(MakeConfig(getpid(), socketFd, deviceFd, path));
        ASSERT_EQ(SANDBOX_SUCCESS, monitor.Init());

        // Nobody accepts and drains, so a message is left half sent.
        ASSERT_TRUE(FillSocketTxBuffer(*monitor.socket_));
        ASSERT_TRUE(monitor.socket_->HasPendingTxData());

        monitor.PushEventReport(1, true, R"({"event_id":"1"})");
        monitor.PushEventReport(2, true, R"({"event_id":"2"})");

        /*
         * Bytes handed to the socket can no longer be dropped, so backlog has to
         * stay where the oldest entry can still be evicted. Both events remain
         * queued, and neither counts as outstanding - nothing was reported.
         */
        EXPECT_EQ(SANDBOX_SUCCESS, monitor.FlushSocketTxQueue());
        EXPECT_EQ(2u, monitor.socketTxQueue_.size());
        EXPECT_TRUE(monitor.pendingAnswers_.empty());

        // EPOLLOUT must stay armed, or nothing would ever drain the queue.
        EXPECT_EQ(SANDBOX_SUCCESS, monitor.UpdateSocketEpollEvents());
        EXPECT_TRUE(monitor.socketWriteEnabled_);
    }

    close(kernelFd);
}

/**
 * @tc.name: MonitorRun001
 * @tc.desc: The event loop forwards a device event, answers an add policy and an
 *           event answer, and finally returns the monitored child exit code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxMonitorTest, MonitorRun001, TestSize.Level1)
{
    std::string path = MakeSocketPath("run");
    ASSERT_FALSE(path.empty());
    UdsListener listener(path);
    ASSERT_TRUE(listener.Valid());

    int deviceFd = -1;
    int kernelFd = -1;
    ASSERT_TRUE(MakeSocketPairFds(deviceFd, kernelFd));

    // Pipe used to hold the monitored child until the exchange is complete.
    int releaseFds[2] = {-1, -1};
    ASSERT_EQ(0, pipe(releaseFds));

    // The monitored child: it exits with a known code once released.
    pid_t child = fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        close(releaseFds[1]);
        close(deviceFd);
        close(kernelFd);
        alarm(PEER_ALARM_SECONDS);
        char discard = 0;
        while (read(releaseFds[0], &discard, 1) < 0 && errno == EINTR) {
        }
        _exit(PEER_EXIT_OK);
    }

    // The application side: it drives the protocol and then releases the child.
    pid_t peer = fork();
    ASSERT_GE(peer, 0);
    if (peer == 0) {
        close(releaseFds[0]);
        close(deviceFd);
        alarm(PEER_ALARM_SECONDS);
        _exit(RunPeerSide(listener.Fd(), kernelFd, releaseFds[1]));
    }

    close(releaseFds[0]);
    close(releaseFds[1]);
    close(kernelFd);

    g_ioctlMockState.mockEnabled = true;
    g_ioctlMockState.mockFd = deviceFd;
    g_ioctlMockState.failOnCallIndex = -1;
    g_ioctlMockState.ioctlCallCount = 0;

    // Connect after both forks so neither of them inherits the app channel.
    int socketFd = -1;
    ASSERT_EQ(SANDBOX_SUCCESS, SandboxMonitor::ConnectToApp(path, socketFd));

    int runRet = SANDBOX_ERR_GENERIC;
    {
        SandboxMonitor monitor(MakeConfig(child, socketFd, deviceFd));
        ASSERT_EQ(SANDBOX_SUCCESS, monitor.Init());
        runRet = monitor.Run();
    }

    // Report the application side result first: it pinpoints the failing step.
    kill(peer, SIGKILL);
    int peerStatus = 0;
    waitpid(peer, &peerStatus, 0);

    EXPECT_EQ(PEER_EXIT_OK, runRet);
    EXPECT_EQ(1, g_ioctlMockState.ioctlCallCount);
    // The peer is killed while parked in pause(), so a normal exit means it
    // bailed out early on one of its checks.
    if (WIFEXITED(peerStatus)) {
        ADD_FAILURE() << "peer side failed at: " <<
               PeerStepName(WEXITSTATUS(peerStatus));
    }
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
