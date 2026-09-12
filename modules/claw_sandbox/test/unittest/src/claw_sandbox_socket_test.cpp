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

#include "claw_sandbox_socket_test.h"
#include "sandbox_error.h"
#include "sandbox_limits.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <securec.h>
#include <fcntl.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#define private public
#include "sandbox_socket.h"
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
constexpr size_t HEADER_SIZE = sizeof(MessageHeader);
constexpr int POLL_TIMEOUT_MS = 2000;

// Send buffer requested by SocketPairFixture::ShrinkSendBuffer(). Any value well
// under MAX_BODY_LENGTH does; the kernel enforces its own floor.
constexpr int SHRUNK_SNDBUF_BYTES = 4096;

/*
 * The body cap comes from sandbox_limits.h rather than a local copy. The copy
 * that used to live here said 10 MB and was left behind when the real limit was
 * derived from the TLV field table, so every "too large" test was handing over a
 * body ten times past the boundary: they passed, but none of them tested the
 * boundary, and SendMessage003 quietly became a rejected message instead of the
 * back-pressure case it is named for.
 */
constexpr size_t OVERSIZE_BODY_LENGTH = MAX_BODY_LENGTH + 1;

// Serializes a message header followed by body. Every header field is explicit
// so malformed frames can be produced.
std::string BuildRawMessage(uint32_t magic, uint32_t version,
    uint32_t bodyLength, uint32_t msgType, uint32_t requestId, int32_t result,
    const std::string &body)
{
    MessageHeader header = {
        .magic = magic,
        .version = version,
        .bodyLength = bodyLength,
        .msgType = msgType,
        .requestId = requestId,
        .result = result
    };

    std::string raw(reinterpret_cast<const char *>(&header), HEADER_SIZE);
    raw += body;
    return raw;
}

// Well formed frame carrying body.
std::string BuildValidMessage(uint32_t msgType, const std::string &body, uint32_t requestId = 1)
{
    return BuildRawMessage(SANDBOX_SOCKET_MAGIC, SANDBOX_SOCKET_VERSION,
        static_cast<uint32_t>(body.size()), msgType, requestId, 0, body);
}

bool SetNonBlockFd(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

// Writes the whole buffer, waiting for room when the peer buffer is full.
bool WriteAll(int fd, const std::string &data)
{
    size_t offset = 0;
    while (offset < data.size()) {
        ssize_t n = write(fd, data.data() + offset, data.size() - offset);
        if (n > 0) {
            offset += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && (errno == EINTR)) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = {fd, POLLOUT, 0};
            if (poll(&pfd, 1, POLL_TIMEOUT_MS) <= 0) {
                return false;
            }
            continue;
        }
        return false;
    }
    return true;
}

// Reads exactly length bytes, waiting for the peer to supply them.
bool ReadExact(int fd, size_t length, std::string &out)
{
    out.clear();
    out.reserve(length);
    std::vector<char> buf(4096);
    while (out.size() < length) {
        size_t want = std::min(buf.size(), length - out.size());
        ssize_t n = read(fd, buf.data(), want);
        if (n > 0) {
            out.append(buf.data(), static_cast<size_t>(n));
            continue;
        }
        if (n == 0) {
            return false;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            struct pollfd pfd = {fd, POLLIN, 0};
            if (poll(&pfd, 1, POLL_TIMEOUT_MS) <= 0) {
                return false;
            }
            continue;
        }
        return false;
    }
    return true;
}

// Unpacked copy of a wire header. Test assertions must never bind a reference
// to a member of the packed MessageHeader.
struct HeaderView {
    uint32_t magic;
    uint32_t version;
    uint32_t bodyLength;
    uint32_t msgType;
    uint32_t requestId;
    int32_t result;
};

HeaderView ToView(const MessageHeader &header)
{
    HeaderView view = {};
    view.magic = header.magic;
    view.version = header.version;
    view.bodyLength = header.bodyLength;
    view.msgType = header.msgType;
    view.requestId = header.requestId;
    view.result = header.result;
    return view;
}

HeaderView ParseHeader(const std::string &raw)
{
    MessageHeader header = {};
    if (raw.size() >= HEADER_SIZE) {
        // EXPECT, not ASSERT: this helper has to return a value, and the size was
        // already checked, so the copy cannot fail.
        EXPECT_EQ(0, memcpy_s(&header, sizeof(header), raw.data(), HEADER_SIZE));
    }
    return ToView(header);
}
} // namespace

void ClawSandboxSocketTest::SetUpTestCase() {}
void ClawSandboxSocketTest::TearDownTestCase() {}
void ClawSandboxSocketTest::SetUp() {}
void ClawSandboxSocketTest::TearDown() {}

namespace {
// Owns a connected socket pair: sock side is handed to SandboxSocket (which
// takes ownership of the fd), peer side stays with the test.
class SocketPairFixture {
public:
    SocketPairFixture()
    {
        int fds[2] = {-1, -1};
        valid_ = socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0;
        if (!valid_) {
            return;
        }
        socketFd_ = fds[0];
        peerFd_ = fds[1];
        valid_ = SetNonBlockFd(socketFd_) && SetNonBlockFd(peerFd_);
    }

    ~SocketPairFixture()
    {
        ClosePeer();
        // socketFd_ is owned by SandboxSocket once Socket() is constructed.
    }

    void ClosePeer()
    {
        if (peerFd_ >= 0) {
            close(peerFd_);
            peerFd_ = -1;
        }
    }

    bool Valid() const
    {
        return valid_;
    }

    int SocketFd() const
    {
        return socketFd_;
    }

    /*
     * Force the kernel send buffer below MAX_BODY_LENGTH so one maximal message
     * cannot be absorbed in a single write and has to stay pending.
     *
     * Without this the test depends on the host's net.core.wmem_default, which
     * on a stock Linux is around 208 KB - comfortably larger than the 100 KB
     * body, so nothing would ever queue and the back-pressure path would not be
     * exercised at all. The kernel doubles the value and clamps it to its own
     * minimum, so the effective buffer is a few KB either way.
     */
    bool ShrinkSendBuffer()
    {
        int size = SHRUNK_SNDBUF_BYTES;
        return setsockopt(socketFd_, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0;
    }

    int PeerFd() const
    {
        return peerFd_;
    }

private:
    bool valid_ = false;
    int socketFd_ = -1;
    int peerFd_ = -1;
};
} // namespace

/**
 * @tc.name: SocketBasic001
 * @tc.desc: GetFd returns the owned fd and a fresh socket has no pending Tx data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, SocketBasic001, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());

    SandboxSocket socket(fixture.SocketFd());
    EXPECT_EQ(fixture.SocketFd(), socket.GetFd());
    EXPECT_FALSE(socket.HasPendingTxData());
}

/**
 * @tc.name: OnReadable001
 * @tc.desc: OnReadable returns success and no messages when nothing is available
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, OnReadable001, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());

    SandboxSocket socket(fixture.SocketFd());
    std::vector<ParsedMessage> messages;
    EXPECT_EQ(SANDBOX_SUCCESS, socket.OnReadable(messages));
    EXPECT_TRUE(messages.empty());
}

/**
 * @tc.name: OnReadable002
 * @tc.desc: OnReadable parses one complete message and reports its header and body
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, OnReadable002, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());

    SandboxSocket socket(fixture.SocketFd());
    const std::string body = R"({"event_id":"1","action":"allow"})";
    ASSERT_TRUE(WriteAll(fixture.PeerFd(),
        BuildValidMessage(SANDBOX_SOCKET_MSG_EVENT_ANSWER, body, 77)));

    std::vector<ParsedMessage> messages;
    EXPECT_EQ(SANDBOX_SUCCESS, socket.OnReadable(messages));
    ASSERT_EQ(1u, messages.size());
    EXPECT_EQ(static_cast<uint32_t>(SANDBOX_SOCKET_MSG_EVENT_ANSWER),
        ToView(messages[0].header).msgType);
    EXPECT_EQ(77u, ToView(messages[0].header).requestId);
    EXPECT_EQ(body.size(), static_cast<size_t>(ToView(messages[0].header).bodyLength));
    EXPECT_EQ(body, messages[0].body);
}

/**
 * @tc.name: OnReadable003
 * @tc.desc: OnReadable keeps a partially received header pending until the rest arrives
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, OnReadable003, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());

    SandboxSocket socket(fixture.SocketFd());
    const std::string raw = BuildValidMessage(SANDBOX_SOCKET_MSG_ADD_POLICY, "{}");

    ASSERT_TRUE(WriteAll(fixture.PeerFd(), raw.substr(0, 10)));
    std::vector<ParsedMessage> messages;
    EXPECT_EQ(SANDBOX_SUCCESS, socket.OnReadable(messages));
    EXPECT_TRUE(messages.empty());
    EXPECT_EQ(SOCKET_STATE_READING_HEADER, socket.readState_);

    ASSERT_TRUE(WriteAll(fixture.PeerFd(), raw.substr(10)));
    EXPECT_EQ(SANDBOX_SUCCESS, socket.OnReadable(messages));
    ASSERT_EQ(1u, messages.size());
    EXPECT_EQ("{}", messages[0].body);
}

/**
 * @tc.name: OnReadable004
 * @tc.desc: OnReadable keeps a partially received body pending until the rest arrives
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, OnReadable004, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());

    SandboxSocket socket(fixture.SocketFd());
    const std::string body = "0123456789";
    const std::string raw = BuildValidMessage(SANDBOX_SOCKET_MSG_ADD_POLICY, body);

    ASSERT_TRUE(WriteAll(fixture.PeerFd(), raw.substr(0, HEADER_SIZE + 4)));
    std::vector<ParsedMessage> messages;
    EXPECT_EQ(SANDBOX_SUCCESS, socket.OnReadable(messages));
    EXPECT_TRUE(messages.empty());
    EXPECT_EQ(SOCKET_STATE_READING_BODY, socket.readState_);

    ASSERT_TRUE(WriteAll(fixture.PeerFd(), raw.substr(HEADER_SIZE + 4)));
    EXPECT_EQ(SANDBOX_SUCCESS, socket.OnReadable(messages));
    ASSERT_EQ(1u, messages.size());
    EXPECT_EQ(body, messages[0].body);
    EXPECT_EQ(SOCKET_STATE_READING_HEADER, socket.readState_);
}

/**
 * @tc.name: OnReadable005
 * @tc.desc: OnReadable returns every message when several arrive in one chunk
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, OnReadable005, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());

    SandboxSocket socket(fixture.SocketFd());
    std::string raw = BuildValidMessage(SANDBOX_SOCKET_MSG_ADD_POLICY, "first", 1);
    raw += BuildValidMessage(SANDBOX_SOCKET_MSG_EVENT_ANSWER, "second", 2);
    raw += BuildValidMessage(SANDBOX_SOCKET_MSG_ADD_POLICY, "", 3);
    ASSERT_TRUE(WriteAll(fixture.PeerFd(), raw));

    std::vector<ParsedMessage> messages;
    EXPECT_EQ(SANDBOX_SUCCESS, socket.OnReadable(messages));
    ASSERT_EQ(3u, messages.size());
    EXPECT_EQ("first", messages[0].body);
    EXPECT_EQ("second", messages[1].body);
    EXPECT_EQ("", messages[2].body);
    EXPECT_EQ(3u, ToView(messages[2].header).requestId);
}

/**
 * @tc.name: OnReadable006
 * @tc.desc: OnReadable rejects a header with the wrong magic
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, OnReadable006, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());

    SandboxSocket socket(fixture.SocketFd());
    ASSERT_TRUE(WriteAll(fixture.PeerFd(),
        BuildRawMessage(0x12345678, SANDBOX_SOCKET_VERSION, 0,
            SANDBOX_SOCKET_MSG_ADD_POLICY, 1, 0, "")));

    std::vector<ParsedMessage> messages;
    EXPECT_EQ(SANDBOX_ERR_SOCKET_PROTOCOL, socket.OnReadable(messages));
    EXPECT_TRUE(messages.empty());
}

/**
 * @tc.name: OnReadable007
 * @tc.desc: OnReadable rejects an unsupported protocol version
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, OnReadable007, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());

    SandboxSocket socket(fixture.SocketFd());
    ASSERT_TRUE(WriteAll(fixture.PeerFd(),
        BuildRawMessage(SANDBOX_SOCKET_MAGIC, SANDBOX_SOCKET_VERSION + 1, 0,
            SANDBOX_SOCKET_MSG_ADD_POLICY, 1, 0, "")));

    std::vector<ParsedMessage> messages;
    EXPECT_EQ(SANDBOX_ERR_SOCKET_PROTOCOL, socket.OnReadable(messages));
}

/**
 * @tc.name: OnReadable009
 * @tc.desc: An over-long body is consumed and dropped instead of ending the
 *           connection, and the message right behind it still parses
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, OnReadable009, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());

    // Over the 256 byte answer limit, but a perfectly well framed message: the
    // header is trustworthy, so bodyLength still says where the next one starts.
    const std::string oversized(MAX_EVENT_ANSWER_JSON_LENGTH + 1, 'x');
    const std::string good = R"({"event_id":"7","action":"allow"})";

    SandboxSocket socket(fixture.SocketFd());
    ASSERT_TRUE(WriteAll(fixture.PeerFd(),
        BuildValidMessage(SANDBOX_SOCKET_MSG_EVENT_ANSWER, oversized, 11) +
        BuildValidMessage(SANDBOX_SOCKET_MSG_EVENT_ANSWER, good, 12)));

    std::vector<ParsedMessage> messages;
    EXPECT_EQ(SANDBOX_SUCCESS, socket.OnReadable(messages));
    ASSERT_EQ(2U, messages.size());

    // The rejected one is still reported, so the peer can be answered.
    EXPECT_EQ(SANDBOX_ERR_SOCKET_MSG_TOO_LARGE, messages[0].rejectReason);
    EXPECT_EQ(11U, messages[0].header.requestId);
    EXPECT_TRUE(messages[0].body.empty());

    // Resynchronised: nothing of the discarded body leaked into this one.
    EXPECT_EQ(SANDBOX_SUCCESS, messages[1].rejectReason);
    EXPECT_EQ(12U, messages[1].header.requestId);
    EXPECT_EQ(good, messages[1].body);
}

/**
 * @tc.name: OnReadable010
 * @tc.desc: The same holds for an add policy body over its own limit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, OnReadable010, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());

    const std::string oversized(MAX_POLICY_JSON_LENGTH + 1, 'p');

    SandboxSocket socket(fixture.SocketFd());
    ASSERT_TRUE(WriteAll(fixture.PeerFd(),
        BuildValidMessage(SANDBOX_SOCKET_MSG_ADD_POLICY, oversized, 1)));

    std::vector<ParsedMessage> messages;
    EXPECT_EQ(SANDBOX_SUCCESS, socket.OnReadable(messages));
    ASSERT_EQ(1U, messages.size());
    EXPECT_EQ(SANDBOX_ERR_SOCKET_MSG_TOO_LARGE, messages[0].rejectReason);
}

/**
 * @tc.name: OnReadable011
 * @tc.desc: A declared body that has not arrived yet leaves the socket waiting
 *           rather than allocating for it
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, OnReadable011, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());

    // Header only, announcing far more than will ever be sent. Nothing is sized
    // off this number, so the socket simply drops what does arrive.
    SandboxSocket socket(fixture.SocketFd());
    ASSERT_TRUE(WriteAll(fixture.PeerFd(),
        BuildRawMessage(SANDBOX_SOCKET_MAGIC, SANDBOX_SOCKET_VERSION,
            UINT32_MAX, SANDBOX_SOCKET_MSG_EVENT_REPORT, 1, 0, "")));

    std::vector<ParsedMessage> messages;
    EXPECT_EQ(SANDBOX_SUCCESS, socket.OnReadable(messages));
    EXPECT_TRUE(messages.empty());
}

/**
 * @tc.name: OnReadable013
 * @tc.desc: OnReadable reports a peer close while waiting for a header
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, OnReadable013, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());

    SandboxSocket socket(fixture.SocketFd());
    fixture.ClosePeer();

    std::vector<ParsedMessage> messages;
    EXPECT_EQ(SANDBOX_ERR_SOCKET_CLOSED, socket.OnReadable(messages));
}

/**
 * @tc.name: OnReadable014
 * @tc.desc: OnReadable reports a peer close that truncates a message body,
 *           after delivering the messages that did arrive intact
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, OnReadable014, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());

    SandboxSocket socket(fixture.SocketFd());
    std::string raw = BuildValidMessage(SANDBOX_SOCKET_MSG_ADD_POLICY, "complete", 1);
    std::string truncated = BuildValidMessage(SANDBOX_SOCKET_MSG_ADD_POLICY, "incomplete", 2);
    raw += truncated.substr(0, HEADER_SIZE + 2);

    ASSERT_TRUE(WriteAll(fixture.PeerFd(), raw));
    fixture.ClosePeer();

    std::vector<ParsedMessage> messages;
    EXPECT_EQ(SANDBOX_ERR_SOCKET_CLOSED, socket.OnReadable(messages));
    ASSERT_EQ(1u, messages.size());
    EXPECT_EQ("complete", messages[0].body);
}

/**
 * @tc.name: OnReadable015
 * @tc.desc: OnReadable reports an I/O error when the fd cannot be read
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, OnReadable015, TestSize.Level0)
{
    int writeOnlyFd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    ASSERT_GE(writeOnlyFd, 0);

    SandboxSocket socket(writeOnlyFd);
    std::vector<ParsedMessage> messages;
    EXPECT_EQ(SANDBOX_ERR_SOCKET_IO, socket.OnReadable(messages));
}

/**
 * @tc.name: SendMessage001
 * @tc.desc: SendMessage writes a well formed frame that the peer can read back
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, SendMessage001, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());

    SandboxSocket socket(fixture.SocketFd());
    const std::string body = R"({"event_id":"5"})";
    EXPECT_EQ(SANDBOX_SUCCESS, socket.SendMessage(SANDBOX_SOCKET_MSG_EVENT_REPORT, body));
    EXPECT_FALSE(socket.HasPendingTxData());

    std::string raw;
    ASSERT_TRUE(ReadExact(fixture.PeerFd(), HEADER_SIZE + body.size(), raw));

    HeaderView header = ParseHeader(raw);
    EXPECT_EQ(SANDBOX_SOCKET_MAGIC, header.magic);
    EXPECT_EQ(SANDBOX_SOCKET_VERSION, header.version);
    EXPECT_EQ(static_cast<uint32_t>(body.size()), header.bodyLength);
    EXPECT_EQ(static_cast<uint32_t>(SANDBOX_SOCKET_MSG_EVENT_REPORT), header.msgType);
    EXPECT_EQ(0u, header.requestId);
    EXPECT_EQ(0, header.result);
    EXPECT_EQ(body, raw.substr(HEADER_SIZE));
}

/**
 * @tc.name: SendResponse001
 * @tc.desc: SendResponse echoes the request id and carries the result with no body
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, SendResponse001, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());

    SandboxSocket socket(fixture.SocketFd());
    EXPECT_EQ(SANDBOX_SUCCESS, socket.SendResponse(4321, SANDBOX_ERR_CONFIG_INVALID));

    std::string raw;
    ASSERT_TRUE(ReadExact(fixture.PeerFd(), HEADER_SIZE, raw));

    HeaderView header = ParseHeader(raw);
    EXPECT_EQ(static_cast<uint32_t>(SANDBOX_SOCKET_MSG_RESPONSE), header.msgType);
    EXPECT_EQ(4321u, header.requestId);
    EXPECT_EQ(static_cast<int32_t>(SANDBOX_ERR_CONFIG_INVALID), header.result);
    EXPECT_EQ(0u, header.bodyLength);
}

/**
 * @tc.name: SendResponse002
 * @tc.desc: SendResponse carries an optional detail body alongside the result
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, SendResponse002, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());

    const std::string body = R"({"type":"add_policy_result","version":1})";

    SandboxSocket socket(fixture.SocketFd());
    EXPECT_EQ(SANDBOX_SUCCESS, socket.SendResponse(4322, SANDBOX_SUCCESS, body));

    std::string raw;
    ASSERT_TRUE(ReadExact(fixture.PeerFd(), HEADER_SIZE + body.size(), raw));

    HeaderView header = ParseHeader(raw);
    EXPECT_EQ(static_cast<uint32_t>(SANDBOX_SOCKET_MSG_RESPONSE), header.msgType);
    EXPECT_EQ(4322u, header.requestId);
    EXPECT_EQ(0, header.result);
    EXPECT_EQ(static_cast<uint32_t>(body.size()), header.bodyLength);
    EXPECT_EQ(body, raw.substr(HEADER_SIZE));
}

/**
 * @tc.name: SendMessage002
 * @tc.desc: SendMessage rejects a body larger than the protocol maximum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, SendMessage002, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());

    SandboxSocket socket(fixture.SocketFd());
    std::string body(OVERSIZE_BODY_LENGTH, 'a');
    EXPECT_EQ(SANDBOX_ERR_SOCKET_MSG_TOO_LARGE,
        socket.SendMessage(SANDBOX_SOCKET_MSG_EVENT_REPORT, body));
    EXPECT_FALSE(socket.HasPendingTxData());
}

/**
 * @tc.name: SendMessage003
 * @tc.desc: A body that does not fit the kernel buffer stays pending and is
 *           flushed by OnWritable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, SendMessage003, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());
    ASSERT_TRUE(fixture.ShrinkSendBuffer());

    SandboxSocket socket(fixture.SocketFd());
    /*
     * The largest body the protocol accepts. It has to stay within
     * MAX_BODY_LENGTH or SendMessage rejects it outright and there is no pending
     * data to flush. What makes it stay pending is the shrunk send buffer above,
     * not the body size: at 100 KB the body fits a stock AF_UNIX buffer whole.
     * Header plus body is exactly MAX_TX_BUFFER_SIZE, which QueueMessage still
     * accepts on an empty buffer, so the Tx cap is not what is being exercised
     * here - SendMessage004 covers that.
     */
    const size_t bodyLength = MAX_BODY_LENGTH;
    std::string body(bodyLength, 'x');

    EXPECT_EQ(SANDBOX_SUCCESS, socket.SendMessage(SANDBOX_SOCKET_MSG_EVENT_REPORT, body));
    EXPECT_TRUE(socket.HasPendingTxData());

    // Drain from the peer while flushing, exactly as the epoll loop would.
    size_t received = 0;
    const size_t expected = HEADER_SIZE + bodyLength;
    std::vector<char> buf(64 * 1024);
    int guard = 0;
    while (received < expected && guard++ < 10000) {
        ssize_t n = read(fixture.PeerFd(), buf.data(), buf.size());
        if (n > 0) {
            received += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            EXPECT_EQ(SANDBOX_SUCCESS, socket.OnWritable());
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }

    EXPECT_EQ(expected, received);
    EXPECT_FALSE(socket.HasPendingTxData());
    EXPECT_EQ(SANDBOX_SUCCESS, socket.OnWritable());
}

/**
 * @tc.name: SendMessage004
 * @tc.desc: SendMessage rejects a message once the pending Tx buffer is full
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, SendMessage004, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());
    ASSERT_TRUE(fixture.ShrinkSendBuffer());

    SandboxSocket socket(fixture.SocketFd());
    /*
     * Nothing is drained from the peer, so everything beyond the kernel buffer
     * keeps piling up in txBuffer_ until the Tx cap rejects the next message.
     * The body has to stay within MAX_BODY_LENGTH, otherwise every send is
     * refused as too large and the Tx cap is never reached at all.
     */
    std::string body(MAX_BODY_LENGTH, 'y');

    /*
     * With the send buffer shrunk, the first message already leaves more pending
     * than the cap allows, so this only has to be more than one. Kept generous
     * so the test still ends in TX_FULL rather than in the loop bound if the
     * kernel's own send-buffer floor turns out to be larger than asked for.
     */
    const int maxAttempts = 16;

    int ret = SANDBOX_SUCCESS;
    int accepted = 0;
    for (int i = 0; i < maxAttempts; i++) {
        ret = socket.SendMessage(SANDBOX_SOCKET_MSG_EVENT_REPORT, body);
        if (ret != SANDBOX_SUCCESS) {
            break;
        }
        accepted++;
    }

    EXPECT_EQ(SANDBOX_ERR_SOCKET_TX_FULL, ret);
    EXPECT_GT(accepted, 0);
    EXPECT_TRUE(socket.HasPendingTxData());
}

/**
 * @tc.name: OnWritable001
 * @tc.desc: OnWritable succeeds when there is nothing pending
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, OnWritable001, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());

    SandboxSocket socket(fixture.SocketFd());
    EXPECT_EQ(SANDBOX_SUCCESS, socket.OnWritable());
    EXPECT_FALSE(socket.HasPendingTxData());
}

/**
 * @tc.name: OnWritable002
 * @tc.desc: Sending to a closed peer reports the socket as closed instead of raising SIGPIPE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, OnWritable002, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());

    SandboxSocket socket(fixture.SocketFd());
    fixture.ClosePeer();

    EXPECT_EQ(SANDBOX_ERR_SOCKET_CLOSED,
        socket.SendMessage(SANDBOX_SOCKET_MSG_EVENT_REPORT, "payload"));
}

/**
 * @tc.name: OnReadable016
 * @tc.desc: The read state machine recovers cleanly and keeps serving after a
 *           zero length body message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxSocketTest, OnReadable016, TestSize.Level0)
{
    SocketPairFixture fixture;
    ASSERT_TRUE(fixture.Valid());

    SandboxSocket socket(fixture.SocketFd());
    ASSERT_TRUE(WriteAll(fixture.PeerFd(),
        BuildValidMessage(SANDBOX_SOCKET_MSG_ADD_POLICY, "", 9)));

    std::vector<ParsedMessage> messages;
    EXPECT_EQ(SANDBOX_SUCCESS, socket.OnReadable(messages));
    ASSERT_EQ(1u, messages.size());
    EXPECT_TRUE(messages[0].body.empty());
    EXPECT_EQ(0u, socket.headerBytesRead_);
    EXPECT_EQ(0u, socket.bodyBytesRead_);

    messages.clear();
    ASSERT_TRUE(WriteAll(fixture.PeerFd(),
        BuildValidMessage(SANDBOX_SOCKET_MSG_ADD_POLICY, "next", 10)));
    EXPECT_EQ(SANDBOX_SUCCESS, socket.OnReadable(messages));
    ASSERT_EQ(1u, messages.size());
    EXPECT_EQ("next", messages[0].body);
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
