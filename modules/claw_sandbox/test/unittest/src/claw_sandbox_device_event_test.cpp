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

#include "claw_sandbox_device_event_test.h"
#include "sandbox_device_event.h"
#include "sandbox_error.h"
#include "sandbox_limits.h"

#include <cstring>
#include <securec.h>
#include <string>
#include <vector>

#include "cJSON.h"

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
// TLV tags taken from TLV_FIELD_TABLE in sandbox_device_event.h.
constexpr uint16_t TAG_EVENT_NAME = 1;      // string
constexpr uint16_t TAG_TIMESTAMP = 2;       // string
constexpr uint16_t TAG_UID = 128;           // uint32, rendered as a number
constexpr uint16_t TAG_PID = 131;           // int32, rendered as a number
constexpr uint16_t TAG_COMM = 133;          // string
constexpr uint16_t TAG_CMDLINE = 140;       // string
constexpr uint16_t TAG_EXEC_CMD = 160;      // string
constexpr uint16_t TAG_EXEC_ARGV = 161;     // string
constexpr uint16_t TAG_FILE_SIZE = 258;     // uint64
constexpr uint16_t TAG_FILE_PATH = 259;     // string
constexpr uint16_t TAG_FILE_MODE = 260;     // string
constexpr uint16_t TAG_FILE_OWNERUID = 261; // uint32, rendered as a number
constexpr uint16_t TAG_FILE_OWNERGID = 262; // uint32, rendered as a number
constexpr uint16_t TAG_APPID = 384;         // uint64
constexpr uint16_t TAG_UNKNOWN = 60000;     // not present in TLV_FIELD_TABLE

constexpr size_t EVENT_HEADER_SIZE = sizeof(DeviceEventHeader);
constexpr size_t TLV_HEADER_SIZE = sizeof(TlvHeader);

// Appends one TLV record (tag + length + raw value) to buf.
void AppendTlv(std::vector<uint8_t> &buf, uint16_t tag, const void *value, uint16_t length)
{
    TlvHeader tlv = {};
    tlv.tag = tag;
    tlv.length = length;

    const uint8_t *tlvBytes = reinterpret_cast<const uint8_t *>(&tlv);
    buf.insert(buf.end(), tlvBytes, tlvBytes + TLV_HEADER_SIZE);

    const uint8_t *valueBytes = reinterpret_cast<const uint8_t *>(value);
    buf.insert(buf.end(), valueBytes, valueBytes + length);
}

void AppendStringTlv(std::vector<uint8_t> &buf, uint16_t tag, const std::string &value)
{
    AppendTlv(buf, tag, value.data(), static_cast<uint16_t>(value.size()));
}

void AppendUint64Tlv(std::vector<uint8_t> &buf, uint16_t tag, uint64_t value)
{
    AppendTlv(buf, tag, &value, sizeof(value));
}

void AppendInt64Tlv(std::vector<uint8_t> &buf, uint16_t tag, int64_t value)
{
    AppendTlv(buf, tag, &value, sizeof(value));
}

// Builds a complete device event. When overrideValLen is true the header's
// valLen is forced to the given value so truncated/oversized frames can be
// simulated without changing the payload.
std::vector<uint8_t> BuildEvent(uint64_t eventId, const std::vector<uint8_t> &payload,
    bool overrideValLen = false, uint32_t valLen = 0)
{
    DeviceEventHeader header = {};
    header.version = 1;
    header.eventClass = 2;
    header.eventType = 3;
    header.valLen = overrideValLen ? valLen : static_cast<uint32_t>(payload.size());
    header.eventId = eventId;

    std::vector<uint8_t> buf;
    const uint8_t *headerBytes = reinterpret_cast<const uint8_t *>(&header);
    buf.insert(buf.end(), headerBytes, headerBytes + EVENT_HEADER_SIZE);
    buf.insert(buf.end(), payload.begin(), payload.end());
    return buf;
}

// Returns the string value of context.<name>, or "<missing>" when absent.
std::string GetContextString(const std::string &json, const std::string &name)
{
    cJSON *root = cJSON_Parse(json.c_str());
    if (root == nullptr) {
        return "<parse-failed>";
    }
    std::string result = "<missing>";
    cJSON *context = cJSON_GetObjectItemCaseSensitive(root, "context");
    if (cJSON_IsObject(context)) {
        cJSON *item = cJSON_GetObjectItemCaseSensitive(context, name.c_str());
        if (cJSON_IsString(item) && item->valuestring != nullptr) {
            result = item->valuestring;
        }
    }
    cJSON_Delete(root);
    return result;
}

/*
 * Returns the numeric value of context.<name>, or a sentinel saying why not:
 * NOT_A_NUMBER when the key is there but not a JSON number, which is what
 * separates "rendered as a number" from "rendered as a string" - the whole
 * point of the uid/pid assertions below.
 */
constexpr double CONTEXT_MISSING = -1;
constexpr double CONTEXT_NOT_A_NUMBER = -2;
double GetContextNumber(const std::string &json, const std::string &name)
{
    cJSON *root = cJSON_Parse(json.c_str());
    if (root == nullptr) {
        return CONTEXT_MISSING;
    }
    double result = CONTEXT_MISSING;
    cJSON *context = cJSON_GetObjectItemCaseSensitive(root, "context");
    if (cJSON_IsObject(context)) {
        cJSON *item = cJSON_GetObjectItemCaseSensitive(context, name.c_str());
        if (cJSON_IsNumber(item)) {
            result = item->valuedouble;
        } else if (item != nullptr) {
            result = CONTEXT_NOT_A_NUMBER;
        }
    }
    cJSON_Delete(root);
    return result;
}

// Returns the string value of a top level field, or "<missing>" when absent.
std::string GetRootString(const std::string &json, const std::string &name)
{
    cJSON *root = cJSON_Parse(json.c_str());
    if (root == nullptr) {
        return "<parse-failed>";
    }
    std::string result = "<missing>";
    cJSON *item = cJSON_GetObjectItemCaseSensitive(root, name.c_str());
    if (cJSON_IsString(item) && item->valuestring != nullptr) {
        result = item->valuestring;
    }
    cJSON_Delete(root);
    return result;
}

// Returns the numeric value of a top level field, or -1 when absent.
double GetRootNumber(const std::string &json, const std::string &name)
{
    cJSON *root = cJSON_Parse(json.c_str());
    if (root == nullptr) {
        return -1;
    }
    double result = -1;
    cJSON *item = cJSON_GetObjectItemCaseSensitive(root, name.c_str());
    if (cJSON_IsNumber(item)) {
        result = item->valuedouble;
    }
    cJSON_Delete(root);
    return result;
}
} // namespace

void ClawSandboxDeviceEventTest::SetUpTestCase() {}
void ClawSandboxDeviceEventTest::TearDownTestCase() {}
void ClawSandboxDeviceEventTest::SetUp() {}
void ClawSandboxDeviceEventTest::TearDown() {}

/**
 * @tc.name: ParseEvent001
 * @tc.desc: ParseEvent returns 0 (need more data) for a null buffer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEvent001, TestSize.Level0)
{
    TlvEventParser parser;
    std::string json;
    EXPECT_EQ(ParseStep::DROP, parser.ParseEvent(nullptr, 100, json));
    EXPECT_TRUE(json.empty());
}

/**
 * @tc.name: ParseEvent002
 * @tc.desc: ParseEvent returns 0 when the buffer is shorter than the event header
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEvent002, TestSize.Level0)
{
    TlvEventParser parser;
    std::vector<uint8_t> buf(EVENT_HEADER_SIZE - 1, 0);
    std::string json;
    EXPECT_EQ(ParseStep::DROP, parser.ParseEvent(buf.data(), buf.size(), json));
}

/**
 * @tc.name: ParseEvent003
 * @tc.desc: ParseEvent rejects a header whose valLen exceeds the maximum event length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEvent003, TestSize.Level0)
{
    TlvEventParser parser;
    std::vector<uint8_t> buf = BuildEvent(1, {}, true, static_cast<uint32_t>(MAX_DEVICE_EVENT_LENGTH));
    std::string json;
    EXPECT_EQ(ParseStep::DROP, parser.ParseEvent(buf.data(), buf.size(), json));
}

/**
 * @tc.name: ParseEvent004
 * @tc.desc: ParseEvent returns 0 when the payload announced by valLen has not fully arrived
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEvent004, TestSize.Level0)
{
    TlvEventParser parser;
    std::vector<uint8_t> payload;
    AppendUint64Tlv(payload, TAG_UID, 20020026);

    std::vector<uint8_t> buf = BuildEvent(1, payload);
    std::string json;
    // Hand over everything except the last payload byte.
    EXPECT_EQ(ParseStep::DROP, parser.ParseEvent(buf.data(), buf.size() - 1, json));
}

/**
 * @tc.name: ParseEventFieldLimit001
 * @tc.desc: A field longer than its own limit makes the event illegal, and only
 *           that event - the stream stays aligned
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEventFieldLimit001, TestSize.Level0)
{
    TlvEventParser parser;
    // The kernel truncates every string at TLV_LEN_STRING, so anything longer
    // did not come from it.
    std::vector<uint8_t> payload;
    AppendStringTlv(payload, TAG_COMM, std::string(TLV_LEN_STRING + 1, 'a'));
    AppendUint64Tlv(payload, TAG_UID, 20020026);

    std::vector<uint8_t> buf = BuildEvent(1, payload);
    std::string json;
    // Dropped on its own; records are independent so nothing else is affected.
    EXPECT_EQ(ParseStep::DROP, parser.ParseEvent(buf.data(), buf.size(), json));
    EXPECT_EQ(SANDBOX_ERR_EVENT_FIELD_INVALID, parser.Error());
}

/**
 * @tc.name: ParseEventFieldLimit002
 * @tc.desc: A repeated tag makes the event illegal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEventFieldLimit002, TestSize.Level0)
{
    TlvEventParser parser;
    // One event describes one operation, so two cmdlines contradict each other.
    std::vector<uint8_t> payload;
    AppendStringTlv(payload, TAG_CMDLINE, "/bin/sh -c first");
    AppendStringTlv(payload, TAG_CMDLINE, "/bin/sh -c second");

    std::vector<uint8_t> buf = BuildEvent(1, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DROP, parser.ParseEvent(buf.data(), buf.size(), json));
    EXPECT_EQ(SANDBOX_ERR_EVENT_FIELD_INVALID, parser.Error());
}

/**
 * @tc.name: ParseEventFieldLimit004
 * @tc.desc: comm right at its limit is accepted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEventFieldLimit004, TestSize.Level0)
{
    TlvEventParser parser;
    const std::string atLimit(TLV_LEN_STRING, 'a');
    std::vector<uint8_t> payload;
    AppendStringTlv(payload, TAG_COMM, atLimit);

    std::vector<uint8_t> buf = BuildEvent(1, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DONE, parser.ParseEvent(buf.data(), buf.size(), json));
    EXPECT_EQ(atLimit, GetContextString(json, "comm"));
}

/**
 * @tc.name: ParseEventFieldLimit003
 * @tc.desc: The largest unescaped event the parser accepts still fits one socket
 *           message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEventFieldLimit003, TestSize.Level0)
{
    TlvEventParser parser;
    // cmdline at its limit, every byte rendering as itself.
    const std::string atLimit(TLV_LEN_STRING, 'a');
    std::vector<uint8_t> payload;
    AppendStringTlv(payload, TAG_CMDLINE, atLimit);

    std::vector<uint8_t> buf = BuildEvent(1, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DONE, parser.ParseEvent(buf.data(), buf.size(), json));
    EXPECT_EQ(atLimit, GetContextString(json, "cmdline"));
    EXPECT_LE(json.size(), MAX_BODY_LENGTH);
}

/**
 * @tc.name: ParseEventFieldLimit006
 * @tc.desc: An exec event carries both argv fields; with each capped at
 *           TLV_LEN_STRING the pair still fits a socket message body
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEventFieldLimit006, TestSize.Level0)
{
    TlvEventParser parser;
    const std::string caller(TLV_LEN_STRING, 'a');
    const std::string target(TLV_LEN_STRING, 'b');
    std::vector<uint8_t> payload;
    AppendStringTlv(payload, TAG_CMDLINE, caller);
    AppendStringTlv(payload, TAG_EXEC_ARGV, target);

    std::vector<uint8_t> buf = BuildEvent(1, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DONE, parser.ParseEvent(buf.data(), buf.size(), json));
    EXPECT_EQ(caller, GetContextString(json, "cmdline"));
    EXPECT_EQ(target, GetContextString(json, "exec_argv"));
    EXPECT_LE(json.size(), MAX_BODY_LENGTH);
}

/**
 * @tc.name: ParseEventFieldLimit007
 * @tc.desc: exec_cmd right at PATH_MAX is accepted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEventFieldLimit007, TestSize.Level0)
{
    TlvEventParser parser;
    const std::string atLimit(TLV_LEN_STRING, '/');
    std::vector<uint8_t> payload;
    AppendStringTlv(payload, TAG_EXEC_CMD, atLimit);

    std::vector<uint8_t> buf = BuildEvent(1, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DONE, parser.ParseEvent(buf.data(), buf.size(), json));
    EXPECT_EQ(atLimit, GetContextString(json, "exec_cmd"));
}

/**
 * @tc.name: ParseEventFieldLimit005
 * @tc.desc: The worst case the static bound is built to absorb: every string
 *           field at its cap and every byte a control character, so cJSON
 *           expands each into six. It has to render, and it has to fit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEventFieldLimit005, TestSize.Level0)
{
    TlvEventParser parser;
    /*
     * The shape the static_assert on MAX_DEVICE_EVENT_LENGTH promises to carry.
     * Reachable because a sandboxed process chooses its own argv, so the bytes
     * are not the kernel's to sanitise - which is why the bound has to hold for
     * arbitrary content rather than for plausible content.
     */
    const std::string escaped(TLV_LEN_STRING, '\x01');
    std::vector<uint8_t> payload;
    for (uint16_t tag : {TAG_EVENT_NAME, TAG_TIMESTAMP, TAG_COMM, TAG_CMDLINE,
                         TAG_EXEC_CMD, TAG_EXEC_ARGV, TAG_FILE_PATH, TAG_FILE_MODE}) {
        AppendStringTlv(payload, tag, escaped);
    }

    std::vector<uint8_t> buf = BuildEvent(1, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DONE, parser.ParseEvent(buf.data(), buf.size(), json));

    // Six output bytes per input byte, and still well inside the body limit.
    EXPECT_GT(json.size(), payload.size());
    EXPECT_LE(json.size(), MAX_BODY_LENGTH);
}

/**
 * @tc.name: ParseEvent005
 * @tc.desc: ParseEvent accepts an event without any TLV payload
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEvent005, TestSize.Level0)
{
    TlvEventParser parser;
    std::vector<uint8_t> buf = BuildEvent(42, {});
    std::string json;
    EXPECT_EQ(ParseStep::DONE, parser.ParseEvent(buf.data(), buf.size(), json));
    EXPECT_EQ("42", GetRootString(json, "event_id"));
    EXPECT_EQ(0, static_cast<int>(GetRootNumber(json, "val_len")));
}

/**
 * @tc.name: ParseEvent006
 * @tc.desc: ParseEvent copies every device event header field into the JSON output
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEvent006, TestSize.Level0)
{
    TlvEventParser parser;
    std::vector<uint8_t> payload;
    AppendStringTlv(payload, TAG_EVENT_NAME, "file_open");

    std::vector<uint8_t> buf = BuildEvent(18446744073709551615ULL, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DONE, parser.ParseEvent(buf.data(), buf.size(), json));
    EXPECT_EQ(1, static_cast<int>(GetRootNumber(json, "version")));
    EXPECT_EQ(2, static_cast<int>(GetRootNumber(json, "event_class")));
    EXPECT_EQ(3, static_cast<int>(GetRootNumber(json, "event_type")));
    // The 64 bit event id must survive as a decimal string, not as a double.
    EXPECT_EQ("18446744073709551615", GetRootString(json, "event_id"));
    EXPECT_EQ(static_cast<int>(payload.size()), static_cast<int>(GetRootNumber(json, "val_len")));
}

/**
 * @tc.name: ParseEvent007
 * @tc.desc: ParseEvent converts string TLV fields into the context object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEvent007, TestSize.Level0)
{
    TlvEventParser parser;
    std::vector<uint8_t> payload;
    AppendStringTlv(payload, TAG_EVENT_NAME, "file_open");
    AppendStringTlv(payload, TAG_TIMESTAMP, "2026-08-18T10:00:00");
    AppendStringTlv(payload, TAG_COMM, "claw_sandbox");
    AppendStringTlv(payload, TAG_CMDLINE, "/bin/sh -c ls");
    AppendStringTlv(payload, TAG_FILE_PATH, "/storage/Users/currentUser/Download/a.txt");

    std::vector<uint8_t> buf = BuildEvent(7, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DONE, parser.ParseEvent(buf.data(), buf.size(), json));

    EXPECT_EQ("file_open", GetContextString(json, "event_name"));
    EXPECT_EQ("2026-08-18T10:00:00", GetContextString(json, "timestamp"));
    EXPECT_EQ("claw_sandbox", GetContextString(json, "comm"));
    EXPECT_EQ("/bin/sh -c ls", GetContextString(json, "cmdline"));
    EXPECT_EQ("/storage/Users/currentUser/Download/a.txt", GetContextString(json, "file_path"));
}

/**
 * @tc.name: ParseEventHeader001
 * @tc.desc: ParseEvent reports the event header to callers that ask for it
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEventHeader001, TestSize.Level0)
{
    TlvEventParser parser;
    std::vector<uint8_t> payload;
    AppendStringTlv(payload, TAG_EVENT_NAME, "file_open");

    std::vector<uint8_t> buf = BuildEvent(4242, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DONE, parser.ParseEvent(buf.data(), buf.size(), json));

    // SandboxMonitor routes on these two fields, so they must survive parsing.
    EXPECT_EQ(4242u, parser.Header().eventId);
    EXPECT_EQ(2u, parser.Header().eventClass);

    // An event that never parsed as a header leaves the header all zeroes, so a
    // caller cannot mistake stale routing fields for this event's own.
    std::string ignored;
    EXPECT_EQ(ParseStep::DROP, parser.ParseEvent(buf.data(), buf.size() - 1, ignored));
    EXPECT_EQ(SANDBOX_ERR_DATA_CORRUPT, parser.Error());
    EXPECT_EQ(0u, parser.Header().eventId);
    EXPECT_EQ(0u, parser.Header().eventClass);
}

/**
 * @tc.name: ParseEventHeader002
 * @tc.desc: An unexpected version is reported as corruption, not as a newer format
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEventHeader002, TestSize.Level0)
{
    TlvEventParser parser;
    std::vector<uint8_t> payload;
    AppendStringTlv(payload, TAG_EVENT_NAME, "file_open");
    std::vector<uint8_t> buf = BuildEvent(9, payload);

    // The header carries no magic, so version is one of the few signals that a
    // run of bytes is a header at all. Corrupt it and the event must be refused.
    DeviceEventHeader header = {};
    ASSERT_EQ(0, memcpy_s(&header, sizeof(header), buf.data(), sizeof(header)));
    header.version = DEVICE_EVENT_VERSION + 1;
    ASSERT_EQ(0, memcpy_s(buf.data(), buf.size(), &header, sizeof(header)));

    std::string json;
    EXPECT_EQ(ParseStep::DROP, parser.ParseEvent(buf.data(), buf.size(), json));
}

/**
 * @tc.name: ParseEvent008
 * @tc.desc: ParseEvent renders uint64 TLV fields as decimal strings, which is
 *           the only way a value past 2^53 survives a JSON number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEvent008, TestSize.Level0)
{
    TlvEventParser parser;
    std::vector<uint8_t> payload;
    AppendUint64Tlv(payload, TAG_FILE_SIZE, 18446744073709551615ULL);
    AppendUint64Tlv(payload, TAG_APPID, 0ULL);

    std::vector<uint8_t> buf = BuildEvent(8, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DONE, parser.ParseEvent(buf.data(), buf.size(), json));

    EXPECT_EQ("18446744073709551615", GetContextString(json, "file_size"));
    EXPECT_EQ("0", GetContextString(json, "appid"));
}

/**
 * @tc.name: ParseEvent009
 * @tc.desc: uid and pid render as JSON numbers, not strings: the kernel keeps
 *           them 32-bit, so a double holds them exactly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEvent009, TestSize.Level0)
{
    TlvEventParser parser;
    std::vector<uint8_t> payload;
    AppendUint64Tlv(payload, TAG_UID, 20020026ULL);
    AppendInt64Tlv(payload, TAG_PID, -12345);

    std::vector<uint8_t> buf = BuildEvent(9, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DONE, parser.ParseEvent(buf.data(), buf.size(), json));

    EXPECT_EQ(20020026, GetContextNumber(json, "uid"));
    EXPECT_EQ(-12345, GetContextNumber(json, "pid"));
    // Not merely "reads back as 20020026": a string would too, through a
    // different accessor. This says the JSON type itself changed.
    EXPECT_EQ("<missing>", GetContextString(json, "uid"));
    EXPECT_EQ("<missing>", GetContextString(json, "pid"));
}

/**
 * @tc.name: ParseEventFieldLimit008
 * @tc.desc: A uid wider than the 32 bits it declares makes the event illegal.
 *           Truncating it would hand the app a uid that looks perfectly
 *           plausible and belongs to somebody else.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEventFieldLimit008, TestSize.Level0)
{
    TlvEventParser parser;
    std::vector<uint8_t> payload;
    AppendUint64Tlv(payload, TAG_UID, static_cast<uint64_t>(UINT32_MAX) + 1);

    std::vector<uint8_t> buf = BuildEvent(1, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DROP, parser.ParseEvent(buf.data(), buf.size(), json));
    // A field rule, not corruption: valLen was fine, so the stream stays aligned.
    EXPECT_EQ(SANDBOX_ERR_EVENT_FIELD_INVALID, parser.Error());

    // The largest value that does fit still goes through.
    TlvEventParser wide;
    std::vector<uint8_t> okPayload;
    AppendUint64Tlv(okPayload, TAG_UID, UINT32_MAX);
    std::vector<uint8_t> okBuf = BuildEvent(2, okPayload);
    std::string okJson;
    EXPECT_EQ(ParseStep::DONE, wide.ParseEvent(okBuf.data(), okBuf.size(), okJson));
    EXPECT_EQ(static_cast<double>(UINT32_MAX), GetContextNumber(okJson, "uid"));
}

/**
 * @tc.name: ParseEventFieldLimit009
 * @tc.desc: A pid outside 32-bit range makes the event illegal, at both ends
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEventFieldLimit009, TestSize.Level0)
{
    const int64_t outOfRange[] = {
        static_cast<int64_t>(INT32_MAX) + 1,
        static_cast<int64_t>(INT32_MIN) - 1,
    };
    for (int64_t bad : outOfRange) {
        TlvEventParser parser;
        std::vector<uint8_t> payload;
        AppendInt64Tlv(payload, TAG_PID, bad);

        std::vector<uint8_t> buf = BuildEvent(1, payload);
        std::string json;
        EXPECT_EQ(ParseStep::DROP, parser.ParseEvent(buf.data(), buf.size(), json)) <<
               "accepted pid " << bad;
        EXPECT_EQ(SANDBOX_ERR_EVENT_FIELD_INVALID, parser.Error());
    }

    // Both limits themselves are legal, negatives included.
    const int32_t inRange[] = {INT32_MIN, -1, 0, INT32_MAX};
    for (int32_t good : inRange) {
        TlvEventParser parser;
        std::vector<uint8_t> payload;
        AppendInt64Tlv(payload, TAG_PID, good);

        std::vector<uint8_t> buf = BuildEvent(1, payload);
        std::string json;
        ASSERT_EQ(ParseStep::DONE, parser.ParseEvent(buf.data(), buf.size(), json)) <<
               "rejected pid " << good;
        EXPECT_EQ(static_cast<double>(good), GetContextNumber(json, "pid"));
    }
}

/**
 * @tc.name: ParseEvent010
 * @tc.desc: ParseEvent rejects a uint64 TLV field whose length is not 8 bytes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEvent010, TestSize.Level0)
{
    TlvEventParser parser;
    uint32_t shortValue = 1;
    std::vector<uint8_t> payload;
    AppendTlv(payload, TAG_UID, &shortValue, sizeof(shortValue));

    std::vector<uint8_t> buf = BuildEvent(10, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DROP, parser.ParseEvent(buf.data(), buf.size(), json));
}

/**
 * @tc.name: ParseEvent011
 * @tc.desc: ParseEvent rejects an int64 TLV field whose length is not 8 bytes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEvent011, TestSize.Level0)
{
    TlvEventParser parser;
    uint16_t shortValue = 1;
    std::vector<uint8_t> payload;
    AppendTlv(payload, TAG_PID, &shortValue, sizeof(shortValue));

    std::vector<uint8_t> buf = BuildEvent(11, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DROP, parser.ParseEvent(buf.data(), buf.size(), json));
}

/**
 * @tc.name: ParseEvent012
 * @tc.desc: ParseEvent skips unknown TLV tags and keeps parsing the known ones behind them
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEvent012, TestSize.Level0)
{
    TlvEventParser parser;
    std::vector<uint8_t> payload;
    AppendStringTlv(payload, TAG_UNKNOWN, "ignored");
    AppendStringTlv(payload, TAG_COMM, "after_unknown");

    std::vector<uint8_t> buf = BuildEvent(12, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DONE, parser.ParseEvent(buf.data(), buf.size(), json));

    EXPECT_EQ("after_unknown", GetContextString(json, "comm"));
    EXPECT_EQ(std::string::npos, json.find("ignored"));
}

/**
 * @tc.name: ParseEvent013
 * @tc.desc: ParseEvent rejects a payload that ends in the middle of a TLV header
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEvent013, TestSize.Level0)
{
    TlvEventParser parser;
    std::vector<uint8_t> payload(TLV_HEADER_SIZE - 1, 0);
    std::vector<uint8_t> buf = BuildEvent(13, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DROP, parser.ParseEvent(buf.data(), buf.size(), json));
}

/**
 * @tc.name: ParseEvent014
 * @tc.desc: ParseEvent rejects a TLV whose declared length runs past the payload
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEvent014, TestSize.Level0)
{
    TlvEventParser parser;
    TlvHeader tlv = {};
    tlv.tag = TAG_COMM;
    tlv.length = 100;  // far beyond the four value bytes that follow

    std::vector<uint8_t> payload;
    const uint8_t *tlvBytes = reinterpret_cast<const uint8_t *>(&tlv);
    payload.insert(payload.end(), tlvBytes, tlvBytes + TLV_HEADER_SIZE);
    payload.insert(payload.end(), {'a', 'b', 'c', 'd'});

    std::vector<uint8_t> buf = BuildEvent(14, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DROP, parser.ParseEvent(buf.data(), buf.size(), json));
}

/**
 * @tc.name: ParseEvent015
 * @tc.desc: ParseEvent consumes exactly one event when several are concatenated
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEvent015, TestSize.Level0)
{
    TlvEventParser parser;
    std::vector<uint8_t> firstPayload;
    AppendStringTlv(firstPayload, TAG_COMM, "first");
    std::vector<uint8_t> first = BuildEvent(100, firstPayload);

    std::vector<uint8_t> secondPayload;
    AppendStringTlv(secondPayload, TAG_COMM, "second");
    std::vector<uint8_t> second = BuildEvent(200, secondPayload);

    // One read yields one record, so the two arrive as separate calls.
    std::string json;
    EXPECT_EQ(ParseStep::DONE, parser.ParseEvent(first.data(), first.size(), json));
    EXPECT_EQ("100", GetRootString(json, "event_id"));
    EXPECT_EQ("first", GetContextString(json, "comm"));

    json.clear();
    EXPECT_EQ(ParseStep::DONE, parser.ParseEvent(second.data(), second.size(), json));
    EXPECT_EQ("200", GetRootString(json, "event_id"));
    EXPECT_EQ("second", GetContextString(json, "comm"));
}

/**
 * @tc.name: ParseEvent016
 * @tc.desc: ParseEvent accepts a zero length string TLV
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEvent016, TestSize.Level0)
{
    TlvEventParser parser;
    std::vector<uint8_t> payload;
    AppendStringTlv(payload, TAG_COMM, "");

    std::vector<uint8_t> buf = BuildEvent(16, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DONE, parser.ParseEvent(buf.data(), buf.size(), json));
    EXPECT_EQ("", GetContextString(json, "comm"));
}

/**
 * @tc.name: ParseEvent017
 * @tc.desc: ParseEvent handles a mixed payload of string, uint64 and int64 fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEvent017, TestSize.Level0)
{
    TlvEventParser parser;
    std::vector<uint8_t> payload;
    AppendStringTlv(payload, TAG_EVENT_NAME, "process_exec");
    AppendUint64Tlv(payload, TAG_UID, 1000);
    AppendInt64Tlv(payload, TAG_PID, 4242);
    AppendStringTlv(payload, TAG_CMDLINE, "/bin/ls -l");
    AppendUint64Tlv(payload, TAG_APPID, 999);

    std::vector<uint8_t> buf = BuildEvent(17, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DONE, parser.ParseEvent(buf.data(), buf.size(), json));

    EXPECT_EQ("process_exec", GetContextString(json, "event_name"));
    EXPECT_EQ(1000, GetContextNumber(json, "uid"));
    EXPECT_EQ(4242, GetContextNumber(json, "pid"));
    EXPECT_EQ("/bin/ls -l", GetContextString(json, "cmdline"));
    EXPECT_EQ("999", GetContextString(json, "appid"));
}

/**
 * @tc.name: ParseEvent018
 * @tc.desc: ParseEvent tolerates a valLen that is smaller than the bytes actually supplied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEvent018, TestSize.Level0)
{
    TlvEventParser parser;
    std::vector<uint8_t> payload;
    AppendStringTlv(payload, TAG_COMM, "abcd");

    // Announce an empty payload while still appending one TLV: the parser must
    // consume only the header and leave the TLV bytes for the next event.
    std::vector<uint8_t> buf = BuildEvent(18, payload, true, 0);
    std::string json;
    EXPECT_EQ(ParseStep::DONE, parser.ParseEvent(buf.data(), buf.size(), json));
    EXPECT_EQ("<missing>", GetContextString(json, "comm"));
}

/**
 * @tc.name: ParseEvent019
 * @tc.desc: file_owneruid and file_ownergid render as JSON numbers too. They are
 *           declared UINT32 in TLV_FIELD_TABLE; were one flipped back to UINT64
 *           it would silently start going out as a decimal string, which is a
 *           wire format change no other assertion here would catch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEvent019, TestSize.Level0)
{
    TlvEventParser parser;
    std::vector<uint8_t> payload;
    AppendUint64Tlv(payload, TAG_FILE_OWNERUID, 20020026ULL);
    AppendUint64Tlv(payload, TAG_FILE_OWNERGID, 20010013ULL);

    std::vector<uint8_t> buf = BuildEvent(19, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DONE, parser.ParseEvent(buf.data(), buf.size(), json));

    EXPECT_EQ(20020026, GetContextNumber(json, "file_owneruid"));
    EXPECT_EQ(20010013, GetContextNumber(json, "file_ownergid"));
    // As in ParseEvent009: this is what says the JSON type is a number, since a
    // string would read back with the same digits through another accessor.
    EXPECT_EQ("<missing>", GetContextString(json, "file_owneruid"));
    EXPECT_EQ("<missing>", GetContextString(json, "file_ownergid"));
}

/**
 * @tc.name: ParseEvent020
 * @tc.desc: An owner id wider than 32 bits makes the event illegal, the same as
 *           a uid does: truncating it would name a different, plausible-looking
 *           account as the file's owner.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClawSandboxDeviceEventTest, ParseEvent020, TestSize.Level0)
{
    TlvEventParser parser;
    std::vector<uint8_t> payload;
    AppendUint64Tlv(payload, TAG_FILE_OWNERUID,
        static_cast<uint64_t>(UINT32_MAX) + 1);

    std::vector<uint8_t> buf = BuildEvent(20, payload);
    std::string json;
    EXPECT_EQ(ParseStep::DROP, parser.ParseEvent(buf.data(), buf.size(), json));
    EXPECT_EQ(SANDBOX_ERR_EVENT_FIELD_INVALID, parser.Error());
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
