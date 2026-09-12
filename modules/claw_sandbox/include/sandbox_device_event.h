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

#ifndef CLAW_SANDBOX_DEVICE_EVENT_H
#define CLAW_SANDBOX_DEVICE_EVENT_H

/*
 * The read side of /dev/dec: the event record the kernel hands back and the
 * parser that turns one into JSON.
 *
 * Its companion is sandbox_device_ioctl.h, which owns the write side (the ioctl
 * numbers and their payloads) of the same device. Both are kernel ABI.
 *
 * The TLV here is not the policy TLV of sandbox_op_control_policy.h: this one is
 * [u16 tag][u16 length][value] and travels kernel-to-userspace, that one is
 * [u32 tag][u32 length][value] and travels the other way. They share a name and
 * nothing else.
 */

#include <cstddef>
#include <cstdint>
#include <string>

#include "sandbox_error.h"
#include "sandbox_limits.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

/*
 * The only device event layout this parser understands.
 *
 * The DEC event header carries no magic, so version together with valLen is the
 * only signal that a run of bytes is a header at all. A mismatch is therefore
 * read as "the stream is misaligned", not as "the kernel was upgraded" - once
 * alignment is lost every field, version included, is just noise.
 */
constexpr uint32_t DEVICE_EVENT_VERSION = 1;
/*
 * DEC event wire header. valLen is the byte length of the TLV payload that
 * immediately follows the header.
 *
 * Deliberately not packed: valLen sits before eventId so that the one 8-byte
 * field starts at offset 16 and the natural layout is already the wire layout.
 * The kernel reads these fields in place, so packed would cost it byte-wise
 * access for nothing. The static_asserts below are what hold the ABI now - do
 * not add packed back to "make it safe", add a field and they will tell you.
 */
struct DeviceEventHeader {
    uint32_t version;
    uint32_t eventClass;
    uint32_t eventType;
    uint32_t valLen;
    uint64_t eventId;
};

// DEC TLV wire header. The value occupies exactly length bytes and strings do
// not need a trailing NUL.
struct TlvHeader {
    uint16_t tag;
    uint16_t length;
} __attribute__((packed));

static_assert(sizeof(DeviceEventHeader) == 24, "Invalid device event header size");
// The point of the field order above; reordering silently breaks the kernel ABI.
static_assert(offsetof(DeviceEventHeader, eventId) == 16, "eventId must stay 8-byte aligned");
static_assert(alignof(DeviceEventHeader) == 8, "DeviceEventHeader must stay naturally aligned");
static_assert(sizeof(TlvHeader) == 4, "Invalid device TLV header size");

// UINT64/INT64 render as decimal strings: a cJSON number is a double, and past
// 2^53 it would come out changed. UINT32/INT32 arrive in the same 8 bytes but
// fit a double exactly, so they render as numbers; over 32 bits is malformed.
enum TlvValueType {
    TLV_VALUE_STRING,
    TLV_VALUE_UINT64,
    TLV_VALUE_INT64,
    TLV_VALUE_UINT32,
    TLV_VALUE_INT32,
};

// maxLength is what the field can legitimately be, not what the wire format
// allows. Over it means a malformed event, not something to render.
struct TlvFieldInfo {
    uint16_t tag;
    const char *name;
    TlvValueType type;
    uint16_t maxLength;
};

constexpr uint16_t TLV_LEN_NUMERIC = sizeof(uint64_t);

// The kernel truncates every string it reports at this length, paths and comm
// alike, so one cap covers them all.
constexpr uint16_t TLV_LEN_STRING = 256;

inline constexpr TlvFieldInfo TLV_FIELD_TABLE[] = {
    {1,   "event_name",    TLV_VALUE_STRING, TLV_LEN_STRING},
    {2,   "timestamp",     TLV_VALUE_STRING, TLV_LEN_STRING},

    {128, "uid",           TLV_VALUE_UINT32, TLV_LEN_NUMERIC},
    {131, "pid",           TLV_VALUE_INT32,  TLV_LEN_NUMERIC},
    {133, "comm",          TLV_VALUE_STRING, TLV_LEN_STRING},
    // Separators already replaced with spaces, so an ordinary string.
    {140, "cmdline",       TLV_VALUE_STRING, TLV_LEN_STRING},
    {141, "start_time",    TLV_VALUE_UINT64, TLV_LEN_NUMERIC},

    {160, "exec_cmd",      TLV_VALUE_STRING, TLV_LEN_STRING},
    // The target's argv, where cmdline is the caller's.
    {161, "exec_argv",     TLV_VALUE_STRING, TLV_LEN_STRING},

    {258, "file_size",     TLV_VALUE_UINT64, TLV_LEN_NUMERIC},
    {259, "file_path",     TLV_VALUE_STRING, TLV_LEN_STRING},
    {260, "file_mode",     TLV_VALUE_STRING, TLV_LEN_STRING},
    {261, "file_owneruid", TLV_VALUE_UINT32, TLV_LEN_NUMERIC},
    {262, "file_ownergid", TLV_VALUE_UINT32, TLV_LEN_NUMERIC},
    {279, "open_flags",    TLV_VALUE_UINT64, TLV_LEN_NUMERIC},

    {384, "appid",         TLV_VALUE_UINT64, TLV_LEN_NUMERIC},
    {386, "agentid",       TLV_VALUE_UINT64, TLV_LEN_NUMERIC},
    // 388 is skipped: it was taskid, which the kernel dropped. Not reused, so an
    // older kernel still sending it shows up as an unknown-tag warning.
};

// ParseTlvFields tracks which fields it has already rendered in a uint32_t.
static_assert(sizeof(TLV_FIELD_TABLE) / sizeof(TLV_FIELD_TABLE[0]) <= 32,
    "The seen-tag bitmap has one bit per table entry");

// Largest event the device may hand over, header included. Every tag is capped
// and may appear once, so the table is the bound. Computed so that adding a row
// above is the only edit needed.
constexpr size_t MaxDeviceEventLength()
{
    size_t total = sizeof(DeviceEventHeader);
    for (const TlvFieldInfo &field : TLV_FIELD_TABLE) {
        total += sizeof(TlvHeader) + static_cast<size_t>(field.maxLength);
    }
    return total;
}

constexpr size_t MAX_DEVICE_EVENT_LENGTH = MaxDeviceEventLength();

// cJSON's only expansion is escaping, worst case a control character becoming
// \u0001. Asserting against that keeps every event this parser accepts inside a
// socket message body; the runtime check in BuildEventJson is the backstop.
constexpr size_t JSON_ESCAPE_WORST_CASE = 6;
static_assert(MAX_DEVICE_EVENT_LENGTH * JSON_ESCAPE_WORST_CASE < MAX_BODY_LENGTH,
    "A parsable event must always fit a socket message body");

// One read of /dev/dec yields one whole event, so there is nothing to carry over
// between calls: an event either comes out or it does not.
enum class ParseStep {
    DONE,
    DROP,
};

class TlvEventParser {
public:
    ParseStep ParseEvent(const uint8_t *data, size_t size, std::string &jsonOutput);

    // Valid after DONE, and after any DROP whose Error() is not
    // SANDBOX_ERR_DATA_CORRUPT - that one never parsed a header, so it reads
    // back all zeroes.
    const DeviceEventHeader &Header() const { return header_; }
    // Why the event was dropped. Valid after DROP.
    int Error() const { return error_; }

private:
    DeviceEventHeader header_ = {};
    int error_ = SANDBOX_SUCCESS;
};

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
#endif // CLAW_SANDBOX_DEVICE_EVENT_H
