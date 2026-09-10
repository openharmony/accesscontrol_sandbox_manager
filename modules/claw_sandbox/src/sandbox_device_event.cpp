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

#include "sandbox_device_event.h"

#include <cstdint>
#include <cstring>

#include "cJSON.h"
#include "securec.h"
#include "sandbox_error.h"
#include "sandbox_limits.h"
#include "sandbox_log.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

static const TlvFieldInfo *FindTlvField(uint16_t tag)
{
    for (const TlvFieldInfo &field : TLV_FIELD_TABLE) {
        if (field.tag == tag) {
            return &field;
        }
    }

    return nullptr;
}

// Every numeric field is 8 wire bytes whatever width it declares, so the four
// appenders below differ only in what they accept and how they render.
static int ReadNumericField(const char *name, const uint8_t *data, uint16_t length, uint64_t &value)
{
    if (length != sizeof(uint64_t)) {
        SANDBOX_LOGE("Invalid numeric TLV length %{public}u for field %{public}s", length, name);
        return SANDBOX_ERR_DATA_CORRUPT;
    }
    if (memcpy_s(&value, sizeof(value), data, sizeof(value)) != 0) {
        SANDBOX_LOGE("Failed to copy the numeric value of TLV field %{public}s", name);
        return SANDBOX_ERR_GENERIC;
    }
    return SANDBOX_SUCCESS;
}

static int AddUint64Field(cJSON *object, const char *name, const uint8_t *data, uint16_t length)
{
    uint64_t value = 0;
    int ret = ReadNumericField(name, data, length, value);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    std::string valueStr = std::to_string(value);
    if (cJSON_AddStringToObject(object, name, valueStr.c_str()) == nullptr) {
        return SANDBOX_ERR_GENERIC;
    }

    return SANDBOX_SUCCESS;
}

static int AddInt64Field(cJSON *object, const char *name, const uint8_t *data, uint16_t length)
{
    uint64_t raw = 0;
    int ret = ReadNumericField(name, data, length, raw);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    std::string valueStr = std::to_string(static_cast<int64_t>(raw));
    if (cJSON_AddStringToObject(object, name, valueStr.c_str()) == nullptr) {
        return SANDBOX_ERR_GENERIC;
    }

    return SANDBOX_SUCCESS;
}

// A 32-bit id as a JSON number. Out of range is rejected, not truncated: a
// truncated uid looks perfectly plausible and belongs to somebody else.
static int AddUint32Field(cJSON *object, const char *name, const uint8_t *data, uint16_t length)
{
    uint64_t value = 0;
    int ret = ReadNumericField(name, data, length, value);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    if (value > UINT32_MAX) {
        SANDBOX_LOGE("TLV field %{public}s is %{public}llu, wider than the 32 bits it declares",
            name, static_cast<unsigned long long>(value));
        return SANDBOX_ERR_EVENT_FIELD_INVALID;
    }

    if (cJSON_AddNumberToObject(object, name, static_cast<double>(value)) == nullptr) {
        return SANDBOX_ERR_GENERIC;
    }

    return SANDBOX_SUCCESS;
}

// Signed counterpart of AddUint32Field, for the pid_t-shaped fields.
static int AddInt32Field(cJSON *object, const char *name, const uint8_t *data, uint16_t length)
{
    uint64_t raw = 0;
    int ret = ReadNumericField(name, data, length, raw);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    const int64_t value = static_cast<int64_t>(raw);
    if (value < INT32_MIN || value > INT32_MAX) {
        SANDBOX_LOGE("TLV field %{public}s is %{public}lld, outside the 32 bits it declares",
            name, static_cast<long long>(value));
        return SANDBOX_ERR_EVENT_FIELD_INVALID;
    }

    if (cJSON_AddNumberToObject(object, name, static_cast<double>(value)) == nullptr) {
        return SANDBOX_ERR_GENERIC;
    }

    return SANDBOX_SUCCESS;
}

static int AddStringField(cJSON *object, const char *name, const uint8_t *data, uint16_t length)
{
    std::string value(reinterpret_cast<const char *>(data), length);

    if (cJSON_AddStringToObject(object, name, value.c_str()) == nullptr) {
        return SANDBOX_ERR_GENERIC;
    }

    return SANDBOX_SUCCESS;
}

static int ParseTlvField(const TlvFieldInfo &field,
    const uint8_t *data, uint16_t length, cJSON *context)
{
    switch (field.type) {
        case TLV_VALUE_STRING:
            return AddStringField(context, field.name, data, length);

        case TLV_VALUE_UINT64:
            return AddUint64Field(context, field.name, data, length);

        case TLV_VALUE_INT64:
            return AddInt64Field(context, field.name, data, length);

        case TLV_VALUE_UINT32:
            return AddUint32Field(context, field.name, data, length);

        case TLV_VALUE_INT32:
            return AddInt32Field(context, field.name, data, length);

        default:
            SANDBOX_LOGE("Unknown TLV value type");
            return SANDBOX_ERR_DATA_CORRUPT;
    }
}

/*
 * Render one TLV.
 *
 * An unknown tag is dropped with a warning - it may simply be newer than this
 * build, and the log is how that gets noticed. A known tag that breaks its own
 * rules is not dropped on its own: over its length limit, or seen twice in
 * one event, means the event contradicts itself, and rendering part of it would
 * hand the app something no correct producer would send. Both reject the event.
 *
 * These two rules are also what makes the table a bound rather than an estimate:
 * nothing over maxLength, and nothing twice, can be rendered.
 */
static int ParseKnownTlvField(const TlvHeader &tlv, const uint8_t *value, cJSON *context,
    uint32_t &renderedTags)
{
    const TlvFieldInfo *field = FindTlvField(tlv.tag);
    if (field == nullptr) {
        SANDBOX_LOGW("Dropping unknown TLV tag %{public}u, %{public}u bytes",
            tlv.tag, tlv.length);
        return SANDBOX_SUCCESS;
    }

    if (tlv.length > field->maxLength) {
        SANDBOX_LOGE("TLV field %{public}s is %{public}u bytes, over its %{public}u limit",
            field->name, tlv.length, field->maxLength);
        return SANDBOX_ERR_EVENT_FIELD_INVALID;
    }

    // One event describes one operation, so a second pid or comm is the kernel
    // contradicting itself.
    const uint32_t bit = 1U << static_cast<uint32_t>(field - TLV_FIELD_TABLE);
    if ((renderedTags & bit) != 0) {
        SANDBOX_LOGE("TLV field %{public}s appears more than once", field->name);
        return SANDBOX_ERR_EVENT_FIELD_INVALID;
    }
    renderedTags |= bit;

    return ParseTlvField(*field, value, tlv.length, context);
}

static int ParseTlvFields(const uint8_t *data, size_t size, cJSON *context)
{
    size_t offset = 0;
    // One bit per entry of TLV_FIELD_TABLE, so a repeat is caught in O(1).
    uint32_t renderedTags = 0;

    while (offset < size) {
        if (size - offset < sizeof(TlvHeader)) {
            return SANDBOX_ERR_DATA_CORRUPT;
        }

        TlvHeader tlv = {};
        if (memcpy_s(&tlv, sizeof(tlv), data + offset, sizeof(tlv)) != 0) {
            SANDBOX_LOGE("Failed to copy the TLV header at offset %{public}zu", offset);
            return SANDBOX_ERR_GENERIC;
        }
        offset += sizeof(tlv);

        if (tlv.length > size - offset) {
            SANDBOX_LOGE("TLV tag %{public}u length out of bounds", tlv.tag);
            return SANDBOX_ERR_DATA_CORRUPT;
        }

        int ret = ParseKnownTlvField(tlv, data + offset, context, renderedTags);
        if (ret != SANDBOX_SUCCESS) {
            return ret;
        }

        offset += tlv.length;
    }

    return SANDBOX_SUCCESS;
}


// Vet one record. header is only written on DONE.
static ParseStep ValidateEventFrame(const uint8_t *data, size_t size, DeviceEventHeader &header)
{
    if (data == nullptr || size < sizeof(DeviceEventHeader)) {
        SANDBOX_LOGE("Device event of %{public}zu bytes is shorter than its header", size);
        return ParseStep::DROP;
    }

    DeviceEventHeader parsed = {};
    if (memcpy_s(&parsed, sizeof(parsed), data, sizeof(parsed)) != 0) {
        SANDBOX_LOGE("Failed to copy the device event header");
        return ParseStep::DROP;
    }

    if (parsed.version != DEVICE_EVENT_VERSION) {
        SANDBOX_LOGE("Unexpected event version %{public}u", parsed.version);
        return ParseStep::DROP;
    }

    if (parsed.valLen > MAX_DEVICE_EVENT_LENGTH - sizeof(DeviceEventHeader)) {
        SANDBOX_LOGE("Invalid event value length %{public}u", parsed.valLen);
        return ParseStep::DROP;
    }

    if (size < sizeof(DeviceEventHeader) + static_cast<size_t>(parsed.valLen)) {
        SANDBOX_LOGE("Device event declares %{public}u payload bytes but only %{public}zu arrived",
            parsed.valLen, size - sizeof(DeviceEventHeader));
        return ParseStep::DROP;
    }

    header = parsed;
    return ParseStep::DONE;
}

/*
 * Render one already validated event as JSON.
 *
 * context is attached to root before anything else can fail, so from that point
 * root owns it and every error path is a single cJSON_Delete(root).
 */
static int BuildEventJson(const DeviceEventHeader &header,
    const uint8_t *payload, std::string &jsonOutput)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        return SANDBOX_ERR_GENERIC;
    }

    cJSON *context = cJSON_CreateObject();
    if (context == nullptr || !cJSON_AddItemToObject(root, "context", context)) {
        // root has not taken context over yet, and Delete tolerates a null.
        cJSON_Delete(context);
        cJSON_Delete(root);
        return SANDBOX_ERR_GENERIC;
    }

    std::string eventId = std::to_string(header.eventId);
    if (cJSON_AddNumberToObject(root, "version", header.version) == nullptr ||
        cJSON_AddNumberToObject(root, "event_class", header.eventClass) == nullptr ||
        cJSON_AddNumberToObject(root, "event_type", header.eventType) == nullptr ||
        cJSON_AddNumberToObject(root, "val_len", header.valLen) == nullptr ||
        cJSON_AddStringToObject(root, "event_id", eventId.c_str()) == nullptr) {
        cJSON_Delete(root);
        return SANDBOX_ERR_GENERIC;
    }

    int ret = ParseTlvFields(payload, header.valLen, context);
    if (ret != SANDBOX_SUCCESS) {
        cJSON_Delete(root);
        return ret;
    }

    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return SANDBOX_ERR_GENERIC;
    }

    /*
     * The only bound on rendered size, and a runtime one - the table sums past
     * MAX_BODY_LENGTH on its own (cmdline and exec_argv are both UINT16_MAX).
     * Reject just this event; the caller skips it by valLen.
     */
    const size_t renderedLength = std::strlen(jsonStr);
    if (renderedLength > MAX_BODY_LENGTH) {
        SANDBOX_LOGE("Device event renders to %{public}zu bytes, over the %{public}zu limit",
            renderedLength, MAX_BODY_LENGTH);
        cJSON_free(jsonStr);
        cJSON_Delete(root);
        return SANDBOX_ERR_SOCKET_MSG_TOO_LARGE;
    }

    jsonOutput.assign(jsonStr, renderedLength);

    cJSON_free(jsonStr);
    cJSON_Delete(root);

    return SANDBOX_SUCCESS;
}

ParseStep TlvEventParser::ParseEvent(const uint8_t *data, size_t size, std::string &jsonOutput)
{
    header_ = {};
    error_ = SANDBOX_SUCCESS;

    if (ValidateEventFrame(data, size, header_) != ParseStep::DONE) {
        error_ = SANDBOX_ERR_DATA_CORRUPT;
        return ParseStep::DROP;
    }

    error_ = BuildEventJson(header_, data + sizeof(DeviceEventHeader), jsonOutput);
    return error_ == SANDBOX_SUCCESS ? ParseStep::DONE : ParseStep::DROP;
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
