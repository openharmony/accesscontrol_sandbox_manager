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

#include "sandbox_manager.h"
#include "sandbox_error.h"
#include "sandbox_log.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <utility>

#include "cJSON.h"
#include "securec.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

static std::string TrimEnvKey(const std::string &rawKey)
{
    size_t begin = 0;
    while (begin < rawKey.size() && std::isspace(static_cast<unsigned char>(rawKey[begin])) != 0) {
        begin++;
    }
    size_t end = rawKey.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(rawKey[end - 1])) != 0) {
        end--;
    }
    return rawKey.substr(begin, end - begin);
}

static std::string ToUpperAscii(const std::string &value)
{
    std::string upper = value;
    std::transform(upper.begin(), upper.end(), upper.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return upper;
}

static int TemplateFieldInvalid(const std::string &field, const char *expected)
{
    std::cerr << "Error: Template field '" << field << "' must be " << expected << std::endl;
    SANDBOX_LOGE("Template field '%{public}s' must be %{public}s", field.c_str(), expected);
    return SANDBOX_ERR_TEMPLATE_INVALID;
}

static int ParseEnvPolicyStringArray(cJSON *envPolicy, const char *fieldName, std::vector<std::string> &values)
{
    if (!cJSON_IsObject(envPolicy) || fieldName == nullptr) {
        return SANDBOX_ERR_TEMPLATE_INVALID;
    }

    cJSON *array = cJSON_GetObjectItem(envPolicy, fieldName);
    if (array == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsArray(array)) {
        return TemplateFieldInvalid(std::string("env-policy.") + fieldName, "an array");
    }

    int size = cJSON_GetArraySize(array);
    for (int i = 0; i < size; i++) {
        cJSON *item = cJSON_GetArrayItem(array, i);
        if (!cJSON_IsString(item) || item->valuestring == nullptr) {
            return TemplateFieldInvalid(
                std::string("env-policy.") + fieldName + "[" + std::to_string(i) + "]", "a string");
        }
        std::string value = ToUpperAscii(TrimEnvKey(item->valuestring));
        if (!value.empty()) {
            values.push_back(value);
        }
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::LoadDefaultConfig()
{
    // System mount entries (simple bind mount, no remount readonly or propagation)
    templateConfig_.systemMounts = {
        {"/proc", "/proc", {"bind", "rec"}, false},
        {"/sys", "/sys", {"bind", "rec"}, false},
        {"/dev", "/dev", {"bind", "rec"}, false},
        {"/tmp", "/tmp", {"bind", "rec"}, false},
        {"/usr", "/usr", {"bind", "rec"}, false},
        {"/etc", "/etc", {"bind", "rec"}, false},
        {"/lib", "/lib", {"bind", "rec"}, false},
        {"/bin", "/bin", {"bind", "rec"}, false},
        {"/sbin", "/sbin", {"bind", "rec"}, false},
        {"/sys_prod", "/sys_prod", {"bind", "rec"}, false},
        {"/system/fonts", "/system/fonts", {"bind", "rec"}, false},
        {"/system/lib", "/system/lib", {"bind", "rec"}, false},
        {"/system/usr", "/system/usr", {"bind", "rec"}, false},
        {"/system/profile", "/system/profile", {"bind", "rec"}, false},
        {"/system/bin", "/system/bin", {"bind", "rec"}, false},
        {"/system/lib64", "/system/lib64", {"bind", "rec"}, false},
        {"/system/etc", "/system/etc", {"bind", "rec"}, false},
        {"/system/framework", "/system/framework", {"bind", "rec"}, false},
        {"/system/resource", "/system/resource", {"bind", "rec"}, false},
        {"/system/app/skills", "/system/app/skills", {"bind", "rec"}, false},
        {"/vendor/lib", "/vendor/lib", {"bind", "rec"}, false},
        {"/vendor/lib64", "/vendor/lib64", {"bind", "rec"}, false},
        {"/config", "/config", {"bind", "rec"}, false},
    };
    templateConfig_.appMounts = {
        {"/storage/media/" + config_.currentUserId + "/local/files/Docs",
            "/storage/Users/" + config_.currentUserId, {"bind", "rec"}, true},
        {"/data/storage/el1/skills", "/data/storage/el1/skills", {"bind", "rec"}, true},
        {"/data/storage/el1/bundle", "/data/storage/el1/bundle", {"bind", "rec"}, true},
    };
    return SANDBOX_SUCCESS;
}

void SandboxManager::ParseMountEntry(cJSON *entry, MountEntry &me)
{
    if (!cJSON_IsObject(entry)) {
        return;
    }

    cJSON *src = cJSON_GetObjectItem(entry, "source");
    if (src == nullptr) {
        src = cJSON_GetObjectItem(entry, "src-path");
    }
    if (cJSON_IsString(src) && src->valuestring != nullptr && strcmp(src->valuestring, "none") != 0) {
        me.source = src->valuestring;
    }
    cJSON *tgt = cJSON_GetObjectItem(entry, "target");
    if (tgt == nullptr) {
        tgt = cJSON_GetObjectItem(entry, "sandbox-path");
    }
    if (cJSON_IsString(tgt) && tgt->valuestring != nullptr && strcmp(tgt->valuestring, "none") != 0) {
        me.target = tgt->valuestring;
    }
    cJSON *mf = cJSON_GetObjectItem(entry, "mount-flags");
    if (cJSON_IsArray(mf)) {
        int mfSize = cJSON_GetArraySize(mf);
        for (int j = 0; j < mfSize; j++) {
            cJSON *item = cJSON_GetArrayItem(mf, j);
            if (cJSON_IsString(item) && item->valuestring != nullptr) {
                me.mountFlags.push_back(item->valuestring);
            }
        }
    }
    cJSON *ce = cJSON_GetObjectItem(entry, "check-exists");
    if (cJSON_IsBool(ce)) {
        me.checkExists = cJSON_IsTrue(ce);
    }
}

int SandboxManager::ParseSystemMountsJson(cJSON *root)
{
    if (!cJSON_IsObject(root)) {
        return SANDBOX_SUCCESS;
    }

    cJSON *sysMounts = cJSON_GetObjectItem(root, "system-mounts");
    if (!cJSON_IsArray(sysMounts)) {
        return SANDBOX_SUCCESS;
    }
    int size = cJSON_GetArraySize(sysMounts);
    for (int i = 0; i < size; i++) {
        cJSON *entry = cJSON_GetArrayItem(sysMounts, i);
        if (!cJSON_IsObject(entry)) {
            continue;
        }
        MountEntry me;
        ParseMountEntry(entry, me);
        if (!me.source.empty() && !me.target.empty()) {
            templateConfig_.systemMounts.push_back(std::move(me));
        }
    }
    return SANDBOX_SUCCESS;
}

void SandboxManager::ParseSymLinkEntry(cJSON *entry, SymLinkEntry &me)
{
    if (!cJSON_IsObject(entry)) {
        return;
    }

    cJSON *src = cJSON_GetObjectItem(entry, "source");
    if (cJSON_IsString(src) && src->valuestring != nullptr) {
        me.source = src->valuestring;
    }
    cJSON *tgt = cJSON_GetObjectItem(entry, "target");
    if (cJSON_IsString(tgt) && tgt->valuestring != nullptr) {
        me.target = tgt->valuestring;
    }
}

int SandboxManager::ParseSymLinkJson(cJSON *root)
{
    if (!cJSON_IsObject(root)) {
        return SANDBOX_SUCCESS;
    }

    cJSON *symbolLinks = cJSON_GetObjectItem(root, "symbol-links");
    if (!cJSON_IsArray(symbolLinks)) {
        return SANDBOX_SUCCESS;
    }
    int size = cJSON_GetArraySize(symbolLinks);
    for (int i = 0; i < size; i++) {
        cJSON *entry = cJSON_GetArrayItem(symbolLinks, i);
        if (!cJSON_IsObject(entry)) {
            continue;
        }
        SymLinkEntry me;
        ParseSymLinkEntry(entry, me);
        if (!me.source.empty() && !me.target.empty()) {
            templateConfig_.symLinks.push_back(std::move(me));
        }
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::ParseAppMountsJson(cJSON *root)
{
    if (!cJSON_IsObject(root)) {
        return SANDBOX_SUCCESS;
    }

    cJSON *appMounts = cJSON_GetObjectItem(root, "app-mounts");
    if (!cJSON_IsArray(appMounts)) {
        return SANDBOX_SUCCESS;
    }
    int size = cJSON_GetArraySize(appMounts);
    for (int i = 0; i < size; i++) {
        cJSON *entry = cJSON_GetArrayItem(appMounts, i);
        if (!cJSON_IsObject(entry)) {
            continue;
        }
        MountEntry me;
        ParseMountEntry(entry, me);
        if (!me.source.empty() && !me.target.empty()) {
            templateConfig_.appMounts.push_back(std::move(me));
        }
    }
    return SANDBOX_SUCCESS;
}

void SandboxManager::ParsePermissionDecPaths(cJSON *obj, PermissionConfig &pc)
{
    if (!cJSON_IsObject(obj)) {
        return;
    }

    cJSON *decPaths = cJSON_GetObjectItem(obj, "dec-paths");
    if (cJSON_IsArray(decPaths)) {
        int dpSize = cJSON_GetArraySize(decPaths);
        for (int j = 0; j < dpSize; j++) {
            cJSON *item = cJSON_GetArrayItem(decPaths, j);
            if (cJSON_IsString(item) && item->valuestring != nullptr) {
                pc.decPaths.push_back(item->valuestring);
            }
        }
    }
}

void SandboxManager::ParsePermissionSwitch(cJSON *obj, PermissionConfig &pc)
{
    ParsePermissionSwitch(obj, pc, false);
}

void SandboxManager::ParsePermissionSwitch(cJSON *obj, PermissionConfig &pc, bool defaultSwitch)
{
    if (!cJSON_IsObject(obj)) {
        pc.sandboxSwitch = defaultSwitch;
        return;
    }

    cJSON *sw = cJSON_GetObjectItem(obj, "sandbox-switch");
    if (sw == nullptr) {
        pc.sandboxSwitch = defaultSwitch;
        return;
    }
    if (cJSON_IsString(sw) && sw->valuestring != nullptr && strcmp(sw->valuestring, "ON") == 0) {
        pc.sandboxSwitch = true;
    } else {
        pc.sandboxSwitch = false;
    }
}

void SandboxManager::ParsePermissionGids(cJSON *obj, PermissionConfig &pc)
{
    if (!cJSON_IsObject(obj)) {
        return;
    }

    cJSON *gids = cJSON_GetObjectItem(obj, "gids");
    if (cJSON_IsArray(gids)) {
        int gidSize = cJSON_GetArraySize(gids);
        for (int j = 0; j < gidSize; j++) {
            cJSON *gidItem = cJSON_GetArrayItem(gids, j);
            if (cJSON_IsNumber(gidItem)) {
                pc.gids.push_back(gidItem->valueint);
            }
        }
    }
}

int SandboxManager::ParseConditionalJson(cJSON *root)
{
    if (!cJSON_IsObject(root)) {
        return TemplateFieldInvalid("<root>", "an object");
    }

    cJSON *cond = cJSON_GetObjectItem(root, "conditional");
    if (cond == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsArray(cond)) {
        return TemplateFieldInvalid("conditional", "an array");
    }

    std::vector<ConditionalRule> rules;
    int arrSize = cJSON_GetArraySize(cond);
    for (int i = 0; i < arrSize; i++) {
        const std::string path = "conditional[" + std::to_string(i) + "]";
        cJSON *item = cJSON_GetArrayItem(cond, i);
        if (!cJSON_IsObject(item)) {
            return TemplateFieldInvalid(path, "an object");
        }

        ConditionalRule rule;
        int ret = ParseConditionalRule(item, rule, path);
        if (ret != SANDBOX_SUCCESS) {
            return ret;
        }
        rules.push_back(std::move(rule));
    }
    templateConfig_.conditionalRules = std::move(rules);
    return SANDBOX_SUCCESS;
}

/*
 * One conditional entry. Every field is optional - a rule may name only a
 * target, for instance - so absence is fine and only a wrong type is not.
 */
// One optional template string field: absent is fine, the wrong type is not.
// Takes the destination rather than the rule, so it needs nothing private.
static int ParseOptionalTemplateString(cJSON *item, const char *field,
    const std::string &path, std::string &value)
{
    cJSON *node = cJSON_GetObjectItem(item, field);
    if (node == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsString(node) || node->valuestring == nullptr) {
        return TemplateFieldInvalid(path + "." + field, "a string");
    }
    value = node->valuestring;
    return SANDBOX_SUCCESS;
}

// One string array field. The index is reported too, so a bad element can be found
// without counting through the array by hand.
static int ParseTemplateStringArray(cJSON *node, const std::string &field,
    std::vector<std::string> &values)
{
    if (!cJSON_IsArray(node)) {
        return TemplateFieldInvalid(field, "an array");
    }
    int size = cJSON_GetArraySize(node);
    for (int j = 0; j < size; j++) {
        cJSON *element = cJSON_GetArrayItem(node, j);
        if (!cJSON_IsString(element) || element->valuestring == nullptr) {
            return TemplateFieldInvalid(field + "[" + std::to_string(j) + "]", "a string");
        }
        values.push_back(element->valuestring);
    }
    return SANDBOX_SUCCESS;
}

// One optional string array field, by name.
static int ParseOptionalTemplateArray(cJSON *item, const char *field,
    const std::string &path, std::vector<std::string> &values)
{
    cJSON *node = cJSON_GetObjectItem(item, field);
    if (node == nullptr) {
        return SANDBOX_SUCCESS;
    }
    return ParseTemplateStringArray(node, path + "." + field, values);
}

// One optional boolean field: absent leaves the default in place.
static int ParseOptionalTemplateBool(cJSON *item, const char *field,
    const std::string &path, bool &value)
{
    cJSON *node = cJSON_GetObjectItem(item, field);
    if (node == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsBool(node)) {
        return TemplateFieldInvalid(path + "." + field, "a boolean");
    }
    value = cJSON_IsTrue(node);
    return SANDBOX_SUCCESS;
}

int SandboxManager::ParseConditionalRule(cJSON *item, ConditionalRule &rule,
    const std::string &path)
{
    int ret = ParseOptionalTemplateString(item, "target", path, rule.target);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    ret = ParseOptionalTemplateString(item, "source", path, rule.source);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    ret = ParseOptionalTemplateArray(item, "mount-flags", path, rule.mountFlags);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    ret = ParseOptionalTemplateArray(item, "permissions", path, rule.permissions);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    return ParseOptionalTemplateBool(item, "check-exists", path, rule.checkExists);
}

int SandboxManager::ParsePermissionJson(cJSON *root)
{
    if (!cJSON_IsObject(root)) {
        return SANDBOX_SUCCESS;
    }

    cJSON *perm = cJSON_GetObjectItem(root, "permission");
    int ret = ParsePermissionSectionJson(perm);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    cJSON *conditional = cJSON_GetObjectItem(root, "conditional");
    if (cJSON_IsObject(conditional)) {
        perm = cJSON_GetObjectItem(conditional, "permission");
        ret = ParsePermissionSectionJson(perm);
    }
    return ret;
}

int SandboxManager::ParsePermissionSectionJson(cJSON *perm)
{
    if (cJSON_IsObject(perm)) {
        SANDBOX_LOGD("[DEBUG INFO] DEC debug parse permission section as object");
        return ParsePermissionObjectJson(perm);
    }
    if (cJSON_IsArray(perm)) {
        SANDBOX_LOGD("[DEBUG INFO] DEC debug parse permission section as array, count=%{public}d",
            cJSON_GetArraySize(perm));
        return ParsePermissionArrayJson(perm);
    }
    SANDBOX_LOGD("[DEBUG INFO] DEC debug parse permission section skip, invalid or missing");
    return SANDBOX_SUCCESS;
}

int SandboxManager::ParsePermissionObjectJson(cJSON *perm)
{
    if (!cJSON_IsObject(perm)) {
        return SANDBOX_SUCCESS;
    }

    cJSON *permItem = nullptr;
    cJSON_ArrayForEach(permItem, perm) {
        int ret = ParseSinglePermissionItem(permItem);
        if (ret != SANDBOX_SUCCESS) {
            return ret;
        }
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::ParsePermissionArrayJson(cJSON *perm)
{
    if (!cJSON_IsArray(perm)) {
        return SANDBOX_SUCCESS;
    }

    int arrSize = cJSON_GetArraySize(perm);
    for (int i = 0; i < arrSize; i++) {
        cJSON *permItem = cJSON_GetArrayItem(perm, i);
        int ret = ParseSinglePermissionArrayItem(permItem);
        if (ret != SANDBOX_SUCCESS) {
            return ret;
        }
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::ParseSinglePermissionItem(cJSON *permItem)
{
    if (!cJSON_IsArray(permItem)) {
        return SANDBOX_SUCCESS;
    }
    if (permItem->string == nullptr || permItem->string[0] == '\0') {
        return SANDBOX_SUCCESS;
    }
    std::string permName = permItem->string;

    // Each permission name maps to an array of config objects
    int arrSize = cJSON_GetArraySize(permItem);
    for (int i = 0; i < arrSize; i++) {
        cJSON *obj = cJSON_GetArrayItem(permItem, i);
        if (!cJSON_IsObject(obj)) {
            continue;
        }
        int ret = ParseSinglePermissionConfig(obj, permName);
        if (ret != SANDBOX_SUCCESS) {
            return ret;
        }
    }
    return SANDBOX_SUCCESS;
}

int SandboxManager::ParseSinglePermissionArrayItem(cJSON *permItem)
{
    if (!cJSON_IsObject(permItem)) {
        SANDBOX_LOGD("[DEBUG INFO] DEC debug parse permission array item skip, non-object");
        return SANDBOX_SUCCESS;
    }

    cJSON *name = cJSON_GetObjectItem(permItem, "name");
    if (!cJSON_IsString(name) || name->valuestring == nullptr || name->valuestring[0] == '\0') {
        SANDBOX_LOGD("[DEBUG INFO] DEC debug parse permission array item skip, missing name");
        return SANDBOX_SUCCESS;
    }
    SANDBOX_LOGD("[DEBUG INFO] DEC debug parse permission array item, permission=%{public}s", name->valuestring);
    return ParseSinglePermissionConfig(permItem, name->valuestring, true);
}

int SandboxManager::ParseSinglePermissionConfig(cJSON *obj, const std::string &permName)
{
    return ParseSinglePermissionConfig(obj, permName, false);
}

int SandboxManager::ParseSinglePermissionConfig(cJSON *obj, const std::string &permName, bool defaultSwitch)
{
    if (!cJSON_IsObject(obj) || permName.empty()) {
        return SANDBOX_SUCCESS;
    }

    PermissionConfig pc;
    ParsePermissionSwitch(obj, pc, defaultSwitch);
    ParsePermissionGids(obj, pc);
    ParsePermissionDecPaths(obj, pc);
    templateConfig_.permissions[permName] = pc;
    return SANDBOX_SUCCESS;
}

// Host environment policy is loaded from the template env-policy section when present.
// It is applied in two stages:
// 1. Inherited environment: variables already present in claw_sandbox's process environment.
// 2. Override environment: variables explicitly passed by the caller through config_.env.
// Caller-provided overrides are less trusted than inherited host values.
int SandboxManager::ParseEnvPolicyJson(cJSON *root)
{
    if (!cJSON_IsObject(root)) {
        return TemplateFieldInvalid("<root>", "an object");
    }

    cJSON *envPolicyObj = cJSON_GetObjectItem(root, "env-policy");
    if (envPolicyObj == nullptr) {
        SANDBOX_LOGD("No env-policy object in template config");
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsObject(envPolicyObj)) {
        return TemplateFieldInvalid("env-policy", "an object");
    }

    EnvPolicy envPolicy;
    const struct {
        const char *field;
        std::vector<std::string> *values;
    } fields[] = {
        {"blocked-everywhere-keys", &envPolicy.blockedEverywhereKeys},
        {"blocked-override-only-keys", &envPolicy.blockedOverrideOnlyKeys},
        {"allowed-inherited-override-only-keys", &envPolicy.allowedInheritedOverrideOnlyKeys},
        {"blocked-prefixes", &envPolicy.blockedPrefixes},
        {"blocked-override-prefixes", &envPolicy.blockedOverridePrefixes},
    };
    for (const auto &entry : fields) {
        int ret = ParseEnvPolicyStringArray(envPolicyObj, entry.field, *entry.values);
        if (ret != SANDBOX_SUCCESS) {
            return ret;
        }
    }
    templateConfig_.envPolicy = std::move(envPolicy);

    SANDBOX_LOGD("Env policy loaded, blockedEverywhere=%{public}zu, blockedOverrideOnly=%{public}zu, "
        "allowedInheritedOverrideOnly=%{public}zu, blockedPrefixes=%{public}zu, "
        "blockedOverridePrefixes=%{public}zu",
        templateConfig_.envPolicy.blockedEverywhereKeys.size(),
        templateConfig_.envPolicy.blockedOverrideOnlyKeys.size(),
        templateConfig_.envPolicy.allowedInheritedOverrideOnlyKeys.size(),
        templateConfig_.envPolicy.blockedPrefixes.size(),
        templateConfig_.envPolicy.blockedOverridePrefixes.size());
    return SANDBOX_SUCCESS;
}

int SandboxManager::ParseExecSelinuxTypesJson(cJSON *root)
{
    if (!cJSON_IsObject(root)) {
        return TemplateFieldInvalid("<root>", "an object");
    }

    cJSON *types = cJSON_GetObjectItem(root, "exec-selinux-types");
    if (types == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsArray(types)) {
        return TemplateFieldInvalid("exec-selinux-types", "an array");
    }

    std::vector<std::string> parsed;
    int size = cJSON_GetArraySize(types);
    for (int i = 0; i < size; i++) {
        cJSON *item = cJSON_GetArrayItem(types, i);
        // SELinux types are matched verbatim, so no trimming or case folding.
        if (!cJSON_IsString(item) || item->valuestring == nullptr || item->valuestring[0] == '\0') {
            return TemplateFieldInvalid(
                "exec-selinux-types[" + std::to_string(i) + "]", "a non-empty string");
        }
        parsed.push_back(item->valuestring);
    }
    templateConfig_.execSelinuxTypes = std::move(parsed);
    return SANDBOX_SUCCESS;
}

int SandboxManager::ParseSeccompJson(cJSON *root)
{
    if (!cJSON_IsObject(root)) {
        return TemplateFieldInvalid("<root>", "an object");
    }

    cJSON *seccomp = cJSON_GetObjectItem(root, "seccomp");
    if (seccomp == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsObject(seccomp)) {
        return TemplateFieldInvalid("seccomp", "an object");
    }
    cJSON *allowList = cJSON_GetObjectItem(seccomp, "allow-list");
    if (allowList == nullptr) {
        return SANDBOX_SUCCESS;
    }
    if (!cJSON_IsArray(allowList)) {
        return TemplateFieldInvalid("seccomp.allow-list", "an array");
    }
    // Collected locally and committed at the end, so a template that fails half
    // way through leaves nothing behind for the caller to reason about.
    std::vector<std::string> allowed;
    int size = cJSON_GetArraySize(allowList);
    for (int i = 0; i < size; i++) {
        cJSON *item = cJSON_GetArrayItem(allowList, i);
        if (!cJSON_IsString(item) || item->valuestring == nullptr) {
            return TemplateFieldInvalid(
                "seccomp.allow-list[" + std::to_string(i) + "]", "a string");
        }
        allowed.push_back(item->valuestring);
    }
    templateConfig_.seccompAllowList = std::move(allowed);
    return SANDBOX_SUCCESS;
}

int SandboxManager::LoadJsonConfig(const std::string &jsonPath)
{
    std::ifstream file(jsonPath);
    if (!file.is_open()) {
        SANDBOX_LOGW("Template config not found at %{public}s, using defaults",
            jsonPath.c_str());
        return LoadDefaultConfig();
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();

    std::unique_ptr<cJSON, decltype(&cJSON_Delete)> root_ptr(cJSON_Parse(content.c_str()), cJSON_Delete);
    cJSON *root = root_ptr.get();

    if (!cJSON_IsObject(root)) {
        std::cerr << "Error: Failed to parse template JSON: " << jsonPath << std::endl;
        SANDBOX_LOGE("Failed to parse template JSON: %{public}s", jsonPath.c_str());
        return SANDBOX_ERR_TEMPLATE_INVALID;
    }

    using ParseStep = int (SandboxManager::*)(cJSON*);
    ParseStep steps[] = {
        &SandboxManager::ParseSystemMountsJson,
        &SandboxManager::ParseSymLinkJson,
        &SandboxManager::ParseAppMountsJson,
        &SandboxManager::ParsePermissionJson,
        &SandboxManager::ParseSeccompJson,
        &SandboxManager::ParseEnvPolicyJson,
        &SandboxManager::ParseConditionalJson,
        &SandboxManager::ParseExecSelinuxTypesJson
    };

    for (auto step : steps) {
        int ret = (this->*step)(root);
        if (ret != SANDBOX_SUCCESS) {
            return ret;
        }
    }

    SANDBOX_LOGD("Template config loaded from %{public}s", jsonPath.c_str());
    return SANDBOX_SUCCESS;
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
