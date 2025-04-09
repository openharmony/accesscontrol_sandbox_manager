/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SANDBOXMANAGER_LOG_H
#define SANDBOXMANAGER_LOG_H

#include <string>
namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

class SandboxManagerLog {
public:
    static std::string MaskRealPath(const char *path);
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS

#ifdef HILOG_ENABLE

#include "hilog/log.h"

/* define LOG_TAG as "accesscontrol_*" at your submodule, * means your submodule name such as "accesscontrol__dac" */
#undef LOG_TAG
#undef LOG_DOMAIN
static constexpr unsigned int ACCESSCONTROL_DOMAIN_SANDBOXMANAGER = 0xD005A07;

#define SANDBOXMANAGER_LOG_DEBUG(label, fmt, ...) \
    ((void)HILOG_IMPL(label.type, LOG_DEBUG, label.domain, label.tag, \
    "[%{public}s]" fmt, __FUNCTION__, ##__VA_ARGS__))
#define SANDBOXMANAGER_LOG_INFO(label, fmt, ...) \
    ((void)HILOG_IMPL(label.type, LOG_INFO, label.domain, label.tag, \
    "[%{public}s]" fmt, __FUNCTION__, ##__VA_ARGS__))
#define SANDBOXMANAGER_LOG_WARN(label, fmt, ...) \
    ((void)HILOG_IMPL(label.type, LOG_WARN, label.domain, label.tag, \
    "[%{public}s]" fmt, __FUNCTION__, ##__VA_ARGS__))
#define SANDBOXMANAGER_LOG_ERROR(label, fmt, ...) \
    ((void)HILOG_IMPL(label.type, LOG_ERROR, label.domain, label.tag, \
    "[%{public}s]" fmt, __FUNCTION__, ##__VA_ARGS__))
#define SANDBOXMANAGER_LOG_FATAL(label, fmt, ...) \
    ((void)HILOG_IMPL(label.type, LOG_FATAL, label.domain, label.tag, \
    "[%{public}s]" fmt, __FUNCTION__, ##__VA_ARGS__))

#else

#include <stdarg.h>
#include <stdio.h>

/* define LOG_TAG as "accesscontrol__*" at your submodule, * means your submodule name such as "accesscontrol__dac" */
#undef LOG_TAG

#define SANDBOXMANAGER_LOG_DEBUG(fmt, ...) printf("[%s] debug: %s: " fmt "\n", LOG_TAG, __func__, ##__VA_ARGS__)
#define SANDBOXMANAGER_LOG_INFO(fmt, ...) printf("[%s] info: %s: " fmt "\n", LOG_TAG, __func__, ##__VA_ARGS__)
#define SANDBOXMANAGER_LOG_WARN(fmt, ...) printf("[%s] warn: %s: " fmt "\n", LOG_TAG, __func__, ##__VA_ARGS__)
#define SANDBOXMANAGER_LOG_ERROR(fmt, ...) printf("[%s] error: %s: " fmt "\n", LOG_TAG, __func__, ##__VA_ARGS__)
#define SANDBOXMANAGER_LOG_FATAL(fmt, ...) printf("[%s] fatal: %s: " fmt "\n", LOG_TAG, __func__, ##__VA_ARGS__)

#endif // HILOG_ENABLE

#endif // SANDBOXMANAGER_LOG_H
