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

#ifndef CLAW_SANDBOX_LOG_H
#define CLAW_SANDBOX_LOG_H

#include <cstdio>
#include "hilog/log.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef APP_FILE_NAME
#define APP_FILE_NAME   (strrchr((__FILE__), '/') ? strrchr((__FILE__), '/') + 1 : (__FILE__))
#endif

#define OHOS_SANDBOX_HILOG 1

#if OHOS_SANDBOX_HILOG == 1

#define SANDBOX_DOMAIN 0xD005B02
#ifndef SANDBOX_LABEL
#define SANDBOX_LABEL "CLAW_SANDBOX"
#endif

#undef LOG_TAG
#define LOG_TAG SANDBOX_LABEL
#undef LOG_DOMAIN
#define LOG_DOMAIN SANDBOX_DOMAIN

#define SANDBOX_LOGI(fmt, ...) \
    HILOG_INFO(LOG_CORE, "[%{public}s:%{public}d]" fmt, (APP_FILE_NAME), (__LINE__), ##__VA_ARGS__)

#define SANDBOX_LOGE(fmt, ...) \
    HILOG_ERROR(LOG_CORE, "[%{public}s:%{public}d]" fmt, (APP_FILE_NAME), (__LINE__), ##__VA_ARGS__)

#define SANDBOX_LOGD(fmt, ...) \
    HILOG_DEBUG(LOG_CORE, "[%{public}s:%{public}d]" fmt, (APP_FILE_NAME), (__LINE__), ##__VA_ARGS__)

#define SANDBOX_LOGV(fmt, ...) \
    HILOG_DEBUG(LOG_CORE, "[%{public}s:%{public}d]" fmt, (APP_FILE_NAME), (__LINE__), ##__VA_ARGS__)

#define SANDBOX_LOGW(fmt, ...) \
    HILOG_WARN(LOG_CORE, "[%{public}s:%{public}d]" fmt, (APP_FILE_NAME), (__LINE__), ##__VA_ARGS__)

#define SANDBOX_LOGF(fmt, ...) \
    HILOG_FATAL(LOG_CORE, "[%{public}s:%{public}d]" fmt, (APP_FILE_NAME), (__LINE__), ##__VA_ARGS__)

#elif OHOS_SANDBOX_HILOG == 0

#define SANDBOX_LOG_TAG "[CLAW_SANDBOX] "

#define SANDBOX_LOGI(fmt, ...) \
    printf("I " SANDBOX_LOG_TAG "%s:%d " fmt "\n", (APP_FILE_NAME), (__LINE__), ##__VA_ARGS__)

#define SANDBOX_LOGV(fmt, ...) \
    printf("V " SANDBOX_LOG_TAG "%s:%d " fmt "\n", (APP_FILE_NAME), (__LINE__), ##__VA_ARGS__)

#define SANDBOX_LOGW(fmt, ...) \
    printf("W " SANDBOX_LOG_TAG "%s:%d " fmt "\n", (APP_FILE_NAME), (__LINE__), ##__VA_ARGS__)

#define SANDBOX_LOGE(fmt, ...) \
    fprintf(stderr, "E " SANDBOX_LOG_TAG "%s:%d " fmt "\n", (APP_FILE_NAME), (__LINE__), ##__VA_ARGS__)

#define SANDBOX_LOGD(fmt, ...) \
    printf("D " SANDBOX_LOG_TAG "%s:%d " fmt "\n", (APP_FILE_NAME), (__LINE__), ##__VA_ARGS__)

#else

#define SANDBOX_LOGI(fmt, ...)
#define SANDBOX_LOGV(fmt, ...)
#define SANDBOX_LOGW(fmt, ...)
#define SANDBOX_LOGE(fmt, ...)
#define SANDBOX_LOGD(fmt, ...)

#endif

#ifdef __cplusplus
}
#endif

#endif
