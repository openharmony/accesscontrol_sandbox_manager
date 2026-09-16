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

#include <cstdint>
#include <cstdio>
#include "hilog/log.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef APP_FILE_NAME
#define APP_FILE_NAME   (strrchr((__FILE__), '/') ? strrchr((__FILE__), '/') + 1 : (__FILE__))
#endif

#define OHOS_SANDBOX_HILOG 1

/* Not a logging concern: the fdsan ownership tags below are built from it too, so
 * it has to stay defined however logging is configured. */
#define SANDBOX_DOMAIN 0xD005B02

#if OHOS_SANDBOX_HILOG == 1

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

/*
 * fdsan ownership tags: one owner per fd, so that a double close is caught.
 *
 * Every fd this module opens and closes itself is tagged with the site that owns
 * it. The check that pays for this is on the close side: fdsan_close_with_tag
 * aborts unless the tag still matches, which is what makes a second close of the
 * same fd -- or a close of a descriptor number that something else has since
 * taken over -- fail loudly instead of silently closing an unrelated fd.
 *
 * Tag layout (uint64_t):
 *   bits 63..32  SANDBOX_DOMAIN  -- this module; services/ tags with a domain of
 *                                   its own, so the two are told apart
 *   bits 31..0   site code       -- which opening site owns the fd
 *
 * MARK claims the fd whatever it already carried, rather than asserting it was
 * untagged. A fresh fd from open() is untagged, but socket() and epoll_create1()
 * are libc wrappers and may have tagged it themselves; an assertion that fires
 * on those would be a false alarm on a correct program. Nothing is given up:
 * the check that catches real bugs is the one at close.
 *
 * Marking is safe on every build. fdsan_* are compiled into the libc regardless
 * of whether fdsan is switched on at runtime, and degrade to plain open/close
 * semantics when it is off -- they are declared by the libc headers, as they are
 * for sandbox_manager_log.h, so no extra include is needed.
 *
 * Deliberately outside the OHOS_SANDBOX_HILOG switch: ownership discipline is not
 * a logging concern and must not vanish when logging is compiled out.
 *
 * Descriptors that cross a fork are tagged the same way, under the rule that fork()
 * copies the tag table: the open site claims the fd, and every close of it --
 * in the parent, in the forked child, or in the monitor the child becomes --
 * uses that same site code. Both processes then see the same owner, and either
 * may close its own copy of the descriptor: the tag is per process and per fd
 * number, so the two closes do not interfere. Claiming twice is harmless, since
 * MARK replaces whatever was there, which is also what lets the receiving side
 * re-claim an fd it was handed rather than inheriting the claim by luck.
 */
#define SANDBOX_FDSAN_TAG(site) \
    (((uint64_t)(SANDBOX_DOMAIN) << 32) | (uint64_t)(site))
#define SANDBOX_FDSAN_MARK(fd, site) \
    fdsan_exchange_owner_tag((fd), fdsan_get_owner_tag(fd), SANDBOX_FDSAN_TAG(site))
#define SANDBOX_FDSAN_CLOSE(fd, site) fdsan_close_with_tag(fd, SANDBOX_FDSAN_TAG(site))

/*
 * Site codes: which opening site owns the fd. Layout of the low half:
 *
 *   bits 31..24  file code (SANDBOX_FDSAN_FILE_*)
 *   bits 23..0   index of the opening site within that file
 *
 * A tag printed as 0xD005B02_04_02 reads as file 0x04, site 2. Give every
 * opening site a code of its own -- sharing one between two opens would hide
 * exactly the mix-up the low half exists to expose.
 */
#define SANDBOX_FDSAN_FILE_AIDS            0x01u
#define SANDBOX_FDSAN_FILE_MANAGER         0x02u
#define SANDBOX_FDSAN_FILE_MOUNT           0x03u
#define SANDBOX_FDSAN_FILE_MONITOR         0x04u
#define SANDBOX_FDSAN_FILE_DELIVER         0x05u
#define SANDBOX_FDSAN_FILE_PARSER          0x06u
#define SANDBOX_FDSAN_FILE_POLICY          0x07u
#define SANDBOX_FDSAN_SITE(file, index) \
    (((uint32_t)(file) << 24) | ((uint32_t)(index) & 0x00FFFFFFu))

/* sandbox_aids.cpp */
#define SANDBOX_FDSAN_SITE_AIDS_DEVICE      SANDBOX_FDSAN_SITE(SANDBOX_FDSAN_FILE_AIDS, 1)
/* sandbox_manager.cpp */
#define SANDBOX_FDSAN_SITE_XPM_DEVICE       SANDBOX_FDSAN_SITE(SANDBOX_FDSAN_FILE_MANAGER, 1)
#define SANDBOX_FDSAN_SITE_DEC_SET          SANDBOX_FDSAN_SITE(SANDBOX_FDSAN_FILE_MANAGER, 2)
#define SANDBOX_FDSAN_SITE_DEC_BATCH        SANDBOX_FDSAN_SITE(SANDBOX_FDSAN_FILE_MANAGER, 3)
#define SANDBOX_FDSAN_SITE_ACCESS_TOKEN     SANDBOX_FDSAN_SITE(SANDBOX_FDSAN_FILE_MANAGER, 4)
#define SANDBOX_FDSAN_SITE_DEC_PATH_MARK    SANDBOX_FDSAN_SITE(SANDBOX_FDSAN_FILE_MANAGER, 5)
#define SANDBOX_FDSAN_SITE_ENCAPS           SANDBOX_FDSAN_SITE(SANDBOX_FDSAN_FILE_MANAGER, 6)
#define SANDBOX_FDSAN_SITE_EXEC_TARGET      SANDBOX_FDSAN_SITE(SANDBOX_FDSAN_FILE_MANAGER, 7)
#define SANDBOX_FDSAN_SITE_START_GATE_READ  SANDBOX_FDSAN_SITE(SANDBOX_FDSAN_FILE_MANAGER, 8)
#define SANDBOX_FDSAN_SITE_START_GATE_WRITE SANDBOX_FDSAN_SITE(SANDBOX_FDSAN_FILE_MANAGER, 9)
/* sandbox_mount.cpp */
#define SANDBOX_FDSAN_SITE_PROC_DIR         SANDBOX_FDSAN_SITE(SANDBOX_FDSAN_FILE_MOUNT, 1)
#define SANDBOX_FDSAN_SITE_NS_MNT           SANDBOX_FDSAN_SITE(SANDBOX_FDSAN_FILE_MOUNT, 2)
#define SANDBOX_FDSAN_SITE_MOUNT_SRC        SANDBOX_FDSAN_SITE(SANDBOX_FDSAN_FILE_MOUNT, 3)
/* sandbox_monitor.cpp */
#define SANDBOX_FDSAN_SITE_MONITOR_CHILD    SANDBOX_FDSAN_SITE(SANDBOX_FDSAN_FILE_MONITOR, 1)
#define SANDBOX_FDSAN_SITE_MONITOR_EPOLL    SANDBOX_FDSAN_SITE(SANDBOX_FDSAN_FILE_MONITOR, 2)
#define SANDBOX_FDSAN_SITE_MONITOR_SOCKET   SANDBOX_FDSAN_SITE(SANDBOX_FDSAN_FILE_MONITOR, 3)
/* sandbox_op_control_deliver.cpp */
#define SANDBOX_FDSAN_SITE_DEC_LOCAL        SANDBOX_FDSAN_SITE(SANDBOX_FDSAN_FILE_DELIVER, 1)
#define SANDBOX_FDSAN_SITE_DEC_PREFORK      SANDBOX_FDSAN_SITE(SANDBOX_FDSAN_FILE_DELIVER, 2)
/* sandbox_op_control_parser.cpp */
#define SANDBOX_FDSAN_SITE_RULE_PATH        SANDBOX_FDSAN_SITE(SANDBOX_FDSAN_FILE_PARSER, 1)
/* sandbox_policy.cpp */
#define SANDBOX_FDSAN_SITE_SOCKET_PATH      SANDBOX_FDSAN_SITE(SANDBOX_FDSAN_FILE_POLICY, 1)

#ifdef __cplusplus
}
#endif

#endif
