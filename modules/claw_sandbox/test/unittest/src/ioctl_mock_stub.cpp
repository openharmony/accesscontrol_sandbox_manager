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

/*
 * ioctl_mock_stub.cpp
 *
 * This file provides mock implementations of open() and ioctl() for unit
 * testing. By defining these symbols in a separate translation unit linked
 * into the test executable, the linker resolves calls from sandbox_manager.cpp
 * to these mock implementations instead of the real libc functions.
 *
 * The mock is controlled via the global g_ioctlMockState:
 *   - When mockEnabled is false (default), all calls are forwarded to the
 *     real kernel via syscall(), so other tests are unaffected.
 *   - When mockEnabled is true, open("/dev/dec") returns a controlled mockFd,
 *     and ioctl calls on that fd return controlled success/failure.
 *
 * This approach enables testing the full DeliverPolicy flow including the
 * file descriptor lifecycle (open → ioctl init → ioctl deliver → close)
 * without requiring the /dev/dec device node to exist.
 */

#include "sandbox_mock_state.h"

#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {
IoctlMockState g_ioctlMockState;
}  // namespace SANDBOX
}  // namespace AccessControl
}  // namespace OHOS
using namespace OHOS::AccessControl::SANDBOX;
extern "C" {
/*
 * Mock open() — intercepts open("/dev/dec", ...) when mock is enabled.
 * All other paths/flag combinations are forwarded to the real kernel
 * via syscall(SYS_openat, AT_FDCWD, ...).
 */
int open(const char *path, int flags, ...)
{
    if (g_ioctlMockState.mockEnabled && path != nullptr &&
        strcmp(path, "/dev/dec") == 0) {
        if (g_ioctlMockState.openFail) {
            errno = g_ioctlMockState.openErrno;
            return -1;
        }
        return g_ioctlMockState.mockFd;
    }

    // Forward to real open via syscall
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    return syscall(SYS_openat, AT_FDCWD, path, flags, mode);
}

/*
 * Mock openat() — intercepts openat(..., "/dev/dec", ...) when mock is enabled.
 * Needed because some libc implementations route open() through openat().
 */
int openat(int dirfd, const char *path, int flags, ...)
{
    if (g_ioctlMockState.mockEnabled && path != nullptr &&
        strcmp(path, "/dev/dec") == 0) {
        if (g_ioctlMockState.openFail) {
            errno = g_ioctlMockState.openErrno;
            return -1;
        }
        return g_ioctlMockState.mockFd;
    }

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    return syscall(SYS_openat, dirfd, path, flags, mode);
}

/*
 * Mock ioctl() — when mock is enabled and fd matches the mock fd,
 * increments ioctlCallCount and returns success or failure based on
 * failOnCallIndex. All other fd/request combinations are forwarded to
 * the real kernel via syscall(SYS_ioctl, ...).
 */
int ioctl(int fd, unsigned long request, ...)
{
    if (g_ioctlMockState.mockEnabled && fd == g_ioctlMockState.mockFd) {
        int callIdx = g_ioctlMockState.ioctlCallCount++;
        if (callIdx == g_ioctlMockState.failOnCallIndex) {
            errno = g_ioctlMockState.ioctlErrno;
            return -1;
        }
        return 0;  // Mock success
    }

    // Forward to real ioctl via syscall
    va_list ap;
    va_start(ap, request);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    return syscall(SYS_ioctl, fd, request, arg);
}

}  // extern "C"
