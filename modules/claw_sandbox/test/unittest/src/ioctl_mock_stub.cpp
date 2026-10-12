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
 * This approach enables testing the full DeliverExecuterInit flow including the
 * file descriptor lifecycle (open → daemon init → config get → ioctl deliver
 * → executer init → close) without requiring the /dev/dec device node to exist.
 */

#include "sandbox_mock_state.h"

#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifdef CONFIG_SHELL_SANDBOX
#include "sandbox_device_ioctl.h"
#endif

/*
 * ioctl's second parameter type is the libc's, not ours: musl (OHOS) declares
 * int ioctl(int, int, ...), glibc and Darwin declare
 * int ioctl(int, unsigned long, ...). Once <sys/ioctl.h> is in scope a
 * definition with the other type is a conflicting declaration, so mirror
 * whichever one this build has. glibc additionally declares it noexcept in
 * C++, which the definition has to repeat.
 */
#if defined(__GLIBC__)
using IoctlRequestType = unsigned long;
#define MOCK_IOCTL_EXCEPTION_SPEC __THROW
#elif defined(__APPLE__)
using IoctlRequestType = unsigned long;
#define MOCK_IOCTL_EXCEPTION_SPEC
#else
using IoctlRequestType = int;
#define MOCK_IOCTL_EXCEPTION_SPEC
#endif

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
int ioctl(int fd, IoctlRequestType request, ...) MOCK_IOCTL_EXCEPTION_SPEC
{
    if (g_ioctlMockState.mockEnabled && fd == g_ioctlMockState.mockFd) {
        int callIdx = g_ioctlMockState.ioctlCallCount++;
#ifdef CONFIG_SHELL_SANDBOX
        // Compare the low 32 bits: the libc may have narrowed the unsigned long
        // command to int on the way in, and the command is a u32 encoding anyway.
        if (g_ioctlMockState.capturePolicy &&
            static_cast<unsigned int>(request) == static_cast<unsigned int>(DEC_CMD_POLICY_ADD)) {
            va_list ap;
            va_start(ap, request);
            // Same type the real call passes: va_arg must not change it.
            const auto *arg = va_arg(ap, SandboxPolicyArg *);
            va_end(ap);
            if (arg != nullptr) {
                // Copy before ioctl() returns: the caller frees the context.
                g_ioctlMockState.capturedModuleId = arg->module_id;
                g_ioctlMockState.capturedPolicyTlv.assign(arg->data, arg->data + arg->size);
            }
        }
#endif
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

#undef MOCK_IOCTL_EXCEPTION_SPEC

}  // extern "C"
