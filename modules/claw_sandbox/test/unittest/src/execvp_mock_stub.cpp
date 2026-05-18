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
 * execvp_mock_stub.cpp
 *
 * This file provides mock implementations of exec-family functions for unit
 * testing. By defining these symbols in a separate translation unit that is
 * linked into the test executable, the linker will resolve calls to these
 * functions from sandbox_manager.cpp to these mock implementations instead of
 * the real libc functions (linker interposition).
 *
 * We mock execve() as the common backend because:
 *   - On macOS, execl() and execvp() in libc both delegate to execve()
 *   - Intercepting execve() ensures all exec-family call paths are covered
 *   - execvp() is also mocked directly for platforms where it uses a
 *     different syscall path
 *
 * This approach is more reliable than preprocessor-based mocking
 * (-Dexecvp=__wrap_execvp) because it operates at the linker level and is not
 * affected by compiler flag forwarding issues in the build system.
 *
 * IMPORTANT: This file must NOT #include <unistd.h> because that would conflict
 * with the function definitions below (unistd.h declares these functions as
 * well). We only include <errno.h> for the errno macro and EACCES constant.
 */
#include <cerrno>

extern "C" {
/*
 * Mock execve() -- the common backend for execl(), execv(), execle(), execve(),
 * execvp(), and execvpe() on macOS. By intercepting this function, we ensure
 * that all exec-family calls from sandbox_manager.cpp are safely mocked.
 */
int execve(const char *path, char *const argv[], char *const envp[])
{
    (void)path;
    (void)argv;
    (void)envp;
    errno = EACCES;
    return -1;
}

/*
 * Mock execvp() for platforms where it may use a direct syscall path instead
 * of delegating to execve().
 */
int execvp(const char *file, char *const argv[])
{
    (void)file;
    (void)argv;
    errno = EACCES;
    return -1;
}

/*
 * Mock execl() for platforms where it may use a direct syscall path instead
 * of delegating to execve().
 */
int execl(const char *path, const char *arg, ...)
{
    (void)path;
    (void)arg;
    errno = EACCES;
    return -1;
}

}  // extern "C"
