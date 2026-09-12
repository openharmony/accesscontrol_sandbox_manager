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

#ifndef SANDBOX_TEST_PRIVILEGED_H
#define SANDBOX_TEST_PRIVILEGED_H

#include <cerrno>
#include <functional>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

/*
 * Runs one step that permanently mutates the process, in a child.
 *
 * capset(), setgroups(), seccomp, ApplyEnvironment(), chdir() and the namespace
 * and mount steps are all one-way and process wide. Run in-process they outlive
 * the test that asked for them, and it is the later tests that fail - with
 * EACCES on a temp file, say, long after the capabilities were dropped.
 *
 * Forking contains it while still running the real call. Build whatever the step
 * needs beforehand; the child performs only that one call. Returns false if the
 * child could not be run, leaving result untouched.
 */
inline bool RunPrivilegedStepInChild(const std::function<int()> &step, int &result)
{
    int pipeFds[2] = {-1, -1};
    if (pipe(pipeFds) != 0) {
        return false;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipeFds[0]);
        close(pipeFds[1]);
        return false;
    }

    if (pid == 0) {
        close(pipeFds[0]);
        int childRet = step();
        ssize_t written = write(pipeFds[1], &childRet, sizeof(childRet));
        // _exit, not exit: the child must not run the test process's destructors.
        _exit(written == static_cast<ssize_t>(sizeof(childRet)) ? 0 : 1);
    }

    close(pipeFds[1]);
    int childRet = 0;
    bool gotResult = read(pipeFds[0], &childRet, sizeof(childRet)) ==
        static_cast<ssize_t>(sizeof(childRet));
    close(pipeFds[0]);

    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);

    if (!gotResult || waited < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return false;
    }

    result = childRet;
    return true;
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS

#endif // SANDBOX_TEST_PRIVILEGED_H
