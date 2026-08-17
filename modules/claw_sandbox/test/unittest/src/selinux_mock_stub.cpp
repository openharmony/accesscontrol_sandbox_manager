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

#include "sandbox_mock_state.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>

#undef getcon
#undef getpidcon
#undef is_selinux_enabled
#undef security_check_context
#undef setcon

#include <selinux/selinux.h>

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {
SelinuxMockState g_selinuxMockState;
}  // namespace SANDBOX
}  // namespace AccessControl
}  // namespace OHOS

using namespace OHOS::AccessControl::SANDBOX;

extern "C" {
int WrapIsSelinuxEnabled(void)
{
    if (!g_selinuxMockState.mockEnabled) {
        return is_selinux_enabled();
    }
    return g_selinuxMockState.selinuxEnabled;
}

static int CopyMockContext(const std::string &source, char **context)
{
    if (context == nullptr) {
        errno = EINVAL;
        return -1;
    }
    *context = strdup(source.c_str());
    if (*context == nullptr) {
        errno = ENOMEM;
        return -1;
    }
    return 0;
}

int WrapGetcon(char **context)
{
    if (!g_selinuxMockState.mockEnabled) {
        return getcon(context);
    }
    ++g_selinuxMockState.getconCallCount;
    if (g_selinuxMockState.getconRet < 0) {
        errno = g_selinuxMockState.errorNumber;
        return g_selinuxMockState.getconRet;
    }
    return CopyMockContext(g_selinuxMockState.currentContext, context);
}

int WrapGetpidcon(pid_t pid, char **context)
{
    if (!g_selinuxMockState.mockEnabled) {
        return getpidcon(pid, context);
    }
    ++g_selinuxMockState.getpidconCallCount;
    g_selinuxMockState.capturedPid = pid;
    if (g_selinuxMockState.getpidconRet < 0) {
        errno = g_selinuxMockState.errorNumber;
        return g_selinuxMockState.getpidconRet;
    }
    return CopyMockContext(g_selinuxMockState.targetContext, context);
}

int WrapSecurityCheckContext(const char *context)
{
    if (!g_selinuxMockState.mockEnabled) {
        return security_check_context(context);
    }
    ++g_selinuxMockState.securityCheckCallCount;
    g_selinuxMockState.checkedContext = context == nullptr ? "" : context;
    if (g_selinuxMockState.securityCheckRet < 0) {
        errno = g_selinuxMockState.errorNumber;
    }
    return g_selinuxMockState.securityCheckRet;
}

int WrapSetcon(const char *context)
{
    if (!g_selinuxMockState.mockEnabled) {
        return setcon(context);
    }
    ++g_selinuxMockState.setconCallCount;
    g_selinuxMockState.setconContext = context == nullptr ? "" : context;
    if (g_selinuxMockState.setconRet < 0) {
        errno = g_selinuxMockState.errorNumber;
    }
    return g_selinuxMockState.setconRet;
}
}  // extern "C"
