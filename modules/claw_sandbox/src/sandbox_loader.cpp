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

#include "sandbox_exec.h"
#include "sandbox_error.h"
#include "sandbox_log.h"

#include <cstdlib>

int main(int argc, char *argv[])
{
    using namespace OHOS::AccessControl::SANDBOX;

    // Create the main entry point and parse arguments
    SandboxExec exec;
    int ret = exec.ParseArguments(argc, argv);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }

    // If --help/-h was used, ParseArguments returns success after printing usage,
    // but config/cmd are not parsed. In that case, skip Run().
    if (exec.HasHelpRequested()) {
        return SANDBOX_SUCCESS;
    }

    // Execute the sandbox -- on success, the current process is replaced by
    // execvp with the target command and never returns.
    ret = exec.Run();
    // Only reached if exec fails
    return ret;
}
