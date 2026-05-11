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

#ifndef CLAW_SANDBOX_SANDBOX_EXEC_H
#define CLAW_SANDBOX_SANDBOX_EXEC_H

#include "sandbox_cmd_parser.h"
#include "sandbox_manager.h"
#include "sandbox_error.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

/**
 * @brief claw_sandbox main entry class
 *
 * Responsible for parsing command line arguments, creating a SandboxManager
 * instance, and executing the sandbox workflow.
 * Usage:
 *   claw_sandbox --config <jsonstr> --cmd <cmdline>
 *   claw_sandbox -d --config <jsonstr>
 *
 * All public methods return SandboxError enum values:
 * - SANDBOX_SUCCESS (0): Success
 * - SANDBOX_ERR_BAD_PARAMETERS (-2): Command line argument error
 * - SANDBOX_ERR_CONFIG_INVALID (-4): --config JSON invalid
 * - SANDBOX_ERR_CMD_INVALID (-3): --cmd command invalid
 * - Other SandboxError values returned by SandboxManager internal steps
 */
class SandboxExec {
public:
    SandboxExec() = default;
    ~SandboxExec() = default;

    /**
     * @brief Parse command line arguments
     * @param argc Argument count
     * @param argv Argument array
     * @return SANDBOX_SUCCESS on success, error code on failure
     */
    int ParseArguments(int argc, char *argv[]);

    /**
     * @brief Execute the sandbox
     * @return SANDBOX_SUCCESS on success (current process replaced by execvp), error code on failure
     */
    int Run();

    /**
     * @brief Print usage help
     */
    static void PrintUsage();

    /**
     * @brief Check if --help was requested (in which case config and cmd may not be parsed)
     * @return true if --help was requested
     */
    bool HasHelpRequested() const
    {
        return helpRequested_;
    }

    /**
     * @brief Check if delete mode was requested with -d
     * @return true if delete mode was requested
     */
    bool HasDeleteRequested() const
    {
        return deleteRequested_;
    }

private:
    int ParseConfigArg(int argc, char *argv[]);
    int ParseCmdArg(int argc, char *argv[]);

    SandboxConfig config_;
    CmdInfo cmdInfo_;
    bool configParsed_ = false;
    bool cmdParsed_ = false;
    bool helpRequested_ = false;
    bool deleteRequested_ = false;
};

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS

#endif // CLAW_SANDBOX_SANDBOX_EXEC_H
