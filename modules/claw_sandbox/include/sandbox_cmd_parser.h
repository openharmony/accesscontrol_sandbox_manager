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

#ifndef CLAW_SANDBOX_SANDBOX_CMD_PARSER_H
#define CLAW_SANDBOX_SANDBOX_CMD_PARSER_H

#include <string>
#include <vector>
#include <cstdint>

#include "accesstoken_kit.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

/**
 * @brief Sandbox configuration parsed from --config JSON
 */
struct SandboxConfig {
    uint64_t callerTokenId = 0;
    uint32_t callerPid = 0;
    uint32_t uid = 0;
    uint32_t gid = 0;
    std::string challenge;
    std::string appid;
    std::string bundleName;                // Bundle name for <PackageName> substitution
    std::string currentUserId;             // Current user ID for <currentUserId> substitution
    std::string name;                      // Optional hex sandbox name (max 64 chars)
    std::vector<std::string> nsFlags;      // Optional namespace flags, e.g. ["net","pid"]
    std::string cliName;                   // CLI name (required)
    std::string subCliName;                // Sub-CLI name (required)
    OHOS::Security::AccessToken::AccessTokenIDEx tokenIdEx;             // Temporary tokenId
    std::vector<OHOS::Security::AccessToken::PermissionWithValue> kernelPermList;  // Kernel Permission List
};

/**
 * @brief Parsed command info from --cmd argument
 */
struct CmdInfo {
    std::string raw;                       // Original command line string
    std::vector<std::string> argv;         // Parsed argument vector
};

/**
 * @brief Command line argument parser
 */
class CmdParser {
public:
    /**
     * @brief Parse --config JSON string into SandboxConfig
     * @param jsonStr JSON string
     * @param config Output config struct
     * @return SANDBOX_SUCCESS on success, SANDBOX_ERR_CONFIG_INVALID on failure
     */
    static int ParseConfig(const std::string &jsonStr, SandboxConfig &config);

    /**
     * @brief Parse --cmd command line into CmdInfo
     * @param cmdline Command line string
     * @return Parsed CmdInfo
     */
    static CmdInfo ParseCommand(const std::string &cmdline);

    /**
     * @brief Convert namespace flag strings to CLONE_XXX bitmask
     * @param nsFlags String array, e.g. ["net", "pid"]
     * @return Combined CLONE_XXX flags (CLONE_NEWNS is always included)
     */
    static int ConvertNsFlags(const std::vector<std::string> &nsFlags);

private:
    static std::string Trim(const std::string &str);
    static std::vector<std::string> Parse(const std::string &commandLine);
};

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS

#endif // CLAW_SANDBOX_SANDBOX_CMD_PARSER_H
