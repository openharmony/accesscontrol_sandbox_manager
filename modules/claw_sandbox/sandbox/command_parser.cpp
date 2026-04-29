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

#include "command_parser.h"
#include "sandbox_log.h"
#include <cctype>
#include <sstream>

namespace OHOS {
namespace Sandbox {

std::string CommandParser::Trim(const std::string& str)
{
    size_t first = str.find_first_not_of(" \t\n\r\f\v");
    if (first == std::string::npos) {
        return "";
    }
    size_t last = str.find_last_not_of(" \t\n\r\f\v");
    return str.substr(first, last - first + 1);
}

bool CommandParser::NeedShellFallback(const std::string& cmd)
{
    size_t pos = 0;
    bool inQuote = false;
    char quoteChar = '\0';

    while (pos < cmd.length()) {
        char c = cmd[pos];

        if (!inQuote && (c == '"' || c == '\'')) {
            inQuote = true;
            quoteChar = c;
            pos++;
            continue;
        } else if (inQuote && c == quoteChar) {
            inQuote = false;
            quoteChar = '\0';
            pos++;
            continue;
        }

        if (!inQuote) {
            char next = (pos + 1 < cmd.length()) ? cmd[pos + 1] : '\0';
            if (c == '&' && next == '&') {
                return true;
            }

            if (c == '|' && next == '|') {
                return true;
            }

            if (c == ';') {
                return true;
            }

            if (c == '|') {
                return true;
            }

            if (c == '>' || c == '<') {
                return true;
            }

            if (c == '$') {
                return true;
            }

            if (c == '*' || c == '?') {
                return true;
            }

            if (c == '`') {
                return true;
            }

            if (c == '#') {
                return true;
            }
        }

        pos++;
    }
    return false;
}

std::vector<std::string> CommandParser::Parse(const std::string& commandLine)
{
    std::string trimmed = Trim(commandLine);
    if (trimmed.empty()) {
        return {};
    }

    if (NeedShellFallback(trimmed)) {
        SANDBOX_LOGD("CommandParser: %{public}s - falling back to sh -c", trimmed.c_str());
        return { "sh", "-c", trimmed };
    }

    std::vector<std::string> args;
    std::string current;
    char quoteChar = '\0';
    bool inQuote = false;

    for (size_t i = 0; i < trimmed.length(); i++) {
        char c = trimmed[i];

        if (!inQuote && (c == '"' || c == '\'')) {
            inQuote = true;
            quoteChar = c;
            current += c;
        } else if (inQuote && c == quoteChar) {
            inQuote = false;
            current += c;
            if (!current.empty()) {
                args.push_back(current);
                current.clear();
            }
        } else if (!inQuote && (c == ' ' || c == '\t')) {
            if (!current.empty()) {
                args.push_back(current);
                current.clear();
            }
        } else {
            current += c;
        }
    }

    if (!current.empty()) {
        args.push_back(current);
    }

    SANDBOX_LOGD("CommandParser: %{public}s - parsed to %{public}zu args", trimmed.c_str(), args.size());
    return args;
}

}
}