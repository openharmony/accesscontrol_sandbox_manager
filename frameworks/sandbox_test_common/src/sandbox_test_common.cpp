/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "sandbox_test_common.h"
#include <sstream>
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "token_setproc.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
using namespace OHOS::Security::AccessToken;

namespace {
    static uint64_t g_shellTokenID = IPCSkeleton::GetSelfTokenID();
}

static uint64_t GetTokenId(const AtmToolsParamInfo &info)
{
    std::string dumpInfo;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    size_t pos = dumpInfo.find("\"tokenID\": ");
    if (pos == std::string::npos) {
        return 0;
    }
    pos += std::string("\"tokenID\": ").length();
    std::string numStr;
    while (pos < dumpInfo.length() && std::isdigit(dumpInfo[pos])) {
        numStr += dumpInfo[pos];
        ++pos;
    }

    std::istringstream iss(numStr);
    uint64_t tokenID;
    iss >> tokenID;
    return tokenID;
}

uint64_t GetTokenIdFromProcess(const std::string &process)
{
    auto tokenId = IPCSkeleton::GetSelfTokenID();
    SetSelfTokenID(g_shellTokenID); // only shell can dump tokenid

    AtmToolsParamInfo info;
    info.processName = process;
    auto res = GetTokenId(info);

    SetSelfTokenID(tokenId);
    return res;
}

bool MockTokenId(const std::string &process)
{
    auto mockTokenId = GetTokenIdFromProcess(process);
    if (mockTokenId == 0) {
        return false;
    }
    if (SetSelfTokenID(mockTokenId) != 0) {
        return false;
    }
    return IPCSkeleton::GetSelfTokenID() != 0;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
