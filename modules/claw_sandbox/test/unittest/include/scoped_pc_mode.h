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

#ifndef CLAW_SANDBOX_SCOPED_PC_MODE_H
#define CLAW_SANDBOX_SCOPED_PC_MODE_H

#include <string>
#include "parameters.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {
/*
 * The shell sandbox type is gated at runtime on persist.sceneboard.ispcmode. A test
 * that drives a shell config through ParseConfig owns that parameter for its
 * duration and puts it back afterwards, so it neither depends on nor disturbs the
 * mode the device happens to be booted in.
 *
 * A parameter that was unset is restored to "false" rather than removed - the
 * parameter system has no delete, and false is what an unset parameter already
 * means to the gate (it fails closed).
 */
class ScopedPcMode {
public:
    explicit ScopedPcMode(const char *value) : saved_(OHOS::system::GetParameter(PC_MODE_PARAM_KEY, ""))
    {
        if (saved_.empty()) {
            saved_ = "false";
        }
        OHOS::system::SetParameter(PC_MODE_PARAM_KEY, value);
    }
    ~ScopedPcMode()
    {
        OHOS::system::SetParameter(PC_MODE_PARAM_KEY, saved_);
    }

    ScopedPcMode(const ScopedPcMode &) = delete;
    ScopedPcMode &operator=(const ScopedPcMode &) = delete;

private:
    static constexpr const char *PC_MODE_PARAM_KEY = "persist.sceneboard.ispcmode";
    std::string saved_;
};
} // SANDBOX
} // AccessControl
} // OHOS
#endif // CLAW_SANDBOX_SCOPED_PC_MODE_H
