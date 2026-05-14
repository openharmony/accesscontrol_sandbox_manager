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

#ifndef GETSHAREDDIRECTORYINFO_FUZZER_H
#define GETSHAREDDIRECTORYINFO_FUZZER_H

#include <cstdint>
#include <vector>
#include <string>

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
    bool GetSharedDirectoryInfoStubFuzzTest(const uint8_t *data, size_t size);
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS

#endif // GETSHAREDDIRECTORYINFO_FUZZER_H
