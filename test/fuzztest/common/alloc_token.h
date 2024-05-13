/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef ALLOC_TOKEN_H
#define ALLOC_TOKEN_H
#include <cstddef>
#include <cstdint>

namespace OHOS {
bool AllocTokenWithFuzz(const uint8_t *data, size_t size, bool(*func)(const uint8_t *, size_t));
void NativeTokenGet();
void AllocToken();
void DeleteToken();
} // OHOS
#endif // ALLOC_TOKEN_H