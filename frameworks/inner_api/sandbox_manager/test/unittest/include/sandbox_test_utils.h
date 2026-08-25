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

#ifndef SANDBOX_TEST_UTILS_H
#define SANDBOX_TEST_UTILS_H

#include "sandbox_test_common.h"
#include <cstdint>
#include <string>
#include <sys/ioctl.h>
#include <vector>

struct dec_token_num_arg {
    uint64_t tokenid;
    int32_t num;
    int32_t denyNum;
    int32_t reserved[2];
};

#define HM_DEC_IOCTL_BASE 's'
#define HM_GET_TOKEN_NUM_ID 14
#define GET_TOKEN_NUM_CMD _IOWR(HM_DEC_IOCTL_BASE, HM_GET_TOKEN_NUM_ID, struct dec_token_num_arg)

bool IsDenyPolicyForPath(const char *targetPath);
bool IsDenyPolicyFileExists();
int GetTokenNum(uint64_t tokenid, int32_t &num, int32_t &denyNum);
int CleanPolicyByPathByUser(int32_t userId, const std::vector<std::string> &filePathList);

#endif // SANDBOX_TEST_UTILS_H
