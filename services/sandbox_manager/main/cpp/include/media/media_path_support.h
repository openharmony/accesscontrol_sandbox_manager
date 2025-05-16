/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#ifndef MEDIA_PATH_SUPPORT_H
#define MEDIA_PATH_SUPPORT_H

#include <cstdint>
#include <string>
#include <vector>
#include "policy_info.h"
#include "media_library_extend_manager.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class SandboxManagerMedia {
public:
    static SandboxManagerMedia &GetInstance();
    SandboxManagerMedia() = default;
    virtual ~SandboxManagerMedia() = default;
    int32_t InitMedia();
    bool IsMediaPolicy(const std::string &path);
    int32_t OperateModeToPhotoPermissionType(std::vector<uint32_t> &mode, std::vector<Media::PhotoPermissionType> &out);
    int32_t OperateModeToMediaOperationMode(std::vector<uint32_t> &mode, std::vector<Media::OperationMode> &out);
    int32_t CheckPolicyBeforeGrant(uint32_t tokenId, std::vector<std::string> &mediaPaths,
        std::vector<std::string> &needGrantUris, std::vector<uint32_t> &mode, std::vector<bool> &mediaBool,
        std::vector<Media::PhotoPermissionType> &type);
    int32_t AddMediaPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &mediaPolicy,
        std::vector<size_t> &mediaPolicyIndex, std::vector<uint32_t> &mediaResults);
    int32_t RemoveMediaPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &mediaPolicy);
    /**
     * @brief called by StartAccessingPolicy/StopAccessingPolicy/MatchPolicy
     * @param tokenId token id of the object
     * @param mediaPolicy vector of PolicyInfo, see policy_info.h
     * @param mediaResults check result of media policy
     * @return SANDBOX_MANAGER_MEDIA_CALL_ERR / SANDBOX_MANAGER_OK
     */
    int32_t GetMediaPermission(uint32_t tokenId, const std::vector<PolicyInfo> &mediaPolicy,
        std::vector<bool> &mediaResults);
private:
    Media::MediaLibraryExtendManager *media_ = nullptr;
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // MEDIA_PATH_SUPPORT_H