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
#ifndef MEDIA_LIBRARY_EXTEND_MANAGER_H
#define MEDIA_LIBRARY_EXTEND_MANAGER_H

#include <string>

namespace OHOS {
namespace Media {
enum class PhotoPermissionType : int32_t {
    TEMPORARY_READ_IMAGEVIDEO = 0,
    PERSIST_READ_IMAGEVIDEO,
    TEMPORARY_WRITE_IMAGEVIDEO,
    TEMPORARY_READWRITE_IMAGEVIDEO,
    PERSIST_READWRITE_IMAGEVIDEO, // Internal reserved value, not open to the public
    PERSIST_WRITE_IMAGEVIDEO,
    GRANT_PERSIST_READWRITE_IMAGEVIDEO,
};

enum class HideSensitiveType : int32_t {
    ALL_DESENSITIZE = 0,
    GEOGRAPHIC_LOCATION_DESENSITIZE,
    SHOOTING_PARAM_DESENSITIZE,
    NO_DESENSITIZE
};

enum class OperationMode : uint32_t {
    READ_MODE = 0b01,
    WRITE_MODE = 0b10,
    READ_WRITE_MODE = 0b11,
};

class MediaLibraryExtendManager {
public:
    MediaLibraryExtendManager() = default;
    virtual ~MediaLibraryExtendManager() = default;
    static MediaLibraryExtendManager *GetMediaLibraryExtendManager();
    void InitMediaLibraryExtendManager();
    int32_t CheckPhotoUriPermission(uint32_t tokenId,
        const std::vector<std::string> &urisSource, std::vector<bool> &result, const std::vector<uint32_t> &flags);
    int32_t GrantPhotoUriPermission(uint32_t srcTokenId, uint32_t targetTokenId, const std::vector<std::string> &uris,
        const std::vector<PhotoPermissionType> &photoPermissionTypes, HideSensitiveType hideSensitiveTpye);
    int32_t CancelPhotoUriPermission(uint32_t srcTokenId, uint32_t targetTokenId,
        const std::vector<std::string> &uris, const bool persistFlag = false,
        const std::vector<OperationMode> &mode = {OperationMode::READ_WRITE_MODE});
    int32_t GetPhotoUrisPermission(uint32_t targetTokenld, const std::vector<std::string> &uris,
        const std::vector<PhotoPermissionType> &photoPermissionTypes, std::vector<bool> &result);
    int32_t GetUrisFromFusePaths(const std::vector<std::string> paths, std::vector<std::string> &uris);
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_LIBRARY_EXTEND_MANAGER_H