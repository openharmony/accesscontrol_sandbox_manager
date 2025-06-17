/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "media_library_extend_manager.h"
namespace OHOS {
namespace Media {
MediaLibraryExtendManager *MediaLibraryExtendManager::GetMediaLibraryExtendManager()
{
    static MediaLibraryExtendManager mediaLibMgr;
    return &mediaLibMgr;
}

void MediaLibraryExtendManager::InitMediaLibraryExtendManager()
{
    return;
}

constexpr const char* MEDIA_PATH_1 = "/data/storage/el2/media/Photo/1/1/1.jpg";
constexpr const char* MEDIA_PATH_2 = "/data/storage/el2/media/Photo/2/2/2.jpg";
// For coverage, when input path 3 , will return no policy
constexpr const char* MEDIA_PATH_3 = "/data/storage/el2/media/Photo/3/3/3.jpg";
// For coverage, when input path 4, will return failed, and no need to define path 4 here

/* for mock
 * path 1 or 2, will return 0 and result = true;
 * path 3, will return 0, but result = false;
 * path 4, will return -1;
 */
int32_t MediaLibraryExtendManager::CheckPhotoUriPermission(uint32_t tokenId,
    const std::vector<std::string> &urisSource, std::vector<bool> &result, const std::vector<uint32_t> &flags)
{
    for (size_t i = 0; i < urisSource.size(); ++i) {
        const std::string &uri = urisSource[i];
        if ((uri == MEDIA_PATH_1) || ((uri == MEDIA_PATH_2))) {
            result[i] = true;
        } else if (uri == MEDIA_PATH_3) {
            result[i] = false;
        } else {
            return -1;
        }
    }
    return 0;
}

/* for mock
 * path 1 or 2, will return 0 and result = true;
 * path 3, will return 0, but result = false;
 * path 4, will return -1;
 */
int32_t MediaLibraryExtendManager::GetPhotoUrisPermission(uint32_t targetTokenld, const std::vector<std::string> &uris,
    const std::vector<PhotoPermissionType> &photoPermissionTypes, std::vector<bool> &result)
{
    for (size_t i = 0; i < uris.size(); ++i) {
        const std::string &uri = uris[i];
        if ((uri == MEDIA_PATH_1) || ((uri == MEDIA_PATH_2))) {
            result[i] = true;
        } else if (uri == MEDIA_PATH_3) {
            result[i] = false;
        } else {
            return -1;
        }
    }
    return 0;
}

/* for mock
 * only mock, the URI format is not reused
 */
int32_t MediaLibraryExtendManager::GetUrisFromFusePaths(const std::vector<std::string> paths,
    std::vector<std::string> &uris)
{
    for (const auto& path : paths) {
        uris.push_back(path);
    }
    return 0;
}

int32_t MediaLibraryExtendManager::GrantPhotoUriPermission(uint32_t srcTokenId, uint32_t targetTokenId,
    const std::vector<std::string> &uris, const std::vector<PhotoPermissionType> &photoPermissionTypes,
    HideSensitiveType hideSensitiveTpye)
{
    return 0;
}

int32_t MediaLibraryExtendManager::CancelPhotoUriPermission(uint32_t srcTokenId, uint32_t targetTokenId,
    const std::vector<std::string> &uris, const bool persistFlag, const std::vector<OperationMode> &operationModes)
{
    return 0;
}
}
}