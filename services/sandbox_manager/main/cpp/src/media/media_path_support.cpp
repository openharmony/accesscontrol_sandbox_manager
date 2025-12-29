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
#include "media_path_support.h"

#include <algorithm>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include "policy_field_const.h"
#include "policy_info.h"
#include "sandbox_manager_const.h"
#include "sandbox_manager_dfx_helper.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerMedia"
};

static std::mutex g_instanceMutex;
inline static const std::string MEDIA_PATH_1 = "/data/storage/el2/media";
inline static const bool CANCEL_PERSIST_FLAG = true; // true means persist
}

template <typename T>
void SandboxManagerMedia::MediaDfx(std::vector<std::string> &uri, std::vector<T> &mode)
{
    for (size_t i = 0; i < uri.size(); ++i) {
        std::string maskPath = SandboxManagerLog::MaskRealPath(uri[i].c_str());
        SANDBOXMANAGER_LOG_INFO(LABEL, "uris:%{public}s, mode:%{public}d", maskPath.c_str(), mode[i]);
    }
}

SandboxManagerMedia &SandboxManagerMedia::GetInstance()
{
    static SandboxManagerMedia *instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new SandboxManagerMedia();
        }
    }
    return *instance;
}

int32_t SandboxManagerMedia::InitMedia()
{
    std::lock_guard<std::mutex> lock(g_instanceMutex);
    if (media_ == nullptr) {
        media_ = Media::MediaPermissionHelper::GetMediaPermissionHelper();
        if (media_ == nullptr) {
            LOGE_WITH_REPORT(LABEL, "MediaPermissionHelper error");
            return INVALID_PARAMTER;
        }
        media_->InitMediaPermissionHelper();
    }
    return SANDBOX_MANAGER_OK;
}

bool SandboxManagerMedia::IsMediaPolicy(const std::string &path)
{
    std::string mediaPath1 = MEDIA_PATH_1;
    if ((path.size() >= mediaPath1.size()) && (path.substr(0, mediaPath1.size()) == mediaPath1)) {
        return true;
    }

    return false;
}

int32_t SandboxManagerMedia::OperateModeToPhotoPermissionType(std::vector<uint32_t> &mode,
    std::vector<Media::PhotoPermissionType> &out)
{
    for (size_t i = 0; i < mode.size(); ++i) {
        if (mode[i] == OperateMode::READ_MODE) {
            out.emplace_back(Media::PhotoPermissionType::PERSIST_READ_IMAGEVIDEO);
        } else if (mode[i] == OperateMode::WRITE_MODE) {
            out.emplace_back(Media::PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO);
        } else if (mode[i] == OperateMode::WRITE_MODE + OperateMode::READ_MODE) {
            out.emplace_back(Media::PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO);
        } else {
            LOGE_WITH_REPORT(LABEL, "OperateModeToPhotoPermissionType error, err mode = %{public}u", mode[i]);
            return INVALID_PARAMTER;
        }
    }
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerMedia::OperateModeToMediaOperationMode(std::vector<uint32_t> &mode,
    std::vector<Media::OperationMode> &out)
{
    for (size_t i = 0; i < mode.size(); ++i) {
        if (mode[i] == OperateMode::READ_MODE) {
            out.emplace_back(Media::OperationMode::READ_MODE);
        } else if (mode[i] == OperateMode::WRITE_MODE) {
            out.emplace_back(Media::OperationMode::WRITE_MODE);
        } else if (mode[i] == OperateMode::WRITE_MODE + OperateMode::READ_MODE) {
            out.emplace_back(Media::OperationMode::READ_WRITE_MODE);
        } else {
            LOGE_WITH_REPORT(LABEL, "OperateModeToMediaOperationMode error, err mode = %{public}u", mode[i]);
            return INVALID_PARAMTER;
        }
    }
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerMedia::CheckPolicyBeforeGrant(uint32_t tokenId, std::vector<std::string> &mediaPaths,
    std::vector<std::string> &needGrantUris, std::vector<uint32_t> &mode, std::vector<bool> &mediaBool,
    std::vector<Media::PhotoPermissionType> &type)
{
    size_t mediaPolicySize = mediaPaths.size();
    std::vector<std::string> uris;
    uris.reserve(mediaPolicySize);

    SANDBOXMANAGER_LOG_INFO(LABEL, "GetUrisFromFusePaths, mediaPathSize:%{public}zu", mediaPaths.size());
    int32_t ret = media_->GetUrisFromFusePaths(mediaPaths, uris);
    if (ret != SANDBOX_MANAGER_OK) {
        LOGE_WITH_REPORT(LABEL, "GetUrisFromFusePaths error, err code:%{public}d", ret);
        return SANDBOX_MANAGER_MEDIA_CALL_ERR;
    }

    SANDBOXMANAGER_LOG_INFO(LABEL, "CheckUrisPermission, uriSize:%{public}zu, typeSize:%{public}zu",
        uris.size(), mode.size());
    MediaDfx(uris, mode);
    ret = media_->CheckPhotoUriPermission(tokenId, uris, mediaBool, mode);
    if (ret != SANDBOX_MANAGER_OK) {
        LOGE_WITH_REPORT(LABEL, "Checkphotouripermission error, err code:%{public}d", ret);
        return SANDBOX_MANAGER_MEDIA_CALL_ERR;
    }

    std::vector<uint32_t> needGrantMode;
    for (size_t i = 0; i < mediaPolicySize; ++i) {
        if (mediaBool[i] == true) {
            needGrantUris.emplace_back(uris[i]);
            needGrantMode.emplace_back(mode[i]);
        } else {
            std::string maskPath = SandboxManagerLog::MaskRealPath(uris[i].c_str());
            LOGE_WITH_REPORT(LABEL, "Uris:%{public}s, had no policy%{public}u", maskPath.c_str(), mode[i]);
        }
    }
    ret = OperateModeToPhotoPermissionType(needGrantMode, type);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }

    return SANDBOX_MANAGER_OK;
}

static void SetAddResultAndWriteDfx(PolicyOperateInfo &info, std::vector<uint32_t> &results, size_t mediaPolicySize,
    std::vector<bool> &mediaBool, OperateTypeEnum operation)
{
    uint32_t succ = 0;
    uint32_t retType;
    if (operation == OperateTypeEnum::PERSIST_POLICY) {
        retType = SandboxRetType::FORBIDDEN_TO_BE_PERSISTED;
    } else {
        retType = SandboxRetType::POLICY_HAS_NOT_BEEN_PERSISTED;
    }

    for (size_t i = 0; i < mediaPolicySize; ++i) {
        if (mediaBool[i] == true) {
            results[i] = SandboxRetType::OPERATE_SUCCESSFULLY;
            succ++;
        } else {
            results[i] = retType;
        }
    }
    info.domain = OperateDomainEnum::MEDIA;
    info.policyNum = mediaPolicySize;
    info.successNum = succ;
    info.failNum = mediaPolicySize - succ;
    info.invalidNum = 0;
    SandboxManagerDfxHelper::WritePersistPolicyOperateSucc(operation, info);
}

int32_t SandboxManagerMedia::AddMediaPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
    std::vector<size_t> &PolicyIndex, std::vector<uint32_t> &results)
{
    if (media_ == nullptr) {
        if (InitMedia() != SANDBOX_MANAGER_OK) {
            LOGE_WITH_REPORT(LABEL, "InitMedia error");
            return SANDBOX_MANAGER_MEDIA_CALL_ERR;
        }
    }
    SANDBOXMANAGER_LOG_INFO(LABEL, "AddMediaPolicy, tokenId:%{public}u", tokenId);
    size_t mediaPolicyIndexSize = PolicyIndex.size();
    PolicyOperateInfo info(0, 0, 0, 0);
    std::vector<std::string> mediaPaths;
    std::vector<uint32_t> mediaMode;
    mediaPaths.reserve(mediaPolicyIndexSize);
    mediaMode.reserve(mediaPolicyIndexSize);
    for (size_t i = 0; i < mediaPolicyIndexSize; ++i) {
        size_t num = PolicyIndex[i];
        mediaPaths.emplace_back(policy[num].path);
        mediaMode.emplace_back(policy[num].mode);
        SandboxManagerDfxHelper::OperateInfoSetByMode(info, policy[num].mode);
    }

    std::vector<bool> mediaBool;
    std::vector<std::string> needGrantUris;
    mediaBool.reserve(mediaPolicyIndexSize);
    needGrantUris.reserve(mediaPolicyIndexSize);
    std::vector<Media::PhotoPermissionType> type;
    int32_t ret = CheckPolicyBeforeGrant(tokenId, mediaPaths, needGrantUris, mediaMode, mediaBool, type);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }

    if (needGrantUris.size() != 0) {
        uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
        SANDBOXMANAGER_LOG_INFO(LABEL, "Grant, callerId:%{public}u, uriSize:%{public}zu, typeSize:%{public}zu",
            callingTokenId, needGrantUris.size(), type.size());
        MediaDfx(needGrantUris, type);
        ret = media_->GrantPhotoUriPermission(callingTokenId, tokenId, needGrantUris,
            type, Media::HideSensitiveType::ALL_DESENSITIZE);
        if (ret != SANDBOX_MANAGER_OK) {
            LOGE_WITH_REPORT(LABEL, "GrantPhotoUriPermission error, err code = %{public}d", ret);
            return SANDBOX_MANAGER_MEDIA_CALL_ERR;
        }
    }
    SetAddResultAndWriteDfx(info, results, mediaPolicyIndexSize, mediaBool, OperateTypeEnum::PERSIST_POLICY);
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerMedia::CheckPolicyBeforeCancel(uint32_t tokenId, std::vector<std::string> &mediaPaths,
    std::vector<std::string> &needCancelUris, std::vector<uint32_t> &mode, std::vector<bool> &mediaBool,
    std::vector<Media::OperationMode> &operationMode)
{
    size_t mediaPolicySize = mediaPaths.size();
    std::vector<std::string> uris;
    uris.reserve(mediaPolicySize);
    SANDBOXMANAGER_LOG_INFO(LABEL, "GetUrisFromFusePaths, mediaPathSize:%{public}zu", mediaPaths.size());
    int32_t ret = media_->GetUrisFromFusePaths(mediaPaths, uris);
    if (ret != SANDBOX_MANAGER_OK) {
        LOGE_WITH_REPORT(LABEL, "GetUrisFromFusePaths error, err code:%{public}d", ret);
        return SANDBOX_MANAGER_MEDIA_CALL_ERR;
    }

    std::vector<Media::PhotoPermissionType> photoPermissionType;
    photoPermissionType.reserve(mediaPolicySize);
    ret = OperateModeToPhotoPermissionType(mode, photoPermissionType);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }

    SANDBOXMANAGER_LOG_INFO(LABEL, "GetUrisPermission, uriSize:%{public}zu, typeSize:%{public}zu",
        uris.size(), photoPermissionType.size());
    MediaDfx(uris, photoPermissionType);
    ret = media_->GetPhotoUrisPermission(tokenId, uris, photoPermissionType, mediaBool);
    if (ret != SANDBOX_MANAGER_OK) {
        LOGE_WITH_REPORT(LABEL, "GetPhotoUrisPermission error, err code:%{public}d", ret);
        return SANDBOX_MANAGER_MEDIA_CALL_ERR;
    }

    std::vector<uint32_t> needCancelMode;
    for (size_t i = 0; i < mediaPolicySize; ++i) {
        if (mediaBool[i] == true) {
            needCancelUris.emplace_back(uris[i]);
            needCancelMode.emplace_back(mode[i]);
        } else {
            std::string maskPath = SandboxManagerLog::MaskRealPath(uris[i].c_str());
            LOGE_WITH_REPORT(LABEL, "Uris:%{public}s, had no policy%{public}u", maskPath.c_str(), mode[i]);
        }
    }

    ret = OperateModeToMediaOperationMode(needCancelMode, operationMode);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }

    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerMedia::RemoveMediaPolicy(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
    std::vector<uint32_t> &result)
{
    if (media_ == nullptr) {
        if (InitMedia() != SANDBOX_MANAGER_OK) {
            LOGE_WITH_REPORT(LABEL, "InitMedia error");
            return SANDBOX_MANAGER_MEDIA_CALL_ERR;
        }
    }
    SANDBOXMANAGER_LOG_INFO(LABEL, "RemoveMediaPolicy, tokenId:%{public}u", tokenId);
    size_t mediaPolicySize = policy.size();
    PolicyOperateInfo info(0, 0, 0, 0);
    std::vector<std::string> mediaPaths;
    std::vector<std::string> uris;
    std::vector<uint32_t> mediaMode;
    mediaPaths.reserve(mediaPolicySize);
    uris.reserve(mediaPolicySize);
    for (size_t i = 0; i < mediaPolicySize; ++i) {
        mediaPaths.emplace_back(policy[i].path);
        mediaMode.emplace_back(policy[i].mode);
        SandboxManagerDfxHelper::OperateInfoSetByMode(info, policy[i].mode);
    }

    std::vector<bool> mediaBool;
    std::vector<std::string> needCancelUris;
    mediaBool.reserve(mediaPolicySize);
    needCancelUris.reserve(mediaPolicySize);
    std::vector<Media::OperationMode> operationMode;
    int32_t ret = CheckPolicyBeforeCancel(tokenId, mediaPaths, needCancelUris, mediaMode, mediaBool, operationMode);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }

    if (needCancelUris.size() != 0) {
        uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
        SANDBOXMANAGER_LOG_INFO(LABEL, "Cancel, callerId:%{public}u, uriSize:%{public}zu, modeSize:%{public}zu",
            callingTokenId, needCancelUris.size(), operationMode.size());
        MediaDfx(needCancelUris, operationMode);
        ret = media_->CancelPhotoUriPermission(callingTokenId, tokenId, needCancelUris,
            CANCEL_PERSIST_FLAG, operationMode);
        if (ret != SANDBOX_MANAGER_OK) {
            LOGE_WITH_REPORT(LABEL, "RemoveMediaPolicy persist error, err code:%{public}d", ret);
            return SANDBOX_MANAGER_MEDIA_CALL_ERR;
        }
    }

    SetAddResultAndWriteDfx(info, result, mediaPolicySize, mediaBool, OperateTypeEnum::UNPERSIST_POLICY);
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerMedia::GetMediaPermission(uint32_t tokenId, const std::vector<PolicyInfo> &policy,
    std::vector<bool> &results)
{
    if (media_ == nullptr) {
        if (InitMedia() != SANDBOX_MANAGER_OK) {
            LOGE_WITH_REPORT(LABEL, "InitMedia error");
            return SANDBOX_MANAGER_MEDIA_CALL_ERR;
        }
    }
    SANDBOXMANAGER_LOG_INFO(LABEL, "GetMediaPermission, tokenId:%{public}u", tokenId);
    size_t mediaPolicySize = policy.size();
    std::vector<std::string> mediaPaths;
    std::vector<std::string> uris;
    std::vector<uint32_t> mediaMode;
    mediaPaths.reserve(mediaPolicySize);
    uris.reserve(mediaPolicySize);
    mediaMode.reserve(mediaPolicySize);
    for (size_t i = 0; i < mediaPolicySize; ++i) {
        mediaPaths.emplace_back(policy[i].path);
        mediaMode.emplace_back(policy[i].mode);
    }

    SANDBOXMANAGER_LOG_INFO(LABEL, "GetUrisFromFusePaths, mediaPathSize:%{public}zu", mediaPaths.size());
    int32_t ret = media_->GetUrisFromFusePaths(mediaPaths, uris);
    if (ret != SANDBOX_MANAGER_OK) {
        LOGE_WITH_REPORT(LABEL, "GetUrisFromFusePaths error, err code:%{public}d", ret);
        return SANDBOX_MANAGER_MEDIA_CALL_ERR;
    }

    std::vector<Media::PhotoPermissionType> photoPermissionType;
    photoPermissionType.reserve(mediaPolicySize);
    ret = OperateModeToPhotoPermissionType(mediaMode, photoPermissionType);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }

    SANDBOXMANAGER_LOG_INFO(LABEL, "GetUrisPermission, uriSize:%{public}zu, typeSize:%{public}zu",
        uris.size(), photoPermissionType.size());
    MediaDfx(uris, photoPermissionType);
    ret = media_->GetPhotoUrisPermission(tokenId, uris, photoPermissionType, results);
    if (ret != SANDBOX_MANAGER_OK) {
        LOGE_WITH_REPORT(LABEL, "GetPhotoUrisPermission error, err code:%{public}d", ret);
        return SANDBOX_MANAGER_MEDIA_CALL_ERR;
    }
    return SANDBOX_MANAGER_OK;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
