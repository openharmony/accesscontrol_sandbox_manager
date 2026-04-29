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

#ifndef SANDBOX_SANDBOX_MANAGER_H
#define SANDBOX_SANDBOX_MANAGER_H

#include <string>
#include <vector>
#include <map>
#include <sys/types.h>
#include <sys/stat.h>

#include "json/json.h"
#include <sandbox_config.h>

namespace OHOS {
namespace Sandbox {

class SandboxManager {
public:
    SandboxManager();
    ~SandboxManager();

    int LoadConfigFile(const std::string &configPath);
    int LoadConfigJsonStr(const std::string &configJsonStr);
    int LoadAppDataConfig(const std::string &appDataPath);
    int CreateSandboxPath();
    int SetUidGid();
    int SetSelinux();
    int SetSeccomp();
    int SetNamespace();
    int MountSystemPaths();
    int MountAppDataPaths();
    int PivotRoot();
#ifndef SANDBOX_NO_EXECUTE
    int Execute();
#endif
    void SetSandboxPath(const std::string &path) { sandboxPath_ = path; }
    void SetCommand(int argc, char *argv[]);
    int RemountRootSlave();
    int DropCapabilities();
    int SetAccessToken();
    void SetSandboxCreated(bool created) { sandboxCreated_ = created; }

private:
    int ParseConfigJson(const Json::Value &root);
    unsigned long ParseMountFlags(const std::vector<std::string> &vec);
    int ParseCommonConfig(const Json::Value &root);
    std::string ReplaceVariable(std::string str, const std::string &from, const std::string &to);
    int DoBindMount(const std::string &src, const std::string &dest, unsigned long flags);
    int MountSinglePath(const MountEntry &entry);
    int CreateSymbolLink(const std::string &target, const std::string &link);
#ifndef SANDBOX_NO_EXECUTE
    int ExecuteCommand();
#endif
    int CleanupSandbox();
    void CleanupAll();
    void ClearEnv();
    void SetNamespaceCreated(bool created) { namespaceCreated_ = created; }
    void SetMountsCreated(bool created) { mountsCreated_ = created; }
    void SetPivotRootDone(bool done) { pivotRootDone_ = done; }

    SandboxConfig config_;
    std::string sandboxPath_;
    std::string configPath_;
    std::vector<char *> cmdArgs_;

private:
    bool namespaceCreated_ = false;
    bool mountsCreated_ = false;
    bool pivotRootDone_ = false;
    bool sandboxCreated_ = false;
};

}
}

#endif