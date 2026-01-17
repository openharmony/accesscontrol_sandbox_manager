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

#include <cstdint>
#include <stack>
#include <string>
#include <unordered_map>
#include <vector>
#include "policy_trie.h"
#include "sandbox_manager_dfx_helper.h"
 
static const int DENIED_PATHS_DEEP = 4;
const std::unordered_map<std::string, int> PolicyTrie::DENIED_PATHS = {
    {"/storage/Users/currentUser/appdata", DENIED_PATHS_DEEP}
};

void PolicyTrie::Clear()
{
    PolicyTrie *root = this;
    std::stack<PolicyTrie *> s;
    for (auto child : root->children_) {
        s.push(child.second);
    }
    while (!s.empty()) {
        PolicyTrie *node = s.top();
        s.pop();
        for (auto child : node->children_) {
            s.push(child.second);
        }
        delete node;
    }
}

std::vector<std::string> PolicyTrie::SplitPath(const std::string &path)
{
    std::vector<std::string> segments;
    size_t start = 0;
    for (size_t i = 0; i < path.size(); i++) {
        if (path[i] == '/') {
            if (i > start) {
                segments.push_back(path.substr(start, i - start));
            }
            start = i + 1;
        }
    }
    if (start < path.size()) {
        segments.push_back(path.substr(start));
    }
    return segments;
}

void PolicyTrie::InsertPath(const std::string &path, uint64_t mode)
{
    PolicyTrie *root = this;
    std::vector<std::string> pathSegments = SplitPath(path);
    PolicyTrie *curNode = root;
    for (const std::string &segment : pathSegments) {
        if (!curNode->children_.count(segment)) {
            curNode->children_[segment] = new PolicyTrie();
        }
        curNode = curNode->children_[segment];
    }
    curNode->isEndOfPath_ = true;
    curNode->mode_ |= mode;
}

bool PolicyTrie::IsPolicyMatch(uint64_t referMode, uint64_t searchMode)
{
    searchMode = searchMode & MODE_FILTER;
	referMode = referMode & MODE_FILTER;
	if ((referMode & searchMode) == searchMode) {
		return true;
	}
	return false;
}

bool PolicyTrie::CheckPath(const std::string &path, uint64_t mode)
{
    PolicyTrie *root = this;
    std::vector<std::string> pathSegments = SplitPath(path);
    PolicyTrie *curNode = root;

    int needLevel = 0;
    for (auto &[denyPath, level] : DENIED_PATHS) {
        if (path.compare(0, denyPath.length(), denyPath) == 0 &&
            (path.length() == denyPath.length() || path[denyPath.length()] == '/')) {
            needLevel = level;
        }
    }

    int32_t curLevel = 0;
    for (const std::string &segment : pathSegments) {
        if (curNode == nullptr || curNode->children_.count(segment) == 0) {
            break;
        }
        curLevel++;
        if (curLevel >= needLevel && curNode->children_[segment]->isEndOfPath_) {
            return IsPolicyMatch(curNode->children_[segment]->mode_, mode);
        }

        curNode = curNode->children_[segment];
    }

    return false;
}
