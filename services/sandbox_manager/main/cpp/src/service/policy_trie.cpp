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
    int start = 0;
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
    bool modeMatch;
    searchMode = searchMode & MODE_FILTER;
    referMode = referMode & MODE_FILTER;
    // refer RW, search R or W shoule return true
    if (referMode == searchMode) {
        modeMatch = true;
    } else if (referMode > searchMode) {
        modeMatch = ((referMode & searchMode) != 0);
    } else {
        modeMatch = false;
    }
    return modeMatch;
}

bool PolicyTrie::CheckPath(const std::string &path, uint64_t mode)
{
    PolicyTrie *root = this;
    std::vector<std::string> pathSegments = SplitPath(path);
    PolicyTrie *curNode = root;

    for (const std::string &segment : pathSegments) {
        if (curNode == nullptr || curNode->children_.count(segment) == 0) {
            return false;
        }
        if (curNode->children_[segment]->isEndOfPath_) {
            return IsPolicyMatch(curNode->children_[segment]->mode_, mode);
        } else {
            curNode = curNode->children_[segment];
        }
    }
    return false;
}