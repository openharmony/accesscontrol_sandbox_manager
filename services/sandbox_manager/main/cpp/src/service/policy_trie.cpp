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

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <stack>
#include <string>
#include <unordered_map>
#include <vector>
#include "policy_trie.h"
#include "sandbox_manager_dfx_helper.h"

namespace {
std::string ToLowerCase(const std::string &str)
{
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return result;
}
std::string BuildPath(const std::string &basePath, const std::string &segment)
{
    return basePath.empty() ? "/" + segment : basePath + "/" + segment;
}
}

static const int DENIED_PATHS_DEEP = 4;
const std::unordered_map<std::string, int> PolicyTrie::DENIED_PATHS = {
    {"/storage/Users/currentUser/appdata", DENIED_PATHS_DEEP}
};

void PolicyTrie::DeleteChildren()
{
    std::stack<PolicyTrie *> s;
    for (auto &[key, child] : children_) {
        s.push(child);
    }
    children_.clear();

    while (!s.empty()) {
        PolicyTrie *node = s.top();
        s.pop();
        for (auto &[key, child] : node->children_) {
            s.push(child);
        }
        node->children_.clear();
        delete node;
    }
}

void PolicyTrie::Clear()
{
    DeleteChildren();
    isEndOfPath_ = false;
    mode_ = 0;
    caseInsensitive_ = false;
}

void PolicyTrie::SetCasePolicy(const std::string &path, bool caseInsensitive)
{
    PolicyTrie *curNode = this;
    if (curNode == nullptr) {
        return;
    }

    std::vector<std::string> pathSegments = SplitPath(path);
    for (const std::string &segment : pathSegments) {
        if (curNode == nullptr) {
            return;
        }
        std::string key = curNode->caseInsensitive_ ? ToLowerCase(segment) : segment;
        if (!curNode->children_.count(key)) {
            curNode->children_[key] = new PolicyTrie();
        }
        curNode = curNode->children_[key];
    }

    if (curNode != nullptr) {
        // Only set caseInsensitive_ for the leaf node
        curNode->caseInsensitive_ = caseInsensitive;
    }
}

void PolicyTrie::SetInsensitive(const std::string &path)
{
    SetCasePolicy(path, true);
}

void PolicyTrie::SetSensitive(const std::string &path)
{
    SetCasePolicy(path, false);
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

void PolicyTrie::InsertPath(const std::string &path, uint64_t mode, bool preserveCase)
{
    PolicyTrie *curNode = this;
    std::vector<std::string> pathSegments = SplitPath(path);

    for (const std::string &segment : pathSegments) {
        std::string key;
        if (preserveCase) {
            key = segment; // Store the original case
            if (curNode->caseInsensitive_) {
                curNode->indexMap_[ToLowerCase(segment)].insert(segment);
            }
        } else {
            // Key case depends on current node's caseInsensitive_ flag
            key = curNode->caseInsensitive_ ? ToLowerCase(segment) : segment;
        }

        if (!curNode->children_.count(key)) {
            curNode->children_[key] = new PolicyTrie();
            curNode->children_[key]->caseInsensitive_ = curNode->caseInsensitive_;
        }
        curNode = curNode->children_[key];
    }
    curNode->isEndOfPath_ = true;
    curNode->mode_ |= mode;
}

void PolicyTrie::InsertPreservingCase(const std::string &path, uint64_t mode)
{
    InsertPath(path, mode, true);
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
    PolicyTrie *curNode = this;
    std::vector<std::string> pathSegments = SplitPath(path);
    int needLevel = 0;
    for (auto &[denyPath, level] : DENIED_PATHS) {
        if (path.compare(0, denyPath.length(), denyPath) == 0 &&
            (path.length() == denyPath.length() || path[denyPath.length()] == '/')) {
            needLevel = level;
        }
    }

    int32_t curLevel = 0;
    for (const std::string &segment : pathSegments) {
        if (curNode == nullptr) {
            break;
        }
        // Key case depends on current node's caseInsensitive_ flag
        std::string key = curNode->caseInsensitive_ ? ToLowerCase(segment) : segment;
        auto it = curNode->children_.find(key);
        if (it == curNode->children_.end()) {
            break;
        }
        PolicyTrie *nextNode = it->second;
        curLevel++;
        if (curLevel >= needLevel && nextNode != nullptr && nextNode->isEndOfPath_) {
            return IsPolicyMatch(nextNode->mode_, mode);
        }

        curNode = nextNode;
    }

    return false;
}

std::vector<std::string> PolicyTrie::FindMatchingPaths(const std::string &path)
{
    std::vector<std::string> results;
    std::vector<std::string> searchSegments = SplitPath(path);

    if (searchSegments.empty()) {
        return results;
    }

    std::vector<SearchState> searchStack;
    searchStack.emplace_back(this, 0, "");

    while (!searchStack.empty()) {
        SearchState current = searchStack.back();
        searchStack.pop_back();

        PolicyTrie* currentNode = current.node;
        size_t segmentIndex = current.currentIndex;
        std::string reconstructedPath = current.currentPath;
        bool iscaseInsensitive = currentNode->caseInsensitive_;

        if (segmentIndex >= searchSegments.size()) {
            if (currentNode->isEndOfPath_) {
                results.push_back(reconstructedPath);
            }
            continue;
        }

        std::string targetSegment = searchSegments[segmentIndex];
        if (!iscaseInsensitive) {
            if (currentNode->children_.find(targetSegment) != currentNode->children_.end()) {
                std::string newPath = BuildPath(reconstructedPath, targetSegment);
                searchStack.emplace_back(currentNode->children_[targetSegment], segmentIndex + 1, newPath);
            }
            continue;
        }

        if (currentNode->indexMap_.find(ToLowerCase(targetSegment)) == currentNode->indexMap_.end()) {
            continue;
        }

        for (const std::string &storedKey: currentNode->indexMap_[ToLowerCase(targetSegment)]) {
            std::string newPath = BuildPath(reconstructedPath, storedKey);
            if (currentNode->children_.find(storedKey) != currentNode->children_.end()) {
                searchStack.emplace_back(currentNode->children_[storedKey], segmentIndex + 1, newPath);
            }
        }
    }

    return results;
}

bool PolicyTrie::IsEmpty() const
{
    // A trie is empty if it has no children and is not an end of path with mode
    return children_.empty() && !isEndOfPath_ && mode_ == 0;
}