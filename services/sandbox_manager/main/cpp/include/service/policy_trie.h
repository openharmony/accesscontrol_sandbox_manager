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

#ifndef POLICY_TRIE_H
#define POLICY_TRIE_H

#include <cstdint>
#include <stack>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

class PolicyTrie {
public:
    PolicyTrie() {}
    ~PolicyTrie() { DeleteChildren(); }

    void Clear();
    void InsertPath(const std::string &path, uint64_t mode, bool preserveCase = false);
    void InsertPreservingCase(const std::string &path, uint64_t mode);
    bool CheckPath(const std::string &path, uint64_t mode);
    std::vector<std::string> FindMatchingPaths(const std::string &path);
    void SetCasePolicy(const std::string &path, bool caseInsensitive);
    void SetInsensitive(const std::string &path);
    void SetSensitive(const std::string &path);
    bool IsEmpty() const;
private:
    inline static const uint64_t MODE_FILTER = 0b11111;
    std::vector<std::string> SplitPath(const std::string &path);
    bool IsPolicyMatch(uint64_t referMode, uint64_t searchMode);
    void DeleteChildren();
    struct SearchState {
        PolicyTrie* node;
        size_t currentIndex;
        std::string currentPath;

        SearchState(PolicyTrie* n, size_t idx, std::string path)
            : node(n), currentIndex(idx), currentPath(path) {}
    };
    static const std::unordered_map<std::string, int> DENIED_PATHS;
    std::unordered_map<std::string, PolicyTrie *> children_;
    bool isEndOfPath_ = false;
    bool caseInsensitive_ = false;
    std::unordered_map<std::string, std::unordered_set<std::string>> indexMap_;
    uint64_t mode_ = 0;
};

#endif