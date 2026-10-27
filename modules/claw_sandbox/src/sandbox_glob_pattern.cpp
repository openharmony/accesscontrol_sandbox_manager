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

#include "sandbox_glob_pattern.h"
#include "sandbox_error.h"

namespace OHOS {
namespace AccessControl {
namespace SANDBOX {

/*
 * --- file path patterns ---
 *
 * One pattern turns into an fd path plus a SUFFIX string. Current grammar:
 *   1. The pattern is absolute.
 *   2. It has exactly one '**', as a whole segment: '/' before it, and '/'
 *      or the end of the pattern after it.
 *   3. It does not end with '/'. A trailing slash asks for directories only,
 *      which a SUFFIX match cannot express.
 *   4. The tail after '**' is empty (the bound directory and its subtree), a
 *      literal path, or a star-led final component: '*' followed by a non-empty
 *      literal without '/' or '*'. For the star-led form both the star and the
 *      separating slash are dropped from the suffix; a literal path keeps its
 *      slash and therefore still matches a whole component.
 *   5. No other '*', and no '?', '[', ']', '{', '}', or '\'.
 *   6. No empty, '.' or '..' component in the fd path or a literal tail path.
 *      The star-led fragment is a suffix, not a path, so it is not split.
 *
 * Known gap: the kernel matches a plain string tail, not glob's final component,
 * so hidden entries match too - a star-led "ll.jpg" tail also matches
 * ".xll.jpg", and the '**' walk descends into hidden directories.
 *
 * The action-conflict check treats the bound fd's inode plus the suffix as the
 * rule's identity, so one pattern under two actions is refused. Merely
 * overlapping patterns still are not a conflict - that remains the kernel's call.
 */

// Any '*' at all marks an entry as a claimed pattern; a lone one is refused, not literal.
bool IsWildcardPattern(const std::string &path)
{
    return path.find('*') != std::string::npos;
}

// Length of the '**' token itself.
static constexpr size_t GLOB_STAR_LEN = 2;

// Length of the prefix that opens a star-led tail: the '/' separating it from '**'
// plus the leading '*'. The literal starts right after it.
static constexpr size_t STAR_TAIL_LEAD_LEN = 2;

// Spec 1: the pattern is an absolute path.
static int CheckPatternAbsolute(const std::string &pattern, std::string &why)
{
    if (pattern.empty() || pattern.front() != '/') {
        why = "must be an absolute path";
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    return SANDBOX_SUCCESS;
}

// Spec 2a: exactly one '**'. On success star is its offset.
static int FindSingleGlobStar(const std::string &pattern, size_t &star, std::string &why)
{
    star = pattern.find("**");
    if (star == std::string::npos) {
        why = "'*' must be part of a '**'";
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    if (pattern.find("**", star + GLOB_STAR_LEN) != std::string::npos) {
        why = "must contain exactly one '**'";
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    return SANDBOX_SUCCESS;
}

// Spec 2b: '**' occupies a whole path segment.
static int CheckGlobStarBoundaries(const std::string &pattern, size_t star, std::string &why)
{
    if (star == 0 || pattern[star - 1] != '/') {
        why = "the '**' must be preceded by '/'";
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    const size_t afterStar = star + GLOB_STAR_LEN;
    if (afterStar < pattern.size() && pattern[afterStar] != '/') {
        why = "the '**' must be followed by '/' or the end of the pattern";
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    return SANDBOX_SUCCESS;
}

// Spec 3: a trailing '/' means directory-only, which the kernel cannot express.
static int CheckNoTrailingSlash(const std::string &pattern, std::string &why)
{
    if (!pattern.empty() && pattern.back() == '/') {
        why = "must not end with '/': the kernel cannot restrict a pattern to directories";
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    return SANDBOX_SUCCESS;
}

// Used by specs 4 and 5b; the definition follows them, under spec 6.
static int CheckNoSpecialComponents(const std::string &path, std::string &why);

// Spec 4: validate the tail after '**' and report whether it is star-led.
// Empty stays empty; a literal tail keeps its leading '/'; the star-led form
// is built without the star and the separating slash.
// A bare '**/*' (empty literal) folds into '**': the kernel cannot exclude the
// '**' directory itself, so the two patterns cannot be told apart.
static int CheckPatternSuffix(const std::string &suffix, bool &starLed, std::string &why)
{
    starLed = false;
    if (suffix.empty()) {
        return SANDBOX_SUCCESS;
    }
    if (suffix.size() >= STAR_TAIL_LEAD_LEN && suffix[STAR_TAIL_LEAD_LEN - 1] == '*') {
        const std::string literal = suffix.substr(STAR_TAIL_LEAD_LEN);
        if (literal.find('/') != std::string::npos) {
            why = "the '*' after '**/' may only match the final path component";
            return SANDBOX_ERR_CONFIG_INVALID;
        }
        if (literal.find('*') != std::string::npos) {
            why = "'*' must be the only wildcard in the final component";
            return SANDBOX_ERR_CONFIG_INVALID;
        }
        starLed = true;
        return SANDBOX_SUCCESS;
    }
    if (suffix.find('*') != std::string::npos) {
        why = "'*' after '**' may only lead the final component ('**/*<literal>')";
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    if (CheckNoSpecialComponents(suffix, why) != SANDBOX_SUCCESS) {
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    return SANDBOX_SUCCESS;
}

// Spec 5a: only '*' is understood; other glob syntax is refused, not literal.
static int CheckNoUnsupportedMetaChars(const std::string &pattern, std::string &why)
{
    const size_t meta = pattern.find_first_of("?[]{}");
    if (meta != std::string::npos) {
        why = std::string("unsupported glob metacharacter '") + pattern[meta] + "'";
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    if (pattern.find('\\') != std::string::npos) {
        why = "escape sequences are not supported";
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    return SANDBOX_SUCCESS;
}

// Spec 5b: the fd path before '**' is literal and canonical.
static int CheckPatternPrefix(const std::string &prefix, std::string &why)
{
    if (prefix.find('*') != std::string::npos) {
        why = "'*' is only allowed as part of the single '**'";
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    if (CheckNoSpecialComponents(prefix, why) != SANDBOX_SUCCESS) {
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    return SANDBOX_SUCCESS;
}

// Spec 6: no empty, '.' or '..' component in a literal path fragment.
static int CheckNoSpecialComponents(const std::string &path, std::string &why)
{
    if (path.find("//") != std::string::npos) {
        why = "must not contain an empty path component";
        return SANDBOX_ERR_CONFIG_INVALID;
    }
    size_t pos = 0;
    while (pos < path.size()) {
        const size_t slash = path.find('/', pos);
        const size_t stop = (slash == std::string::npos) ? path.size() : slash;
        const std::string component = path.substr(pos, stop - pos);
        if (component == "." || component == "..") {
            why = "must not contain a '.' or '..' path component";
            return SANDBOX_ERR_CONFIG_INVALID;
        }
        if (slash == std::string::npos) {
            break;
        }
        pos = slash + 1;
    }
    return SANDBOX_SUCCESS;
}

// Single entry point for the pattern grammar, in spec order. Every check runs
// before out is touched; on success out.prefix is the fd path before '**' and
// out.suffix is the SUFFIX string.
int ParseFilePattern(const std::string &pattern, FilePattern &out, std::string &why)
{
    int ret = CheckPatternAbsolute(pattern, why);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    size_t star = 0;
    ret = FindSingleGlobStar(pattern, star, why);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    ret = CheckGlobStarBoundaries(pattern, star, why);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    ret = CheckNoTrailingSlash(pattern, why);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    const std::string prefix = pattern.substr(0, star);
    const std::string suffix = pattern.substr(star + GLOB_STAR_LEN);
    bool starLed = false;
    ret = CheckPatternSuffix(suffix, starLed, why);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    ret = CheckNoUnsupportedMetaChars(pattern, why);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    ret = CheckPatternPrefix(prefix, why);
    if (ret != SANDBOX_SUCCESS) {
        return ret;
    }
    out.prefix = prefix;
    out.suffix = starLed ? suffix.substr(STAR_TAIL_LEAD_LEN) : suffix;
    return SANDBOX_SUCCESS;
}

} // namespace SANDBOX
} // namespace AccessControl
} // namespace OHOS
