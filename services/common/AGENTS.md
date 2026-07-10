# services/common — Agent Instructions

> **Scope**: `services/common/` — shared utilities (`VariantValue`, `GenericValues`, `SandboxMemoryManager`, `DataSizeReportAdapter`) used by the Sandbox Manager service layer.  
> **Output**: Shared library `sandbox_manager_service_common.so`.  
> **Complementary file**: Read root `AGENTS.md` §4 (Do not) and §14 (Verification) before making changes here — they also apply to this module.  
> **Before editing**: state which utility component (§2) you are changing and whether the change affects the `GenericValues` type contract or `SandboxMemoryManager` feature-gated build.

---

## 1. Module Overview

**Path**: `services/common/`
**Language**: C++17
**Build target**: `sandbox_manager_service_common`
**Output**: `libsandbox_manager_service_common.so`

This module provides foundational data structures and utilities shared across the Sandbox Manager. It has **no business logic** — all classes here are generic building blocks.

### External dependencies

| Dependency | Purpose |
|------------|---------|
| `c_utils:utils` | Common utilities |
| `hilog:libhilog` | Logging |
| `hisysevent:libhisysevent` | System event reporting |
| `ipc:ipc_core` | IPC core |
| `safwk:system_ability_fwk` | SystemAbility framework |
| `samgr:samgr_proxy` | SAMgr proxy |

### Feature flags

| Flag | Effect |
| --- | --- |
| `sandbox_manager_process_resident` | When `false`: builds `SandboxMemoryManager`. When `true`: excludes it. |

---

## 2. Where to look (task → path)

| Task category | Open first | Also read |
| --- | --- | --- |
| Change `VariantValue` type storage / getter behavior | `database/include/variant_value.h` | `database/src/variant_value.cpp` |
| Change `GenericValues` key-value API or default-return semantics | `database/include/generic_values.h` | `database/src/generic_values.cpp`, `variant_value.h` |
| Change memory manager (unload tracking / concurrency) | `utils/sandbox_memory_manager.h` | `BUILD.gn` (check whether feature-gated) |
| Change data-size reporting (HiSysEvent) | `utils/data_size_report_adapter.h` | Root `AGENTS.md` §3.3 (domain terms for `hisysevent`) |
| Change build config (deps, sources, feature flags) | `BUILD.gn` | Root `AGENTS.md` §10 (Feature Flags), `../../../sandbox_manager.gni` |
| Use one of these utilities in downstream code | This file §3.3 (vocabulary) + §5 (pitfalls) | `services/sandbox_manager/AGENTS.md` for usage context |

---

## 3. Knowledge Routing

### 3.1 Task-based routing

- **Changing `VariantValue` type system** (`GetType()`, `GetInt()`, `GetInt64()`, `GetString()`): Read all call sites using each getter — some downstream code relies on the `DEFAULT_VALUE` (-1) / empty-string fallback behavior. Changing return semantics would silently shift behavior in `PolicyInfoManager` and RDB layers.
- **Adding new data types to `VariantValue`**: Also update `GenericValues::Get*` forwarding methods. Update `VariantValue::GetType()` to include the new `ValueType` enum.
- **Changing `GenericValues`** (`Put`, `Get`, `GetInt`, `GetString`, `Exists`, `Delete`, `IsEmpty`, `Size`, `Clear`): Verify that `GetInt("missing_key") → -1` semantics are preserved or that all callers are updated.
- **Changing `SandboxMemoryManager`**: Check whether the change compiles with both `sandbox_manager_process_resident=true` and `false`. The class is excluded from build when resident.
- **Changing `DataSizeReportAdapter` reporting interval or format**: Verify HiSysEvent schema (`USER_DATA_SIZE` event in `FILEMANAGEMENT` domain). Check that `ONE_DAY` interval change doesn't cause excessive reporting.

### 3.2 Path-based routing

| Path | Read this |
| --- | --- |
| `database/` | This file §5.1 (pitfalls for default-value confusion) |
| `utils/` | Root `AGENTS.md` §10 (feature flag `sandbox_manager_process_resident`), this file §4.1 (do not assume unconditional availability) |

### 3.3 Vocabulary-based routing

| Term | Meaning | Load this |
| --- | --- | --- |
| `VariantValue` | Variant wrapper: stores `int32_t`, `int64_t`, or `std::string` | `database/include/variant_value.h` |
| `ValueType` | Enum: `TYPE_INT`, `TYPE_INT64`, `TYPE_STRING`, `TYPE_NONE` | `variant_value.h` |
| `GenericValues` | `std::map<std::string, VariantValue>` — RDB key-value container | `database/include/generic_values.h` |
| `DEFAULT_VALUE` | Sentinel `-1` returned by `GetInt()`/`GetInt64()` on type mismatch or missing key | `variant_value.h` |
| `SandboxMemoryManager` | Tracks concurrent function calls; controls service unload | `utils/sandbox_memory_manager.h` |
| `MAX_RUNNING_NUM` | Threshold `256` — warning logged when exceeded | `sandbox_memory_manager.h` |
| `DataSizeReportAdapter` | Reports user-data directory size to HiSysEvent | `utils/data_size_report_adapter.h` |
| `REPORT_USER_DATA_SIZE` | HiSysEvent handler ID | `data_size_report_adapter.h` |

---

## 4. Do not / Ask before

### 4.1 Do not (must have upgrade confirmation)

- Do **not** change `VariantValue::GetInt()` or `GetInt64()` default return value (`VariantValue::DEFAULT_VALUE = -1`) — downstream code in `PolicyInfoManager` and RDB layers depends on this sentinel for condition checks. If you must change it, audit every call site.
- Do **not** remove `VariantValue::GetType()` dispatch or change the `ValueType` enum values — serialized data in RDB may carry these types.
- Do **not** hardcode a dependency on `SandboxMemoryManager` — it is conditionally compiled (excluded when `sandbox_manager_process_resident=true`). Always guard with `#ifndef SANDBOX_MANAGER_PROCESS_RESIDENT` or equivalent build-config check.
- Do **not** change `DataSizeReportAdapter::ONE_DAY` (86400s) without maintainer confirmation — existing dashboards and alerts depend on the 24-hour reporting cadence.
- Do **not** add new external dependencies to `BUILD.gn` without verifying they are already in `bundle.json#deps.components` at the root.

### 4.2 Ask before (escalate to maintainer)

- Changing `VariantValue` to a non-`std::variant` implementation — affects ABI of `libsandbox_manager_service_common.so`.
- Adding new public methods to `GenericValues` that change its implicit contract with RDB operations.
- Changing `SandboxMemoryManager` locking strategy from recursive mutex — `PolicyInfoManager` may call into it recursively.
- Adding new directories/files to `services/common/` — they become part of the shared library boundary.
- Changing `DataSizeReportAdapter` to report synchronously — it intentionally uses a separate thread to avoid blocking service startup.

---

## 5. Common Pitfalls (operational)

### Pitfall 1: `GenericValues.GetInt()` silently returns -1

`GetInt("key")` returns `VariantValue::DEFAULT_VALUE` (-1) when the key is missing OR the value is not an int. This makes -1 indistinguishable from "not found".

```cpp
// Wrong — cannot distinguish missing key from valid -1
int32_t result = values.GetInt("my_key");

// Correct — check type explicitly
VariantValue v = values.Get("my_key");
if (v.GetType() == ValueType::TYPE_INT) {
    int32_t result = v.GetInt();
} else {
    // Handle missing or type mismatch
}
```

### Pitfall 2: `SandboxMemoryManager` may not be linked

When `sandbox_manager_process_resident=true`, `sandbox_memory_manager.cpp` is excluded from the build. Any code that unconditionally calls `SandboxMemoryManager::GetInstance()` will fail to link.

```cpp
// Wrong — will not link on resident builds
SandboxMemoryManager::GetInstance().AddFunctionRuningNum();

// Correct — guard with feature flag
#ifndef SANDBOX_MANAGER_PROCESS_RESIDENT
    SandboxMemoryManager::GetInstance().AddFunctionRuningNum();
#endif
```

### Pitfall 3: `VariantValue` type mismatch returns default silently

Calling `GetInt()` on a `VariantValue` holding a string returns `DEFAULT_VALUE` (-1) instead of asserting or erroring. Same for `GetString()` on an int — returns `""`.

```cpp
VariantValue v("hello");    // TYPE_STRING
int32_t result = v.GetInt();  // Returns -1 silently — bug waiting to happen!
```

### Pitfall 4: `GenericValues::Put` only inserts, never updates

`GenericValues::Put(key, value)` **inserts a new key** if the key does not exist, but **does not modify** an existing key's value. To update a value, you must `Delete()` the key first, then `Put()` the new value.

```cpp
// Wrong — Put after Put has no effect on the existing key
values.Put("my_key", 1);
values.Put("my_key", 2);  // "my_key" is still 1!

// Correct — Delete first, then Put
values.Delete("my_key");
values.Put("my_key", 2);  // "my_key" is now 2
```

---

## 6. Verification Loop

### 6.1 Minimum checks (every change)

```bash
# Build the common library (verify compilation of all feature-flag states)
hb build -T sandbox_manager --product-name {product_name}
```

### 6.2 Feature-flag-aware verification

Since `SandboxMemoryManager` is conditionally compiled, build with **both** flag states:

```bash
# Verify with process_resident=true
hb build -T sandbox_manager --product-name rk3568

# Verify with process_resident=false (e.g. phone product)
hb build -T sandbox_manager --product-name phone
```

(If a specific product is unavailable for your environment, document which flag state could not be tested — see §6.4.)

### 6.3 Task-specific checks

| Change | Extra validation |
| --- | --- |
| Changed `VariantValue` type system | Run all `GenericValues` unit tests and RDB tests (`sandbox_manager_rdb_test.cpp`) to catch downstream breakage in default-value semantics |
| Changed `GenericValues` API | Audit every `GenericValues::GetInt` / `GetInt64` / `GetString` call site in the entire repo for changed semantics |
| Changed `SandboxMemoryManager` | Build with both flag states; verify `IsAllowedUnloadService()` returns `true` only when `callFuncRunningNum_ == 0` |
| Changed `DataSizeReportAdapter` | Verify HiSysEvent schema compatibility; check that the reporting interval still matches expectations |

### 6.4 Done definition

- [ ] Build passes (common library + dependent targets)
- [ ] Both `sandbox_manager_process_resident=true` and `false` build states verified (or documented as untested with reason)
- [ ] If `VariantValue`/`GenericValues` semantics changed: all downstream call sites audited and updated
- [ ] Final response documents which flag states were tested and any skipped checks with justification

### 6.5 Fallback

If you cannot build both flag states, state in your response:
1. Which flag state was not tested and why.
2. The minimum `hb build -T` command a maintainer would run.
3. A specific note about whether `SandboxMemoryManager` changes were involved (it is the most common build-failure vector here).

---

## 7. Version History

| Version | Date | Changes | Maintainer |
| --- | --- | --- | --- |
| v2.0 | 2026-07-10 | Rewrote from README to agent instruction format: added Where to look, Do not/Ask before, Knowledge routing, feature-flag-aware Verification loop | AI Assistant |
| v1.0 | 2026-02-11 | Initial documentation | AI Assistant |
