# Sandbox Manager — Services Layer Agent Instructions

> **Scope**: `services/sandbox_manager/` — core `SystemAbility` implementation, policy business logic, RDB persistence, MAC adapter, media/share/sensitive event handling.  
> **Complementary file**: Parent `AGENTS.md` at repository root covers SDK ABI constraints, IPC serialization rules, and cross-layer verification; read it first when changing anything below.  
> **Before editing**: state which component (§2) you are changing, whether it touches RDB schema, MAC ioctl, or permission logic, and which Do-not rules (§4) apply.

---

## 1. Module Overview

**Path**: `services/sandbox_manager/`
**Layer**: Service Layer (core SystemAbility)
**Language**: C++17
**Build target**: `sandbox_manager`

This directory hosts the main Sandbox Manager `SystemAbility`. It:
- Receives IPC requests via `SandboxManagerStub`.
- Validates permissions via `SandboxManagerService::CheckPermission()`.
- Dispatches policy operations (persist, set, activate, query) to `PolicyInfoManager`.
- Persists policies to RDB (`policy_table`, `shared_file_info_table`).
- Interfaces with the kernel MAC layer via ioctl.
- Subscribes to install/uninstall HiSysEvents for policy migration.

---

## 2. Where to look (task → path)

| Task category | Open first | Also read |
| --- | --- | --- |
| Change SA lifecycle / IPC dispatch / permission check | `include/service/sandbox_manager_service.h` | Root `AGENTS.md` §4 (Do not bypass `CheckPermission`) |
| Change policy core logic (validate/filter/match/cleanup) | `include/service/policy_info_manager.h` | `include/service/policy_trie.h`, `include/database/sandbox_manager_rdb.h` |
| Change RDB schema / field constants / open callback | `include/database/policy_field_const.h`, `include/database/sandbox_manager_rdb_open_callback.h` | Root `AGENTS.md` §4 Do not (no DROP TABLE) |
| Change RDB CRUD or batching behavior | `include/database/sandbox_manager_rdb.h`, `include/database/sandbox_manager_rdb_utils.h` | Root `AGENTS.md` §3.1 (batch limits) |
| Change MAC adapter (ioctl, params, support detection) | `include/mac/mac_adapter.h` | Root `AGENTS.md` §3.3 (MacParams, IsMacSupport) |
| Change media path detection / permission conversion | `include/media/media_path_support.h` | `include/share/share_files.h` |
| Change shared file JSON config | `include/share/share_files.h` | `bundle.json` for dependency review |
| Change HiSysEvent subscription (install/uninstall events) | `include/sensitive/sandbox_manager_event_subscriber.h` | `include/preserve/persistent_preserve.h` |
| Change persistent preserve (uninstall save / reinstall restore) | `include/preserve/persistent_preserve.h` | Root `AGENTS.md` §7.4 (Preserve API reference) |
| Change service constants / limits / permission strings | `include/service/sandbox_manager_const.h` | Root `AGENTS.md` §9 (limits), §4 (do not change limits without ask) |
| Write or extend unit tests / mocks | `test/unittest/`, `test/mock/` | Root `AGENTS.md` §14.2 (task-specific test categories) |

---

## 3. Knowledge Routing

### 3.1 Task-based routing

- **Changing `PolicyInfoManager` validation logic**: Read `include/service/sandbox_manager_const.h` for `MODE_FILTER` and batch constants. Read `include/database/policy_field_const.h` for field names.
- **Changing MAC adapter commands**: Read `include/mac/mac_adapter.h` thoroughly — check `IsMacSupport()` callers, `MacParams` layout, and all ioctl call sites.
- **Changing RDB behavior**: Read `include/database/sandbox_manager_rdb_open_callback.h` `OnUpgrade()` — never drop tables. Read `services/common/AGENTS.md` for `GenericValues` type-safety rules.
- **Adding new permission checks to `CheckPermission()`**: Cross-reference `sandbox_manager_const.h` permission strings AND `bundle.json#requestPermissions` in the root.
- **Changing event subscriber**: Read `include/sensitive/sandbox_manager_event_subscriber.h` to understand the event filter keys before modifying the handler.

### 3.2 Path-based routing

Read the following when opening directories:

| Path | Read this |
| --- | --- |
| `include/service/` | Root `AGENTS.md` §11 (arch diagram), §4 (Do not) |
| `include/database/` | Root `AGENTS.md` §3.1 (persistence routing), this file §4.1 (RDB no-DROP rule) |
| `include/mac/` | Root `AGENTS.md` §3.3 (MacParams, IsMacSupport) |
| `include/media/` | This file §4.1 (media path constraints), §7 API reference for media permission types |
| `include/preserve/` | Root `AGENTS.md` §7.4, this file §6.2 (preserve flow) |

### 3.3 Vocabulary-based routing

| Term | Meaning | Load this |
| --- | --- | --- |
| `PolicyTrie` | Trie tree for path-prefix matching and mode lookup | `include/service/policy_trie.h` |
| `GenericValues` | Key-value container for RDB operations | `services/common/AGENTS.md` |
| `SandboxManagerRdb::DataType` | `PERSIST_POLICY` / `SHARED_FILE_INFO` enum | `include/database/sandbox_manager_rdb.h` |
| `MacParams` | ioctl param struct: `tokenId`, `policyFlag`, `timestamp`, `userId` | `include/mac/mac_adapter.h` |
| `IsMacSupport()` | Runtime probe: is MAC available on this device? | `include/mac/mac_adapter.h` |
| `OnUpgrade()` | RDB schema migration entry — never DROP | `include/database/sandbox_manager_rdb_open_callback.h` |
| `CheckPermission()` | Permission gate in `SandboxManagerService` | Root `AGENTS.md` §4 (do not bypass) |
| `OperateModeToPhotoPermissionType()` | Media path mode -> permission type conversion | `include/media/media_path_support.h` |

---

## 4. Do not / Ask before

### 4.1 Do not (must have upgrade confirmation)

- Do **not** modify `PolicyInfoManager` singleton lifecycle — it uses `DECLARE_DELAYED_SINGLETON` and is managed by `SandboxManagerService`.
- Do **not** call `MacAdapter::SetSandboxPolicy` / `UnSetSandboxPolicy` without first checking `IsMacSupport()`.
- Do **not** add, remove, or reorder fields in `policy_table` schema. Schema changes must go through `SandboxManagerRdbOpenCallback::OnUpgrade` only.
- Do **not** add new database tables without adding corresponding `DataType` enum entries in `SandboxManagerRdb` and updating `PolicyFieldConst`.
- Do **not** modify `policyTableName` or `sharedFileInfoTableName` in `policy_field_const.h` — existing RDB databases reference these names.
- Do **not** modify `HiSysEvent` event key strings in `sandbox_manager_event_subscriber.h` without checking all downstream event consumers.
- Do **not** delete the `MacAdapter` singleton or assume MAC is always present — the adapter may be uninitialized on products without MAC support.
- Do **not** add synchronous long-running operations to IPC handler paths (`SandboxManagerService` stub methods) — they block the Binder thread pool.

### 4.2 Ask before (escalate to maintainer)

- Changing `SandboxManagerRdb::GetInstance()` to a non-singleton pattern or changing its lock strategy (`RWLock`).
- Adding new `HiSysEvent` event types in the subscriber — must align with `FILEMANAGEMENT` domain conventions.
- Changing `PolicyTrie` matching semantics (prefix match depth, mode accumulation) — affects policy query correctness for all callers.
- Replacing `std::variant` in `VariantValue` with a different type-erasure mechanism.
- Adding new media permission types in `media_path_support.h` — must align with the photo-library framework's permission enum.
- Changing `g_shareMap` structure in `share_files.h` from the bundle→user→path hierarchy.
- Moving code between `services/sandbox_manager/` and `services/common/` — each targets a different `.so` boundary.

---

## 5. Key Components (compact reference)

### 5.1 Service component (`include/service/`)

| Class | File | Key role |
| --- | --- | --- |
| `SandboxManagerService` | `sandbox_manager_service.h` | `SystemAbility` + `SandboxManagerStub`, IPC dispatch, `CheckPermission()` |
| `PolicyInfoManager` | `policy_info_manager.h` | Core singleton: validate/filter/match policies, RDB CRUD, MAC dispatch |
| `PolicyTrie` | `policy_trie.h` | Trie for path-prefix matching and mode checking |
| `SandboxManagerConst` | `sandbox_manager_const.h` | Limits (`POLICY_PATH_LIMIT`, batch sizes), 7 permission strings, `MODE_FILTER` |

### 5.2 Database component (`include/database/`)

| Class | File | Key role |
| --- | --- | --- |
| `SandboxManagerRdb` | `sandbox_manager_rdb.h` | RDB wrapper: `Add`/`Remove`/`Modify`/`Find` via `GenericValues` |
| `SandboxManagerRdbOpenCallback` | `sandbox_manager_rdb_open_callback.h` | `OnCreate`/`OnUpgrade` — schema evolution |
| `PolicyFiledConst` | `policy_field_const.h` | `FIELD_*` constants, table names |

### 5.3 MAC adapter (`include/mac/`)

| Class | File | Key role |
| --- | --- | --- |
| `MacAdapter` | `mac_adapter.h` | `SetSandboxPolicy`/`UnSetSandboxPolicy`/`QuerySandboxPolicy` etc. ioctl wrapper |
| `MacParams` | (same) | `{tokenId, policyFlag, timestamp, userId}` |

### 5.4 Media / Share / Sensitive / Preserve

| Class | File | Key role |
| --- | --- | --- |
| `SandboxManagerMedia` | `include/media/media_path_support.h` | Media path detection, permission type conversion |
| `SandboxManagerShare` | `include/share/share_files.h` | Shared file JSON config map |
| `SandboxManagerCommonEventSubscriber` | `include/sensitive/sandbox_manager_event_subscriber.h` | HiSysEvent listener (install/uninstall) |
| `PersistentPreserve` (static) | `include/preserve/persistent_preserve.h` | Save/restore policies across app uninstall/reinstall |

---

## 6. Data Flow Examples

### Persist policy

```
Client → IPC: PersistPolicy(policies)
SandboxManagerService → CheckPermission(SET_SANDBOX_POLICY)
PolicyInfoManager::AddPolicy()
  → FilterValidPolicyInBatch() — validate
  → CheckPathIsBlocked() — blocklist check
  → CheckPolicyValidity() — path/mode check
  → ExactFind() — duplicate check
SandboxManagerRdb::Add() → INSERT INTO policy_table
```

### Activate policy

```
Client → IPC: StartAccessingPolicy(policies)
PolicyInfoManager::StartAccessingPolicy()
  → RDB query for persistent policies
  → MatchPolicy() — find matching
  MacAdapter::SetSandboxPolicy() → ioctl to kernel
```

### Set temporary policy

```
Client → IPC: SetPolicy(policies)
PolicyInfoManager::SetPolicy()
  → FilterValidPolicyInBatch() — validate
  MacAdapter::SetSandboxPolicy(policyFlag=0) → ioctl
  (NOT stored in RDB; lost on restart)
```

---

## 7. Verification Loop

### 7.1 Minimum checks (every change)

```bash
# Build service + tests
hb build -T sandbox_manager --product-name {product_name}
hb build -T sandbox_manager_build_module_test --product-name {product_name}

# Build fuzz
hb build -T sandbox_manager_build_fuzz_test --product-name {product_name}
```

### 7.2 Task-specific checks

| Changed component | Extra validation |
| --- | --- |
| `include/service/policy_info_manager.h` | Run `policy_info_manager_test.cpp` — verify validate/filter/match flows with edge-case inputs (empty paths, null modes, unicode paths, max-batch-size lists) |
| `include/database/` | Run `sandbox_manager_rdb_test.cpp` — verify `OnUpgrade` migration path with old schema version |
| `include/mac/mac_adapter.h` | Run module UT; verify `IsMacSupport()` paths with both `true` and `false`; test ioctl error handling |
| `include/media/media_path_support.h` | Run `media_path_mock_test.cpp` with various path formats |
| `include/preserve/persistent_preserve.h` | Simulate uninstall→reinstall; verify `SaveBundlePersistentPolicies` + `RestoreBundlePersistentPolicies` produce matching tokenId mapping |
| `include/service/sandbox_manager_const.h` (limits) | Verify downstream consumers handle changed limits — test with boundary values |
| `test/` additions | All new test cases must build and pass with `sandbox_manager_build_module_test` |

### 7.3 Done definition

- [ ] Build passes (`sandbox_manager` + `sandbox_manager_build_module_test`)
- [ ] All relevant service-layer unit tests PASS
- [ ] If RDB schema changed: migration SQL documented in PR, `OnUpgrade` covers old→new schema
- [ ] If MAC adapter changed: `IsMacSupport()` both branches verified; ioctl error codes documented
- [ ] If permission logic changed: `CheckPermission()` path verified (not bypassed); `bundle.json` synced if new permission added

### 7.4 Fallback

If validation cannot be run, state in the final response:
1. Which checks were skipped and why.
2. The exact `hb build -T` command a maintainer would use.

---

## 8. Common Pitfalls

### Pitfall 1: Forgetting to activate after persist

`PersistPolicy` → RDB only. Must call `StartAccessingPolicy` for MAC activation.

### Pitfall 2: MAC not available

`MacAdapter::IsMacSupport()` may return false. All MAC call paths in `PolicyInfoManager` check this — if you add a new MAC call, add the check too.

### Pitfall 3: Thread safety — `PolicyInfoManager` singleton

`PolicyInfoManager::GetInstance()` is accessed from multiple Binder threads. Internal state (`PolicyTrie`, batch counters) must remain thread-safe.

### Pitfall 4: `OnUpgrade` version ordering

`RdbStoreCallback::OnUpgrade(oldVersion, newVersion)` may be called with any oldVersion — write defensive migration that handles gaps (e.g., 1→3, not just 2→3).

---

## 9. Version History

| Version | Date | Changes | Maintainer |
| --- | --- | --- | --- |
| v2.0 | 2026-07-10 | Rewrote from README to agent instruction format: added Where to look, Do not/Ask before, Knowledge routing, Verification loop | AI Assistant |
| v1.0 | 2026-02-11 | Initial documentation | AI Assistant |
