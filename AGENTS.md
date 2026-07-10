# sandbox_manager — AI Agent Instructions

> **Target audience**: Coding agents (Codex / Claude Code / Copilot / other LLM tools) making changes, reviewing code, or debugging within OpenHarmony `base/accesscontrol/sandbox_manager`.  
> **This file is the top-level guide.** Subdirectory `AGENTS.md` files complement it — see [Where to look](#2-where-to-look-task-to-path).  
> **Before editing, state** the task category (from §2 table), which docs you loaded, and which constraints (§4) are relevant. This ensures maintainers can verify your reasoning.

---

## 1. Project Overview

Sandbox Manager is an OpenHarmony SystemAbility that **persists, validates, and delivers file-sharing rules between application sandboxes to the kernel MAC layer**. It solves cross-app file access caused by sandbox directory isolation. The project is structured in four layers:

| Layer | Path | Responsibility |
| --- | --- | --- |
| **Interfaces (SDK)** | `interfaces/inner_api/sandbox_manager/` | Public C++ API, IPC client (`SandboxManagerKit`) |
| **Frameworks** | `frameworks/sandbox_manager/` `frameworks/inner_api/sandbox_manager/` | Parcel serialization, logging, DFX, SDK impl |
| **Services (SA)** | `services/sandbox_manager/main/cpp/` | `SystemAbility` main service, policy core logic, RDB persistence, MAC adaptation |
| **Common utils** | `services/common/` `services/sandbox_manager/main/cpp/include/service/` | Shared types, memory mgmt, statistics reporting |
| **Aux modules** | `modules/claw_sandbox/` | seccomp config and execution (see [Where to look](#2-where-to-look-task-to-path)) |

**Language**: C++17  ·  **Build**: GN / Ninja  ·  **Subsystem**: `accesscontrol`  ·  **Component**: `sandbox_manager` (published as `@ohos/sandbox_manager`, see `bundle.json`)

---

## 2. Where to look (task → path)

> **Before writing code, classify your task below, open the listed path(s) and any referenced sub-`AGENTS.md`.** Prefer the nearest (subdirectory) file over the top-level one.

| Task category | Open first | Sub-`AGENTS.md` |
| --- | --- | --- |
| Change public SDK API / error codes / public structs | `interfaces/inner_api/sandbox_manager/include/{sandbox_manager_kit.h,sandbox_manager_err_code.h,policy_info.h}` | — |
| Change IPC Stub / Parcel serialization order | `frameworks/sandbox_manager/include/*.h` (esp. `policy_info_vector_parcel.h`, `set_info_parcel.h`, `policy_info_parcel.h`, `*_vec_raw_data.h`) | — |
| Change `SystemAbility` lifecycle / permission check / dispatch | `services/sandbox_manager/main/cpp/include/service/sandbox_manager_service.h` | `services/sandbox_manager/AGENTS.md` |
| Change persistent policy RDB operations / schema / upgrade | `services/sandbox_manager/main/cpp/include/database/*` | `services/sandbox_manager/AGENTS.md` §2 |
| Change MAC kernel dispatch (commands, ioctl, Deny policy) | `services/sandbox_manager/main/cpp/include/mac/mac_adapter.h` | `services/sandbox_manager/AGENTS.md` §3 |
| Change `PolicyInfoManager` business logic (validate, filter, match, cleanup) | `services/sandbox_manager/main/cpp/include/service/policy_info_manager.h` | `services/sandbox_manager/AGENTS.md` §1 |
| Change media-library path handling / shared-file config | `services/sandbox_manager/main/cpp/include/media/*`, `services/sandbox_manager/main/cpp/include/share/*` | — |
| Change `PersistentPreserve` (save on uninstall, restore on reinstall) | `services/sandbox_manager/main/cpp/include/preserve/persistent_preserve.h` | — |
| Change common utilities (`GenericValues` / memory mgmt / DFX reporting) | `services/common/include/**` | `services/common/AGENTS.md` |
| Change seccomp command config / `claw_sandbox` execution | `modules/claw_sandbox/include/` | — |
| Change tests / add fuzz entry | `test/fuzztest/**`, `services/sandbox_manager/test/` | — |

---

## 3. Knowledge Routing

When your task mentions any of the triggers below, **read the referenced document or header** — do not rely on memory.

### 3.1 Task-based routing

- **Public API, error codes, `PolicyInfo` / `OperateMode` / `SandboxRetType` fields**: Read `interfaces/inner_api/sandbox_manager/include/*.h`. Cross-check method names against the IPC Stub at `services/sandbox_manager/main/cpp/include/service/sandbox_manager_service.h`.
- **IPC serialization**: Read `frameworks/sandbox_manager/include/*.h` and the corresponding `services/sandbox_manager/main/cpp/src/**` implementation. Changing serialization order **breaks IPC compatibility** (see §4 Do not).
- **Persistence behavior**: Read `services/sandbox_manager/main/cpp/include/database/{sandbox_manager_rdb.h,sandbox_manager_rdb_open_callback.h,policy_field_const.h}`. Confirm the schema upgrade path (`OnUpgrade`) — never `DROP TABLE`.
- **MAC layer dispatch**: Read `mac/mac_adapter.h` and the `MODE_FILTER` / `NON_PERSIST_POLICY_BATCH_SIZE` constants in `sandbox_manager_const.h`. Do not guess ioctl parameters.
- **Feature Flag / Bundle config**: Read `bundle.json` and `sandbox_manager.gni`. Confirm default values and dependency closure.

### 3.2 Path-based routing

Before editing files under the following directories, read their sub-`AGENTS.md` (or the relevant section of this file if none exists):

| Path | Sub-`AGENTS.md` exists? |
| --- | --- |
| `services/sandbox_manager/` | ✅ `services/sandbox_manager/AGENTS.md` |
| `services/common/` | ✅ `services/common/AGENTS.md` |
| `modules/claw_sandbox/` | ❌ (none yet — use §2 table to find headers) |
| `test/fuzztest/` | ❌ (none yet) |

> **Rule: subdirectory first, then top-level.** If a subdirectory has no `AGENTS.md`, read the headers listed in the §2 table.

### 3.3 Vocabulary-based routing

| Term / abbreviation | Meaning | Load this |
| --- | --- | --- |
| `OperateMode` | Bitmask permissions (`READ_MODE=1` … `DENY_WRITE_MODE=64`), see `policy_info.h` | `policy_info.h` |
| `SandboxRetType` | Per-policy return enum, `OPERATE_SUCCESSFULLY=0` onward | `policy_info.h` |
| `SandboxManagerErrCode` | Service-level error enum, `SANDBOX_MANAGER_OK=0` onward | `sandbox_manager_err_code.h` |
| `policyFlag` | MAC-layer policy label: `0=temporary`, `1=persistent`; conveyed via `MacParams.policyFlag` | `mac/mac_adapter.h` `MacParams` |
| `GenericValues` | RDB generic key-value container (`int32/int64/string/VariantValue`) | `services/common/AGENTS.md` |
| `POLICY_PATH_LIMIT=4095` | Max path length per policy | `sandbox_manager_const.h` |
| `MAX_BATCH_COUNT=32` | API batch limit per call (`1<<MAX_BATCH_COUNT_SHIFT`) | `sandbox_manager_const.h` |
| `NON_PERSIST_POLICY_BATCH_SIZE=200` / `PERSIST_POLICY_BATCH_SIZE=200000` | Internal batching thresholds | `sandbox_manager_const.h` |
| `PersistentPreserve` | Save on app uninstall, restore on reinstall (tokenId migration) | `services/sandbox_manager/main/cpp/include/preserve/persistent_preserve.h` |
| `MacAdapter::IsMacSupport()` | MAC kernel availability probe — read before modifying MAC code | `mac/mac_adapter.h` |
| `CheckPermission()` / `SetPermission*` names | 7 permission strings defined in `sandbox_manager_const.h` | `sandbox_manager_const.h` |

---

## 4. Do not / Ask before (high-risk operations)

> These items reflect **real incidents or easily triggered destructive changes** in this repository. Do not bypass them without maintainer confirmation.

### 4.1 Do not (without upgrade confirmation)

- Do **not** change the field order or bit values of `PolicyInfo`, `OperateMode`, `SandboxRetType`, or `SharedDirectoryInfo` — these form the SDK ABI consumed by all apps and services.
- Do **not** change `SandboxManagerErrCode` values or insert new enum values in the middle — append at the end only, and sync the cross-process Stub.
- Do **not** change field order in `*_parcel.h` / `*_raw_data.h` under `frameworks/sandbox_manager/include/` — this breaks IPC serialization.
- Do **not** modify the `MacParams` layout or ioctl command words in `mac/mac_adapter.h` — these are a contract with the kernel driver.
- Do **not** rename `FIELD_*` columns or table names in `database/policy_field_const.h` — schema upgrades must go through `SandboxManagerRdbOpenCallback::OnUpgrade`; `DROP TABLE` is forbidden.
- Do **not** bypass `SandboxManagerService::CheckPermission()` (including mocking it out in unit tests). Mock the `AccessToken` framework result instead.
- Do **not** add runtime dependencies beyond `cJSON` / `hilog` / `relational_store` / `selinux` / `safwk` / `samgr`. Check `bundle.json#deps.components` for the closure.
- Do **not** treat temporary policies (`SetPolicy`, `policyFlag=0`) as persistent — see §13.3 Pitfall 3 (Mixing up temporary and persistent).
- Do **not** directly `delete` `SandboxManagerService` / `PolicyInfoManager` singletons from `services/common/` utility code; they are managed by `DECLARE_DELAYED_SINGLETON`.

### 4.2 Ask before (escalate to maintainers before starting)

- Changing SA ID / `bundle.json#component.name` / `syscap` — cross-subsystem contract.
- Changing Feature Flag defaults (`sandbox_manager_*.gn` or `bundle.json#features`) — affects all build products.
- Changing batch limits (`MAX_BATCH_COUNT`, `NON_PERSIST_POLICY_BATCH_SIZE`, `PERSIST_POLICY_BATCH_SIZE`) or path limit (`POLICY_PATH_LIMIT`).
- Changing the `CheckPermission()` verification chain or adding new permissions to `sandbox_manager_const.h` — must also update `bundle.json` `requestPermissions`.
- Changing MAC `ioctl` commands or adding new Deny policy modes — couples with kernel and selinux policy files.
- Marking an existing public API `[[deprecated]]` or migrating to a new API — needs release notes.
- Changing seccomp rule loading in `modules/claw_sandbox` — affects device runtime security.

---

## 5. Basic Information

| Attribute | Value |
| --- | --- |
| Repository | `base/accesscontrol/sandbox_manager` |
| Published name | `@ohos/sandbox_manager` (`bundle.json#name`) |
| Subsystem | `accesscontrol` |
| Component | `sandbox_manager` |
| Adapted system type | `standard` |
| ROM / RAM | `10000KB` / `5000KB` |
| Primary language | C++17 |
| Build system | GN / Ninja |
| Feature flags | 5 entries, see §10 |

---

## 6. Directory Structure

```
accesscontrol_sandbox_manager/
├── bundle.json                            # Component metadata, deps, Feature Flags
├── sandbox_manager.gni                    # GN declarations (Feature Flag defaults)
├── BUILD.gn                               # Build entry point
├── interfaces/                            # SDK interface layer (external ABI)
│   └── inner_api/sandbox_manager/
│       ├── include/                       # Public headers (SDK ABI)
│       │   ├── sandbox_manager_kit.h      # SandboxManagerKit entry
│       │   ├── policy_info.h              # PolicyInfo / OperateMode / SandboxRetType / SharedDirectoryInfo
│       │   └── sandbox_manager_err_code.h # SandboxManagerErrCode enum
│       └── src/                           # SDK implementation (IPC client)
├── frameworks/                            # Framework layer
│   ├── sandbox_manager/include/           # Parcel serialization + DFX
│   │   ├── policy_info_vector_parcel.h    # PolicyInfo vector Parcel
│   │   ├── policy_info_parcel.h           # Single PolicyInfo Parcel
│   │   ├── set_info_parcel.h              # SetInfo Parcel
│   │   ├── policy_vec_raw_data.h          # Vector IPC data
│   │   ├── uint32_vec_raw_data.h          # uint32 result vector
│   │   ├── bool_vec_raw_data.h            # bool result vector
│   │   ├── shared_directory_info_vec_raw_data.h
│   │   └── sandbox_manager_dfx_helper.h
│   └── inner_api/sandbox_manager/         # SDK logging, DFX
├── services/                              # Service layer
│   ├── common/                            # Common utilities (indep. .so) → services/common/AGENTS.md
│   │   ├── database/{variant_value,generic_values}.h
│   │   └── utils/{sandbox_memory_manager,data_size_report_adapter}.h
│   └── sandbox_manager/                   # → services/sandbox_manager/AGENTS.md
│       ├── main/cpp/
│       │   ├── include/
│       │   │   ├── service/               # SA main class, PolicyInfoManager, PolicyTrie, constants
│       │   │   ├── database/              # RDB wrapper, field constants, OpenCallback
│       │   │   ├── mac/                   # MacAdapter
│       │   │   ├── media/                 # Media paths
│       │   │   ├── sensitive/             # HiSysEvent subscription
│       │   │   ├── share/                 # Shared files JSON
│       │   │   └── preserve/              # PersistentPreserve
│       │   └── src/                       # Corresponding implementations
│       └── test/{unittest,mock}/
├── modules/claw_sandbox/                  # seccomp command config + execution (no AGENTS.md)
└── test/fuzztest/                         # Fuzz tests (no AGENTS.md)
    ├── innerkits/sandbox_manager/         # SDK-side fuzz (one per API)
    └── services/sandbox_manager/          # SA Stub fuzz
```

---

## 7. API Reference

> Full signatures are authoritative in `interfaces/inner_api/sandbox_manager/include/sandbox_manager_kit.h`. This table lists **category and permission boundary only**; it does not reproduce parameters.

### 7.1 Persistent policies (RDB)

| API | Permission | Purpose |
| --- | --- | --- |
| `CleanPersistPolicyByPath(filePathList)` | `SET_SANDBOX_POLICY` | Clear persistent policies by path |
| `PersistPolicy(policy, result)` / `PersistPolicy(tokenId, policy, result)` | `SET_SANDBOX_POLICY` | Write persistent policy (RDB) |
| `UnPersistPolicy(...)` / `UnPersistPolicy(tokenId)` | `SET_SANDBOX_POLICY` | Delete persistent policy |
| `GetPersistPolicy(tokenId, policy)` | `GET_FILE_ACCESS_PERSIST` | Get persistent policies by tokenId |
| `CheckPersistPolicy(tokenId, policy, result)` | `CHECK_SANDBOX_POLICY` | Check if already persisted |
| `CleanPolicyByUserId(userId, filePathList)` | `SET_SANDBOX_POLICY` | Clean by userId |

### 7.2 Temporary / activate / revoke policies (MAC layer)

| API | Permission | Purpose |
| --- | --- | --- |
| `SetPolicy(tokenId, policy, policyFlag, result[, setInfo\|timestamp])` | `SET_SANDBOX_POLICY` | Write policy to MAC layer, optional `setInfo` or `timestamp` |
| `SetPolicyAsync(tokenId, policy, policyFlag[, timestamp])` | `SET_SANDBOX_POLICY` | Async version |
| `SetPolicyByBundleName(bundleName, appCloneIndex, policy, policyFlag, result)` | `SET_SANDBOX_POLICY` | Set by bundle name (clone app) |
| `UnSetPolicy(tokenId, policy)` / `UnSetPolicyAsync(...)` | `SET_SANDBOX_POLICY` | Revoke from MAC layer |
| `StartAccessingPolicy(policy, result[, useCallerToken, tokenId, timestamp])` | `SET_SANDBOX_POLICY` | Activate persistent policy |
| `StopAccessingPolicy(policy, result)` | `SET_SANDBOX_POLICY` | Deactivate |
| `StartAccessingByTokenId(tokenId[, timestamp])` | `SET_SANDBOX_POLICY` | Activate by tokenId (auto-loads flag=1) |
| `UnSetAllPolicyByToken(tokenId[, timestamp])` | `SET_SANDBOX_POLICY` | Revoke all policies for a tokenId |
| `CheckPolicy(tokenId, policy, result)` | `CHECK_SANDBOX_POLICY` | Check MAC-layer status |

### 7.3 Deny / Shared files

| API | Permission | Purpose |
| --- | --- | --- |
| `SetDenyPolicy(tokenId, policy, result)` / `UnSetDenyPolicy(tokenId, policy)` | `SET_SANDBOX_POLICY` | Deny-mode policies |
| `SetShareFileInfo` / `UpdateShareFileInfo` / `UnsetShareFileInfo` | `ACCESS_SHARED_FILE` | JSON shared file config |
| `GetSharedDirectoryInfo(result)` | `CHECK_SANDBOX_POLICY` | List shared directories |
| `GrantSharedDirectoryPermission()` / `RevokeSharedDirectoryPermission()` | `FILE_ACCESS_MANAGER` | Temp grant/revoke |

### 7.4 Persistent policy migration (`PersistentPreserve`)

Called via static methods in `services/sandbox_manager/main/cpp/include/preserve/persistent_preserve.h`:

- `GetPersistedPoliciesByTokenId(tokenId, policies)`
- `SaveBundlePersistentPolicies(bundleName, userId, appIdentifier, tokenId)` — called on uninstall
- `RestoreBundlePersistentPolicies(appIdentifier, userId, newTokenId, bundleName)` — called on reinstall
- `DeleteBundlePersistentPolicies(appIdentifier, userId)`

> The caller is typically `sensitive/sandbox_manager_event_subscriber` (HiSysEvent subscriber).

---

## 8. Error Codes

Actual definitions in `sandbox_manager_err_code.h` (`enum SandboxManagerErrCode : int32_t`). `SANDBOX_MANAGER_OK = 0`; order-sensitive, **append only at the end**.

| Name | Value | Trigger |
| --- | ---: | --- |
| `SANDBOX_MANAGER_OK` | `0` | Success |
| `PERMISSION_DENIED` | `1` | Permission check failed |
| `INVALID_PARAMTER` | `2` | Invalid parameter (empty path, illegal mode, etc.) |
| `SANDBOX_MANAGER_SERVICE_NOT_EXIST` | `3` | SA does not exist |
| `SANDBOX_MANAGER_SERVICE_PARCEL_ERR` | `4` | Parcel serialization failed |
| `SANDBOX_MANAGER_SERVICE_REMOTE_ERR` | `5` | Remote IPC error |
| `SANDBOX_MANAGER_DB_ERR` | `6` | RDB error |
| `SANDBOX_MANAGER_DB_RETURN_EMPTY` | `7` | RDB query returned empty |
| `SANDBOX_MANAGER_DB_RECORD_NOT_EXIST` | `8` | Record does not exist |
| `SANDBOX_MANAGER_MAC_NOT_INIT` | `9` | MAC not initialized |
| `SANDBOX_MANAGER_MAC_IOCTL_ERR` | `10` | MAC ioctl failed |
| `SANDBOX_MANAGER_DENY_ERR` | `11` | Deny policy conflict |
| `SANDBOX_MANAGER_MEDIA_CALL_ERR` | `12` | Media library call failed |
| `SANDBOX_MANAGER_KILL_PROCESS_ERR` | `13` | Process kill failed |
| `SANDBOX_MANAGER_NOT_SYS_APP` | `14` | Non-system app called restricted API |

> Per-policy granular results use `enum SandboxRetType` in `policy_info.h`.

---

## 9. Policy Types

### 9.1 `PolicyInfo` (struct)

```cpp
struct PolicyInfo {
    std::string path;   // Path
    uint64_t    mode;   // OperateMode bitmask
    PolicyType  type;   // UNKNOWN | SELF_PATH | AUTHORIZATION_PATH | OTHERS_PATH
};
```

> Note: `pathDesc` / `fixedNeighborPath` from historical docs **do not exist** in the current header — do not use them.

### 9.2 `OperateMode` (bitmask)

| Name | Value | Note |
| --- | ---: | --- |
| `READ_MODE` | `1 << 0` | |
| `WRITE_MODE` | `1 << 1` | |
| `CREATE_MODE` | `1 << 2` | |
| `DELETE_MODE` | `1 << 3` | |
| `RENAME_MODE` | `1 << 4` | |
| `DENY_READ_MODE` | `1 << 5` | |
| `DENY_WRITE_MODE` | `1 << 6` | |
| `MAX_MODE` | `1 << 7` | Sentinel |

`MODE_FILTER = 0b11` (from `sandbox_manager_const.h`) masks the lowest 2 bits for R/W checks.

### 9.3 `SandboxRetType` (per-policy return)

`OPERATE_SUCCESSFULLY=0`, `FORBIDDEN_TO_BE_PERSISTED=1`, `INVALID_MODE=2`, `INVALID_PATH=3`, `POLICY_HAS_NOT_BEEN_PERSISTED=4`, `POLICY_MAC_FAIL=5`, `FORBIDDEN_TO_BE_PERSISTED_BY_FLAG=6`.

### 9.4 Permission constants (7 total, in `sandbox_manager_const.h`)

`SET_SANDBOX_POLICY`, `CHECK_SANDBOX_POLICY`, `FILE_ACCESS_PERSIST`, `GET_FILE_ACCESS_PERSIST`, `REVOKE_FILE_ACCESS_PERSIST`, `FILE_ACCESS_MANAGER`, `ACCESS_SHARED_FILE`.

### 9.5 Key limits

| Name | Value | Source |
| --- | ---: | --- |
| `SA_LIFE_TIME` | `180000 ms` | Service unloads after 3 min idle |
| `POLICY_PATH_LIMIT` | `4095` | Max policy path length |
| `MAX_BATCH_COUNT` | `32` (`1<<MAX_BATCH_COUNT_SHIFT=5`) | **Per-API-call batch limit** |
| `NON_PERSIST_POLICY_BATCH_SIZE` | `200` | Internal non-persistent batch threshold |
| `PERSIST_POLICY_BATCH_SIZE` | `200000` | Internal persistent batch threshold |

---

## 10. Feature Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `sandbox_manager_feature_coverage` | `false` | Code coverage instrumentation |
| `sandbox_manager_process_resident` | `false` | Process resident (PC=resident, Phone=non-resident); when `false`, builds `sandbox_memory_manager` |
| `sandbox_manager_with_dec` | `false` | Data Execution Prevention |
| `sandbox_manager_dec_ext` | `false` | DEC extension |
| `sandbox_manager_enable_aids` | `false` | AIDs compatibility switch (affects `modules/claw_sandbox`) |

> Defaults are defined in both `sandbox_manager.gni` (top-level) and `bundle.json#features`. They must match; if they diverge, `bundle.json` wins and the `.gni` file should be updated.

---

## 11. Architecture Design

```
┌─────────────────────────────────────┐
│   Interfaces (SDK)                  │  ← SandboxManagerKit
│   frameworks/ (Parcel / SDK impl)   │
└─────────────┬───────────────────────┘
              │ IPC (Binder)
┌─────────────▼───────────────────────┐
│   Services / SA                     │
│   SandboxManagerService             │  ← OnStart/OnStop + CheckPermission
│   PolicyInfoManager                 │  ← validate / filter / match / cleanup
│   ├─ SandboxManagerRdb (RDB)        │  ← policy_table / shared_file_info_table
│   └─ MacAdapter                     │  ← ioctl to kernel MAC layer
│   PersistentPreserve                │  ← save on uninstall / restore on reinstall
│   MediaSupport / ShareFiles / EventSubscriber
└─────────────────────────────────────┘
```

| Component | Path | Responsibility |
| --- | --- | --- |
| `SandboxManagerService` | `services/sandbox_manager/main/cpp/include/service/sandbox_manager_service.h` | `SystemAbility` + `SandboxManagerStub`, IPC dispatch |
| `PolicyInfoManager` | `services/sandbox_manager/main/cpp/include/service/policy_info_manager.h` | Core business logic (singleton) |
| `SandboxManagerRdb` | `services/sandbox_manager/main/cpp/include/database/sandbox_manager_rdb.h` | RDB wrapper |
| `MacAdapter` | `services/sandbox_manager/main/cpp/include/mac/mac_adapter.h` | MAC ioctl |
| `PersistentPreserve` | `services/sandbox_manager/main/cpp/include/preserve/persistent_preserve.h` | App uninstall/reinstall policy migration |

---

## 12. Policy Lifecycle Management

### 12.1 Persistent vs Temporary

| Dimension | Persistent | Temporary |
| --- | --- | --- |
| API | `PersistPolicy` / `UnPersistPolicy` | `SetPolicy` / `UnSetPolicy` |
| Storage | RDB | Kernel MAC only |
| Lifetime | Until app uninstall | Current app lifecycle |
| Activation | Requires `StartAccessingPolicy` | Auto-activated |
| Cross-reboot | Yes | No |

### 12.2 Persistent policy lifecycle

1. **PERSIST**: `PersistPolicy` → `PolicyInfoManager::AddPolicy` → `SandboxManagerRdb::Add` into `policy_table`.
2. **ACTIVATE**: `StartAccessingPolicy` → read from RDB → `MacAdapter::SetSandboxPolicy` to kernel.
3. **DEACTIVATE**: `StopAccessingPolicy` → `MacAdapter::UnSetSandboxPolicy` (RDB preserved).
4. **CLEANUP**: `UnPersistPolicy` → RDB deletion.

### 12.3 Temporary policy lifecycle

1. **SET**: `SetPolicy` → `MacAdapter::SetSandboxPolicy(policyFlag=0)` (no RDB write).
2. **AUTO-UNSET**: Process exit / restart / explicit `UnSetPolicy` → `MacAdapter::UnSetSandboxPolicy`.

### 12.4 Bundle uninstall/reinstall policy migration

- **Uninstall**: `sensitive/sandbox_manager_event_subscriber` receives event → `PersistentPreserve::SaveBundlePersistentPolicies` associates policies with `appIdentifier`.
- **Reinstall**: `PersistentPreserve::RestoreBundlePersistentPolicies` looks up `appIdentifier` → rebinds policies to new `tokenId`.

---

## 13. Common Pitfalls

### Pitfall 1: Misunderstanding `MAX_BATCH_COUNT` (internal splitting constant)

`MAX_BATCH_COUNT=32` is an **internal batching constant** used by the service to split large inputs into 32-item chunks before RDB writes. It is **not** an API input limit — the public API accepts arbitrary-length vectors and internally splits them. However, performance degrades with very large inputs because the service serializes, deserializes, and processes the entire vector.

```cpp
// OK — the API accepts large vectors; MAX_BATCH_COUNT governs internal RDB splitting only
std::vector<PolicyInfo> policies(1000, /*...*/);
SandboxManagerKit::PersistPolicy(policies, results); // service splits internally

// Better for large inputs — split client-side to reduce IPC payload size
constexpr size_t MAX_BATCH_COUNT = 32;  // sandbox_manager_const.h
for (size_t i = 0; i < all.size(); i += MAX_BATCH_COUNT) {
    auto batch = slice(all, i, i + MAX_BATCH_COUNT);
    SandboxManagerKit::PersistPolicy(batch, results);
}
```

### Pitfall 2: Forgetting to activate persistent policies

`PersistPolicy` only writes to RDB — **it does not take effect immediately**. You must call `StartAccessingPolicy` afterward, or `CheckPolicy()` will return false.

### Pitfall 3: Mixing up temporary and persistent

`SetPolicy(policyFlag=0)` is temporary — lost on process exit. Persistence requires `PersistPolicy` + `StartAccessingPolicy`.

### Pitfall 4: Path length exceeding `POLICY_PATH_LIMIT=4095`

`policy.path.size() > 4095` → `INVALID_PARAMTER`. Strip duplicate `//` and avoid relative paths.

### Pitfall 5: Modifying MAC code without checking `IsMacSupport()`

MAC is unavailable on some products/emulators. Always read `IsMacSupport()` before modifying `MacAdapter`. All call paths must check for null/support first.

### Pitfall 6: Removing `CheckPermission` in unit tests

`SandboxManagerService::CheckPermission` is a security gate. **Do not** mock it to return `true`. Instead, mock the `AccessToken` framework result.

### Pitfall 7: Using `DROP TABLE` in RDB

Schema evolution must go through `SandboxManagerRdbOpenCallback::OnUpgrade` (bump version + migration SQL). `DROP` + recreate would erase all user-persisted policies.

### Pitfall 8: Changing IPC Parcel field order without updating interface token

Changing serialization order in `policy_info_parcel.h` etc. → must update the corresponding `Parcel::Marshalling`/`ReadFromParcel` and check `sandbox_manager.gni` for interface token conventions.

---

## 14. Verification Loop

> **You must run the checks in this section before declaring "Done".** List any failures explicitly — do not silently ignore them.

### 14.1 Minimum checks (every change)

```bash
# Build main service + module unit tests
hb build -T sandbox_manager --product-name {product_name}
hb build -T sandbox_manager_build_module_test --product-name {product_name}

# Build fuzz targets
hb build -T sandbox_manager_build_fuzz_test --product-name {product_name}
```

### 14.2 Task-specific checks

| Change path / type | Extra validation |
| --- | --- |
| Changed `interfaces/inner_api/sandbox_manager/include/` | Rebuild and run module UT (`sandbox_manager_build_module_test`); diff SDK ABI |
| Changed `frameworks/sandbox_manager/include/*parcel*` | Run module UT — at minimum `sandboxstub_test`, `persistpolicystub_test`, `unpersistpolicystub_test` |
| Changed `services/sandbox_manager/main/cpp/include/database/` | Run `SandboxManagerRdbOpenCallback::OnUpgrade` upgrade-path test cases, confirm schema evolution executable |
| Changed `mac/mac_adapter.h` | Run module UT + real device or MAC-capable emulator; compare `SANDBOX_MANAGER_MAC_IOCTL_ERR` counts |
| Changed `preserve/persistent_preserve.h` | Simulate uninstall→reinstall flow, verify policy rebinds to new `tokenId` |
| Changed Feature Flag / `bundle.json` | Build on at least 2 products (e.g. `rk3568`, `phone`) |
| Changed `modules/claw_sandbox/` | Run module UT; verify seccomp loading on real device |

### 14.3 Done definition

- [ ] Build passes (`sandbox_manager` + module tests)
- [ ] All relevant module UT tests PASS
- [ ] If public API changed: PR description includes **Public API Impact** (signature / enum value / serialization field changes) and maintainer confirmation
- [ ] If RDB schema changed: PR description gives the `OnUpgrade` migration SQL
- [ ] If MAC / permissions changed: PR description explains kernel driver or `bundle.json#permissions` sync points
- [ ] If Feature Flag changed: both `bundle.json` and `sandbox_manager.gni` updated, and PR includes build comparison across 2 products

### 14.4 Fallback (when validation cannot be run)

Your final response **must explicitly state**:

1. **Which** checks were **not executed** (e.g. specific product build missing, device-level runtime validation not performed).
2. **Why** — build-machine limitation, environment dependency, product matrix gap (not "the change is small").
3. **Minimum repro command** — a copy-pasteable `hb build -T` line for the maintainer to run on their machine.

> Missing these items means the PR/reply is considered **incomplete**.

---

## 15. Subordinate AGENTS.md Files

Two sub-`AGENTS.md` files exist in this repository. Read them before entering their directories:

- `services/sandbox_manager/AGENTS.md` — Service layer (`PolicyInfoManager` / RDB / MAC / Media / Share / Sensitive) implementation details, component relationships, debugging tips.
- `services/common/AGENTS.md` — Common utilities (`VariantValue` / `GenericValues` / `SandboxMemoryManager` / `DataSizeReportAdapter`) usage and pitfalls.

Subordinate files may supplement implementation details not covered here, but **must not conflict** with the §4 Do not or §14 Verification sections. If a conflict arises, this file takes precedence — notify the maintainer.

---

## 16. Version History

| Version | Date | Changes | Maintainer |
| --- | --- | --- | --- |
| v2.0 | 2026-07-10 | Full English translation; added "state task/doc/constraints before editing" preamble; repolished for clarity and consistency with the review rubric | AI Assistant |
| v1.1 | 2026-07-08 | Added Where to look / Knowledge Routing / Do not-Ask before / Verification Loop; fixed PolicyInfo fields, error codes, OperateMode bit values, batch limits; added modules/claw_sandbox and PersistentPreserve routing | AI Assistant |
| v1.0 | 2026-01-31 | Initial version | AI Assistant |
