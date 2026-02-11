# Sandbox Manager - Services Layer

## Module Overview

**Module Path**: `services/sandbox_manager/`
**Layer**: Service Layer (Core Service Implementation)
**Language**: C++
**Build Target**: `sandbox_manager`

The Services Layer is the core implementation of the Sandbox Manager system. It hosts the main `SystemAbility` service, manages policy lifecycle, handles persistent storage via RDB, interfaces with the MAC security layer, and provides file sharing business logic.

---

## Directory Structure

```
services/sandbox_manager/
├── common/                                # Common utilities shared across service layer
│   ├── database/                          # Database common utilities
│   │   ├── generic_values.h/cpp           # Generic key-value container for DB operations
│   │   └── variant_value.h/cpp            # Variant value type supporting multiple data types
│   └── utils/                             # Service utility classes
│       ├── data_size_report_adapter.h/cpp # Memory size reporting adapter
│       └── sandbox_memory_manager.h/cpp   # Memory management utilities
│
├── main/cpp/                              # Main service implementation
│   ├── include/                           # Public headers for service components
│   │   ├── service/                       # Core service logic
│   │   │   ├── sandbox_manager_service.h       # Main SystemAbility service class
│   │   │   ├── policy_info_manager.h           # Policy management business logic (core)
│   │   │   ├── policy_trie.h                  # Trie tree for path matching
│   │   │   └── sandbox_manager_const.h         # Service constants and permissions
│   │   ├── database/                      # RDB storage operations
│   │   │   ├── sandbox_manager_rdb.h          # RDB database operation wrapper
│   │   │   ├── sandbox_manager_rdb_utils.h    # RDB utility functions
│   │   │   ├── sandbox_manager_rdb_open_callback.h  # Database open callback
│   │   │   └── policy_field_const.h            # Database field name constants
│   │   ├── mac/                           # MAC (Mandatory Access Control) layer adaptation
│   │   │   └── mac_adapter.h                   # MAC security control adapter
│   │   ├── media/                         # Media library path support
│   │   │   └── media_path_support.h           # Media path handling
│   │   ├── sensitive/                     # Sensitive event subscription
│   │   │   └── sandbox_manager_event_subscriber.h  # HiSysEvent subscriber
│   │   └── share/                         # File sharing business logic
│   │       └── share_files.h                   # Shared file configuration manager
│   │
│   └── src/                               # Implementation files (mirror include structure)
│       ├── service/
│       ├── database/
│       ├── mac/
│       ├── media/
│       ├── sensitive/
│       └── share/
│
└── test/                                  # Service layer tests
    ├── unittest/                          # Unit tests
    └── mock/                              # Mock implementations
```

---

## Core Components

### 1. Service Component (`service/`)

The service component implements the main SystemAbility and core business logic.

| Class | File | Responsibility |
|-------|------|----------------|
| **SandboxManagerService** | [sandbox_manager_service.h](main/cpp/include/service/sandbox_manager_service.h) | Main SystemAbility service, IPC entry point, service lifecycle management (OnStart/OnStop) |
| **PolicyInfoManager** | [policy_info_manager.h](main/cpp/include/service/policy_info_manager.h) | **Core policy management logic**: persist/unpersist, set/unset, activate/deactivate, policy validation, path matching |
| **PolicyTrie** | [policy_trie.h](main/cpp/include/service/policy_trie.h) | Trie tree data structure for efficient path prefix matching and mode checking |

#### SandboxManagerService
- **Base Class**: `SystemAbility`, `SandboxManagerStub` (IPC)
- **SA ID**: System-defined ID for Sandbox Manager service
- **Key Responsibilities**:
  - Service lifecycle: `OnStart()`, `OnStop()`, `OnIdle()`
  - Permission checking: `CheckPermission()`
  - IPC request dispatching to `PolicyInfoManager`
  - Delayed unload management for memory optimization

#### PolicyInfoManager (The Core Brain)
- **Pattern**: Singleton (`GetInstance()`)
- **Key Methods**:
  - **Persistent Policy Operations**:
    - `AddPolicy()` - Add policies to RDB database
    - `RemovePolicy()` - Remove policies from database
    - `MatchPolicy()` - Match policies from database
  - **Temporary Policy Operations**:
    - `SetPolicy()` - Set temporary policies (auto-activated)
    - `UnSetPolicy()` - Remove temporary policies
  - **Activation Control**:
    - `StartAccessingPolicy()` - Activate persistent policies (load to MAC)
    - `StopAccessingPolicy()` - Deactivate policies (remove from MAC)
  - **Policy Validation**:
    - `CheckPolicyValidity()` - Validate policy path and mode
    - `CheckPathIsBlocked()` - Check if path is in blocklist
    - `FilterValidPolicyInBatch()` - Batch filter invalid policies
  - **Database Operations**:
    - `ExactFind()` - Find exact policy record
    - `RangeFind()` - Find policies within depth range
    - `TransferPolicyToGeneric()` / `TransferGenericToPolicy()` - Convert between Policy and GenericValues
  - **Bundle Lifecycle**:
    - `RemoveBundlePolicy()` - Clean up policies on app uninstall
    - `CleanPolicyByUserId()` - Clean up policies for specific user

---

### 2. Database Component (`database/`)

The database component handles all RDB (Relational Database) operations for persistent storage.

| Class | File | Responsibility |
|-------|------|----------------|
| **SandboxManagerRdb** | [sandbox_manager_rdb.h](main/cpp/include/database/sandbox_manager_rdb.h) | RDB wrapper, provides Add/Remove/Modify/Find operations |
| **PolicyFiledConst** | [policy_field_const.h](main/cpp/include/database/policy_field_const.h) | Database field name constants (TOKENID, PATH, MODE, DEPTH, FLAG) |
| **SandboxManagerRdbOpenCallback** | [sandbox_manager_rdb_open_callback.h](main/cpp/include/database/sandbox_manager_rdb_open_callback.h) | RDB open callback, handles database creation and version upgrades |

#### Database Schema
| Table Name | Fields |
|------------|--------|
| **policy_table** | `tokenId` (INT32), `path` (TEXT), `mode` (INT32), `depth` (INT32), `flag` (INT32) |

#### SandboxManagerRdb API
```cpp
// Add records to database
int32_t Add(const DataType type, const std::vector<GenericValues> &values,
            const std::string &duplicateMode = IGNORE);

// Remove records matching conditions
int32_t Remove(const DataType type, const GenericValues &conditions);

// Modify records matching conditions
int32_t Modify(const DataType type, const GenericValues &modifyValues,
               const GenericValues &conditions);

// Find records matching conditions with symbol comparison
int32_t Find(const DataType type, const GenericValues &conditions,
             const GenericValues &symbols, std::vector<GenericValues> &results);
```

---

### 3. MAC Adapter Component (`mac/`)

The MAC (Mandatory Access Control) adapter interfaces with the kernel-level security layer.

| Class | File | Responsibility |
|-------|------|----------------|
| **MacAdapter** | [mac_adapter.h](main/cpp/include/mac/mac_adapter.h) | MAC layer ioctl interface, set/unset/query/check sandbox policies |

#### MacAdapter Methods
- `SetSandboxPolicy()` - Set sandbox policies to MAC layer
- `UnSetSandboxPolicy()` - Unset sandbox policies from MAC layer
- `SetDenyPolicy()` - Set deny policies (blocking mode)
- `UnSetDenyPolicy()` - Unset deny policies
- `QuerySandboxPolicy()` - Query if policy exists in MAC
- `CheckSandboxPolicy()` - Check if policy is active in MAC
- `DestroySandboxPolicy()` - Destroy all policies for a tokenId
- `UnSetSandboxPolicyByUser()` - Unset policies by userId

#### MacParams Structure
```cpp
struct MacParams {
    uint32_t tokenId;      // Application token ID
    uint64_t policyFlag;   // Policy flag (0=临时, 1=持久化)
    uint64_t timestamp;    // Policy timestamp
    int32_t userId;        // User ID
};
```

---

### 4. Media Path Support Component (`media/`)

The media component handles special logic for media library paths.

| Class | File | Responsibility |
|-------|------|----------------|
| **SandboxManagerMedia** | [media_path_support.h](main/cpp/include/media/media_path_support.h) | Media path detection, permission type conversion, media library interaction |

#### SandboxManagerMedia Methods
- `IsMediaPolicy()` - Check if path is a media library path
- `OperateModeToPhotoPermissionType()` - Convert OperateMode to PhotoPermissionType
- `CheckPolicyBeforeGrant()` - Check media permissions before granting
- `AddMediaPolicy()` - Add media-specific policies
- `RemoveMediaPolicy()` - Remove media-specific policies
- `GetMediaPermission()` - Get media permission status

---

### 5. Sensitive Event Component (`sensitive/`)

The sensitive component subscribes to system events for policy cleanup.

| Class | File | Responsibility |
|-------|------|----------------|
| **SandboxManagerCommonEventSubscriber** | [sandbox_manager_event_subscriber.h](main/cpp/include/sensitive/sandbox_manager_event_subscriber.h) | HiSysEvent subscriber, listens for app install/uninstall events |

#### Event Handling
- `OnReceiveEvent()` - Handle common events
- `OnReceiveEventRemove()` - Handle app uninstall (clean up policies)
- `OnReceiveEventAdd()` - Handle app install events

---

### 6. File Sharing Component (`share/`)

The share component manages shared file configuration from JSON profiles.

| Class | File | Responsibility |
|-------|------|----------------|
| **SandboxManagerShare** | [share_files.h](main/cpp/include/share/share_files.h) | Shared file configuration manager, loads JSON config |

#### Share Configuration Map Structure
```
g_shareMap hierarchy:
├── bundleName1
│   ├── User100
│   │   └── path1: r/w
│   └── User200
│       ├── path1: r/w
│       └── path2: r/w
└── bundleName2
    └── User100
        ├── path1: r/w
        └── path2: r/w
```

#### SandboxManagerShare Methods
- `InitShareMap()` - Initialize share configuration map
- `GetShareCfgByBundle()` - Get share config for a specific bundle
- `FindPermission()` - Find permission for path in share map
- `DeleteByBundleName()` - Delete share config for bundle
- `TransAndSetToMap()` - Parse JSON and add to map

---

### 7. Common Utilities (`common/`)

#### GenericValues
Generic key-value container for database operations.
- Supports `int32_t`, `int64_t`, `string`, `VariantValue` types
- Used for database query conditions and results

#### VariantValue
Variant value type that can hold multiple data types.

---

## Service Layer Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    IPC Client (Interfaces Layer)                │
│                    SandboxManagerKit                             │
└─────────────────────────────────────────────────────────────────┘
                                ↓ IPC/Binder
┌─────────────────────────────────────────────────────────────────┐
│              SandboxManagerService (SystemAbility)              │
│              - Service Lifecycle (OnStart/OnStop)                │
│              - Permission Checking                              │
│              - Request Dispatching                              │
└─────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────┐
│              PolicyInfoManager (Core Business Logic)            │
│              - Policy Validation                                │
│              - Path Matching (PolicyTrie)                        │
│              - Policy Lifecycle Management                       │
└──────────┬────────────────────────────────────┬─────────────────┘
           ↓                                    ↓
┌──────────────────────┐            ┌──────────────────────────┐
│  SandboxManagerRDB   │            │      MacAdapter          │
│  (Persistent Storage)│            │  (MAC Security Layer)    │
│                      │            │                          │
│  - Add/Remove/Find   │            │  - Set/UnSet Policy      │
│  - RDB Operations    │            │  - Query/Check Policy    │
└──────────────────────┘            └──────────────────────────┘
           ↓                                    ↓
┌──────────────────────┐            ┌──────────────────────────┐
│  RDB Database        │            │   Kernel MAC Layer       │
│  (policy_table)      │            │   (Sandbox Control)      │
└──────────────────────┘            └──────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    Supporting Components                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │ MediaSupport │  │ ShareFiles   │  │ EventSubscriber      │ │
│  │              │  │              │  │                      │ │
│  │ Media paths  │  │ Shared cfg   │  │ App install/remove   │ │
│  └──────────────┘  └──────────────┘  └──────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Data Flow Examples

### Example 1: Persist Policy Flow

```
Client (SandboxManagerKit)
    → IPC: PersistPolicy(policies)
    ↓
SandboxManagerService
    → CheckPermission(SET_SANDBOX_POLICY)
    ↓
PolicyInfoManager::AddPolicy()
    → FilterValidPolicyInBatch() - Validate policies
    → CheckPathIsBlocked() - Check blocklist
    → CheckPolicyValidity() - Validate path/mode
    → ExactFind() - Check for duplicates
    ↓
SandboxManagerRdb::Add()
    → Insert into RDB policy_table
    ↓
Return results to client
```

### Example 2: Start Accessing Policy Flow (Activation)

```
Client
    → IPC: StartAccessingPolicy(policies)
    ↓
SandboxManagerService
    ↓
PolicyInfoManager::StartAccessingPolicy()
    → Query from RDB for persistent policies
    → MatchPolicy() - Find matching policies
    ↓
MacAdapter::SetSandboxPolicy()
    → ioctl to MAC layer
    → Load policies to kernel
    ↓
Return results (policies now active)
```

### Example 3: Set Temporary Policy Flow

```
Client
    → IPC: SetPolicy(policies)
    ↓
SandboxManagerService
    ↓
PolicyInfoManager::SetPolicy()
    → FilterValidPolicyInBatch() - Validate
    ↓
MacAdapter::SetSandboxPolicy()
    → ioctl to MAC layer
    → Set policyFlag = 0 (temporary)
    ↓
Return results (policies immediately active)
    Note: NOT stored in RDB, lost on app restart
```

---

## Database Operations Guide

### GenericValues Usage

`GenericValues` is a key-value map used for database operations:

```cpp
// Create condition for query
GenericValues conditions;
conditions.Put(PolicyFiledConst::FIELD_TOKENID, tokenId);
conditions.Put(PolicyFiledConst::FIELD_MODE, OperateMode::READ);

// Create symbols for comparison (e.g., depth <= 2)
GenericValues symbols;
symbols.Put(PolicyFiledConst::FIELD_DEPTH, 2);

// Query results
std::vector<GenericValues> results;
int32_t ret = SandboxManagerRdb::GetInstance().Find(
    DataType::PERSIST_POLICY, conditions, symbols, results);

// Access result values
for (const auto& result : results) {
    std::string path = result.GetString(PolicyFiledConst::FIELD_PATH);
    uint32_t mode = result.GetInt(PolicyFiledConst::FIELD_MODE);
}
```

---

## Constants and Permissions

### Permissions (sandbox_manager_const.h)

| Permission | Purpose | Used By |
|------------|---------|---------|
| `ohos.permission.SET_SANDBOX_POLICY` | Set/unset sandbox policies | PersistPolicy, SetPolicy, StartAccessingPolicy, etc. |
| `ohos.permission.CHECK_SANDBOX_POLICY` | Check sandbox policies | CheckPolicy, CheckPersistPolicy |
| `ohos.permission.FILE_ACCESS_PERSIST` | Persist file access | StartAccessingPolicy |
| `ohos.permission.FILE_ACCESS_MANAGER` | File access manager | File manager operations |

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `SA_LIFE_TIME` | 180000 ms (3 min) | Service idle timeout before unload |
| `POLICY_PATH_LIMIT` | 4095 | Maximum policy path length |
| `MODE_FILTER` | 0b11 | Mode filter for read/write bits |
| `SPACE_MGR_SERVICE_UID` | 7013 | Space manager service UID |
| `FOUNDATION_UID` | 5523 | Foundation process UID |

---

## Policy Lifecycle Management

### Persistent Policy Lifecycle

```
1. PERSIST PHASE
   Client → PersistPolicy()
   PolicyInfoManager → AddPolicy() → RDB::Add()
   Result: Stored in database

2. ACTIVATION PHASE
   Client → StartAccessingPolicy()
   PolicyInfoManager → MatchPolicy() (from RDB)
   PolicyInfoManager → MacAdapter::SetSandboxPolicy()
   Result: Loaded to MAC layer, now effective

3. DEACTIVATION PHASE
   Client → StopAccessingPolicy()
   PolicyInfoManager → MacAdapter::UnSetSandboxPolicy()
   Result: Removed from MAC layer, still in RDB

4. CLEANUP PHASE
   Client → UnPersistPolicy()
   PolicyInfoManager → RemovePolicy() → RDB::Remove()
   Result: Deleted from database
```

### Temporary Policy Lifecycle

```
1. SET PHASE
   Client → SetPolicy()
   PolicyInfoManager → MacAdapter::SetSandboxPolicy()
   policyFlag = 0 (temporary)
   Result: Immediately active in MAC layer
   Note: NOT stored in RDB

2. AUTO-UNSET PHASE
   - App process terminates
   - OR: UnSetPolicy() explicitly called
   PolicyInfoManager → MacAdapter::UnSetSandboxPolicy()
   Result: Removed from MAC layer
```

---

## Common Pitfalls in Services Layer

### Pitfall 1: Forgetting to Activate Persistent Policies

**Problem**: After `PersistPolicy`, policies are only in RDB, not active.

**Solution**: Must call `StartAccessingPolicy` to activate.

### Pitfall 2: Policy Path Validation

**Problem**: Invalid paths (e.g., blocklisted paths) cause failures.

**Solution**: Always call `CheckPolicyValidity()` and `CheckPathIsBlocked()` before adding policies.

### Pitfall 3: Thread Safety in Database Operations

**Problem**: Concurrent database access can cause corruption.

**Solution**: `SandboxManagerRdb` uses `RWLock` for thread-safe access. Always use the singleton instance.

### Pitfall 4: MAC Layer Not Available

**Problem**: MAC operations fail on systems without MAC support.

**Solution**: Always check `MacAdapter::IsMacSupport()` before MAC operations.

---

## Testing

### Unit Tests Location
- `services/sandbox_manager/test/unittest/`
  - `sandbox_manager_service_test.cpp` - Service tests
  - `policy_info_manager_test.cpp` - Policy manager tests
  - `sandbox_manager_rdb_test.cpp` - Database tests
  - `policy_trie_test.cpp` - Trie tree tests
  - `media_path_mock_test.cpp` - Media path tests
  - `dec_testcase.cpp` - DEC tests

### Build and Run Tests

```bash
# Build tests
./build.sh --product-name {product_name} --build-target sandbox_manager_build_module_test

# Run tests (on device)
# Tests are installed to /data/bin/
```

---

## Integration with Other Layers

### Upstream: Interfaces Layer
- Receives IPC requests via `SandboxManagerStub`
- Returns results via `PolicyVecRawData`, `Uint32VecRawData`, `BoolVecRawData`

### Downstream Dependencies
- **RDB (relational_store)**: Persistent storage
- **MAC Layer**: Kernel security control
- **Media Library**: Media path handling
- **HiSysEvent**: System event subscription
- **Bundle Manager**: App install/uninstall events
- **AccessToken**: Token ID management

---

## Development Notes

### Adding New Policy Types

1. Extend `OperateMode` in interfaces layer
2. Update `PolicyInfoManager::CheckPolicyValidity()`
3. Add MAC layer support in `MacAdapter`
4. Update database schema if needed

### Debugging Tips

1. Enable HiSysEvent logging for policy operations
2. Check RDB database at `/data/service/el2/public/database/sandbox_manager_rdb`
3. Use `CheckPolicy()` to verify policy status in MAC layer
4. Review `PolicyInfoManager` logs for validation failures

---

## Version History

| Version | Date | Changes | Maintainer |
|---------|------|---------|------------|
| v1.0 | 2026-02-11 | Initial services layer documentation | AI Assistant |
