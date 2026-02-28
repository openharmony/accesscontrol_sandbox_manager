# services/common - AI Knowledge Base

## Module Overview

The `services/common` module provides shared utilities and data structures used by the Sandbox Manager service layer. This module is compiled as a shared library (`sandbox_manager_service_common`) and contains common functionality for data storage abstraction, memory management, and system event reporting.

**Language**: C++
**Build Target**: `sandbox_manager_service_common`
**Output**: Shared library (`*.so`)

---

## Directory Structure

```
services/common/
├── BUILD.gn                      # GN build configuration
├── database/                     # Database-related utility classes
│   ├── include/
│   │   ├── variant_value.h       # Variant type wrapper (int, int64, string)
│   │   └── generic_values.h      # Generic key-value container
│   └── src/
│       ├── variant_value.cpp
│       └── generic_values.cpp
└── utils/                        # Service utility functions
    ├── sandbox_memory_manager.h  # Memory/unload management (conditional)
    ├── sandbox_memory_manager.cpp
    ├── data_size_report_adapter.h
    └── data_size_report_adapter.cpp
```

---

## Build Configuration

### Library Information

| Attribute | Value |
|-----------|-------|
| Library Name | `sandbox_manager_service_common` |
| Type | `ohos_shared_library` |
| Subsystem | `accesscontrol` |
| Part | `sandbox_manager` |

### External Dependencies

| Dependency | Purpose |
|------------|---------|
| `c_utils:utils` | Common utilities |
| `hilog:libhilog` | Logging framework |
| `hisysevent:libhisysevent` | System event reporting |
| `ipc:ipc_core` | IPC core functionality |
| `safwk:system_ability_fwk` | SystemAbility framework |
| `samgr:samgr_proxy` | SAMgr proxy |

### Feature Flags

| Flag | Behavior |
|------|----------|
| `sandbox_manager_process_resident` | Mark whether the sandbox process is resident. Resident in PC, not resident in phone. When `false`, includes `sandbox_memory_manager.cpp` in build |

---

## Component Reference

### Database Utilities (`database/`)

#### VariantValue

**File**: `database/include/variant_value.h`

A variant type wrapper that can hold different data types (int32_t, int64_t, string).

**Usage Notes**:
- Type-safe getters return `DEFAULT_VALUE` (-1) or empty string on type mismatch
- Uses `std::variant` for underlying storage
- Used by `GenericValues` for value storage

---

#### GenericValues

**File**: `database/include/generic_values.h`

A generic key-value container used for database operations and generic data passing. Stores string keys mapped to `VariantValue` objects.

**Usage Notes**:
- Returns default values when key not found:
  - `GetInt()`: `VariantValue::DEFAULT_VALUE` (-1)
  - `GetString()`: empty string
- Commonly used for RDB database value storage and retrieval

---

### Utilities (`utils/`)

#### SandboxMemoryManager

**File**: `utils/sandbox_memory_manager.h`

Manages service lifecycle and unload behavior. Only included in build when `sandbox_manager_process_resident` is `false`.

**Key Constants**:
- `MAX_RUNNING_NUM = 256` - Maximum concurrent function calls threshold

**Usage Notes**:
- Thread-safe singleton pattern with recursive mutex protection
- Tracks concurrent function calls to determine if service can be unloaded
- Logs warning when running function count exceeds `MAX_RUNNING_NUM`
- `IsAllowedUnloadService()` returns `true` only when `callFuncRunningNum_ == 0`

---

#### DataSizeReportAdapter

**File**: `utils/data_size_report_adapter.h`

Reports user data statistics to HiSysEvent for monitoring and analytics.

```cpp
void ReportUserDataSize();  // Main entry point
```

**Key Constants**:
| Constant | Value | Purpose |
|----------|-------|---------|
| `SANDBOX_MGR_NAME` | `"sandbox_manager"` | Component name for reporting |
| `SYS_EL1_SANDBOX_MGR_DIR` | `"/data/service/el1/public/sandbox_manager"` | Monitored directory |
| `USER_DATA_DIR` | `"/data"` | Partition to monitor |
| `UNITS` | `1024.0` | Conversion factor (B to MB) |
| `ONE_DAY` | `86400` (24*60*60) | Reporting interval in seconds |

**Behavior**:
1. Checks if more than 24 hours have passed since last report
2. Reports to HiSysEvent with domain `FILEMANAGEMENT`, event `USER_DATA_SIZE`
3. Reports asynchronously in a separate thread
4. Reports partition remaining size and folder size

**HiSysEvent Format**:
| Key | Value |
|-----|-------|
| `COMPONENT_NAME` | `"sandbox_manager"` |
| `PARTITION_NAME` | `"/data"` |
| `REMAIN_PARTITION_SIZE` | Remaining MB (double) |
| `FILE_OR_FOLDER_PATH` | `"/data/service/el1/public/sandbox_manager"` |
| `FILE_OR_FOLDER_SIZE` | Folder size in bytes |

---

## Design Patterns

### Singleton Pattern

**Class**: `SandboxMemoryManager`

- Double-checked locking with recursive mutex
- Lazy initialization on first `GetInstance()` call
- Thread-safe instance creation

```cpp
SandboxMemoryManager& SandboxMemoryManager::GetInstance()
{
    static SandboxMemoryManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new SandboxMemoryManager();
        }
    }
    return *instance;
}
```

---

## Build and Test

### Build Commands

```bash
./build.sh --product-name rk3568 --build-target sandbox_manager
```

### Output Locations

| Output Type | Location |
|-------------|----------|
| Shared library | `out/{product}/accesscontrol/sandbox_manager/libsandbox_manager_service_common.so` |

---

## Common Pitfalls

### Pitfall 1: Default Value Confusion

**Problem Description**: `GenericValues.GetInt()` and `GetInt64()` return `VariantValue::DEFAULT_VALUE` (-1) when:
- Key doesn't exist
- Type mismatch occurs

This makes it impossible to distinguish between "not found" and a legitimate -1 value.

**Correct Approach**: Use `Get()` and check `GetType()` first:

```cpp
// Wrong: Can't distinguish missing key from valid -1
int32_t result = values.GetInt("my_key");

// Correct: Explicit type checking
VariantValue v = values.Get("my_key");
if (v.GetType() == ValueType::TYPE_INT) {
    int32_t result = v.GetInt();  // Safe to access
} else {
    // Handle missing or wrong type
}
```

### Pitfall 2: SandboxMemoryManager Conditional Build

**Problem Description**: `SandboxMemoryManager` only exists when `sandbox_manager_process_resident` is `false`. Code that unconditionally uses this class will fail to compile in resident mode.

**Workaround**: Check build configuration before using this class, or use feature flags:

```cpp
// Check if memory manager is available
#ifndef SANDBOX_MANAGER_PROCESS_RESIDENT
    SandboxMemoryManager::GetInstance().AddFunctionRuningNum();
#endif
```

### Pitfall 3: VariantValue Type Mismatch Silently Returns Default

**Problem Description**: Calling `GetInt()` on a `VariantValue` containing a string returns `DEFAULT_VALUE` (-1) instead of throwing an error or asserting.

**Example**:
```cpp
VariantValue v("hello");  // TYPE_STRING
int32_t result = v.GetInt();  // Returns -1, no error!
```

**Correct Approach**: Always check type before accessing:

```cpp
if (v.GetType() == ValueType::TYPE_INT) {
    int32_t result = v.GetInt();
}
```

---

## Integration Points

### Upstream Dependencies

This module is used by:
- `services/sandbox_manager/main/cpp` - Main service implementation

### Downstream Dependencies

This module depends on:
- `frameworks/` - Framework layer includes
- `interfaces/inner_api/sandbox_manager` - Public API definitions

---

## Version History

| Version | Date | Changes | Maintainer |
|---------|------|---------|------------|
| v1.0 | 2026-02-11 | Initial documentation | AI Assistant |
