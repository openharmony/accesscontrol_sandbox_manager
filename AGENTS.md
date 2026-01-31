# sandbox_manager - AI Knowledge Base

## Project Overview

Sandbox Manager is a system foundation service in OpenHarmony, responsible for managing and persisting file sharing rules between application sandboxes. It provides persistent storage, management, and activation functions for legitimate inter-application file sharing, solving the file sharing issues caused by application sandbox directory isolation.

**Language**: C++
**Build System**: GN (Generate Ninja)
**Subsystem**: accesscontrol
**Component**: sandbox_manager

## Basic Information

| Attribute | Value |
|-----------|-------|
| Repository Name | sandbox_manager |
| Subsystem | base/accesscontrol |
| Primary Language | C++ |
| Last Updated | 2026-02-04 |

## Directory Structure

```
accesscontrol_sandbox_manager/
├── interfaces/                    # Interface layer (Public API definitions)
│   └── inner_api/sandbox_manager/ # Sandbox Manager Inner API module
│       ├── include/               # Public header files
│       │   ├── sandbox_manager_kit.h        # Main API entry class (SandboxManagerKit)
│       │   │                          # See [API Reference](#api-reference)
│       │   ├── policy_info.h                # Policy information structures (PolicyInfo, SandboxRetType, OperateMode)
│       │   └── sandbox_manager_err_code.h   # Error code definitions
│       └── src/                   # SDK implementation (IPC client-side code)
├── frameworks/                    # Framework layer (Data serialization & utilities)
│   ├── common/                    # Common utilities shared across layers
│   ├── sandbox_manager/           # Framework implementation
│   │   ├── include/               # Serialization related headers (Parcel marshalling)
│   │   └── src/                   # Parcel serialization implementation
│   └── inner_api/sandbox_manager/ # Inner API framework utilities (logging, DFX)
├── services/                      # Service layer (Core service implementation)
│   ├── common/                    # Service common code
│   │   ├── database/              # RDB helper utilities and database constants
│   │   └── utils/                 # Service utilities (permission check, file operations)
│   └── sandbox_manager/main/      # Main service implementation (SystemAbility)
│       └── cpp/
│           ├── include/
│           │   ├── service/       # Core service logic (SandboxManagerService, PolicyInfoManager)
│           │   ├── database/      # RDB storage operations (SandboxManagerRDB)
│           │   ├── mac/           # MAC layer adaptation (MacAdapter)
│           │   ├── media/         # Media path support (media library path handling)
│           │   ├── sensitive/     # Sensitive event subscription (HiSysEvent)
│           │   └── share/         # File sharing business logic
│           └── src/               # Corresponding implementations
├── test/                          # Test directory
│   └── fuzztest/                  # Fuzz tests for security testing
├── bundle.json                    # Component configuration (subsystem, part metadata)
├── sandbox_manager.gni            # GN configuration variables
└── BUILD.gn                       # Build entry point
```

### Layered Architecture

```
┌─────────────────────────────────────┐
│   Interfaces Layer                  │  ← Public API definitions
│   - SandboxManagerKit               │
├─────────────────────────────────────┤
│   Frameworks Layer                  │  ← Data serialization, logging
│   - Parcel serialization            │
│   - Logging and DFX utilities       │
├─────────────────────────────────────┤
│   Services Layer                    │  ← Core service implementation
│   - SandboxManagerService           │  SystemAbility
│   - PolicyInfoManager               │  Policy management
│   - RDB Storage                     │  Persistent storage
│   - MAC Adapter                     │  Security control
└─────────────────────────────────────┘
```

### Key Directory Description

| Directory | Description |
|-----------|-------------|
| interfaces/inner_api/sandbox_manager/ | Public API definitions, including SDK headers and implementation |
| frameworks/ | Framework layer code, including data serialization and logging utilities |
| services/ | Service layer code, core service implementation and database storage |
| test/fuzztest/ | Fuzz test code |

---

## Repository Overview

### Core Features

- **Persistent Policy Management**: Provides persistent storage for policies, valid until application uninstallation
- **Temporary Policy Management**: Provides temporary policy settings, valid only during the current application lifecycle
- **Policy Activation Control**: Supports dynamic enabling and disabling of persistent policies
- **Inner API**: Provides C++ API interfaces for internal system components

### Major Dependencies

| Dependency | Purpose |
|------------|---------|
| ability_base | Ability foundation framework |
| access_token | Access token management |
| bundle_framework | Bundle management framework |
| ipc | Inter-process communication |
| relational_store | Relational Database (RDB) |
| samgr | System ability manager |
| hisysevent | System event logging |
| hilog | System logging |
| cJSON | JSON processing library |

---

## Technology Stack

### Programming Languages

- **C++17**: Primary development language

### Frameworks and Libraries

| Framework/Library | Purpose |
|-------------------|---------|
| IPC (Binder) | Cross-process communication |
| RDB (Relational Database) | Policy persistent storage |
| MAC (Mandatory Access Control) | Mandatory access control |
| SystemAbility | System ability framework |

## Quick Start

### Typical Usage Flow

```cpp
#include "sandbox_manager_kit.h"

using namespace OHOS::AccessControl;

// 1. Define policy: Allow App B to read App A's files
PolicyInfo policy;
policy.path = "/data/storage/el2/base/haps/appA/files/";
policy.pathDesc = "App A private files";
policy.mode = OperateMode::READ;
policy.fixedNeighborPath = "/data/storage/el2/base/haps/appB/";

// 2. Set persistent policy (stored in database)
std::vector<PolicyInfo> policies = {policy};
std::vector<SandboxRetType> results;
int32_t ret = SandboxManagerKit::PersistPolicy(policies, results);

// 3. Activate policy (load to MAC layer to take effect)
ret = SandboxManagerKit::StartAccessingPolicy(policies, results);

// Later: Deactivate when done
ret = SandboxManagerKit::StopAccessingPolicy(policies, results);

// Clean up: Remove persistent policy
ret = SandboxManagerKit::UnPersistPolicy(policies, results);
```

### Important Notes

- **Policy Size Limit**: Maximum 500 policies per batch
- **Permission Required**: `ohos.permission.SET_SANDBOX_POLICY` for policy operations
- **Lifecycle**:
  - `PersistPolicy`: Valid until app uninstallation
  - `SetPolicy`: Valid only during current app lifecycle
- **Activation Required**: Persisted policies must be activated with `StartAccessingPolicy`

## Build and Test

### Build Commands

```bash
# Build module (replace {product_name} with actual product like "ohos-sdk", "rk3568")
./build.sh --product-name {product_name} --build-target sandbox_manager

# Example for standard products:
./build.sh --product-name ohos-sdk --build-target sandbox_manager
./build.sh --product-name rk3568 --build-target sandbox_manager
```

### Test Commands

Unit tests are located in test directories under each layer, using `ohos_unittest` framework:

```bash
# Build test (replace {product_name} with actual product)
./build.sh --product-name {product_name} --build-target sandbox_manager_build_module_test

# Example:
./build.sh --product-name ohos-sdk --build-target sandbox_manager_build_module_test
```

Fuzz tests are located in `test/fuzztest/` directory.

### Output Locations

| Output Type | Location |
|-------------|----------|
| Library files | out/{product}/accesscontrol/sandbox_manager/*.so |

---

## API Reference

### Core API Class

**SandboxManagerKit**: Main API entry class, defined in `sandbox_manager_kit.h`

### Major Interfaces

| API | Description | Header | Permission Required |
|-----|-------------|--------|---------------------|
| `PersistPolicy()` | Add persistent policies | [sandbox_manager_kit.h](interfaces/inner_api/sandbox_manager/include/sandbox_manager_kit.h) | `ohos.permission.SET_SANDBOX_POLICY` |
| `UnPersistPolicy()` | Remove persistent policies | [sandbox_manager_kit.h](interfaces/inner_api/sandbox_manager/include/sandbox_manager_kit.h) | `ohos.permission.SET_SANDBOX_POLICY` |
| `SetPolicy()` | Set temporary policies | [sandbox_manager_kit.h](interfaces/inner_api/sandbox_manager/include/sandbox_manager_kit.h) | `ohos.permission.SET_SANDBOX_POLICY` |
| `UnSetPolicy()` | Remove temporary policies | [sandbox_manager_kit.h](interfaces/inner_api/sandbox_manager/include/sandbox_manager_kit.h) | `ohos.permission.SET_SANDBOX_POLICY` |
| `StartAccessingPolicy()` | Activate persistent policies | [sandbox_manager_kit.h](interfaces/inner_api/sandbox_manager/include/sandbox_manager_kit.h) | `ohos.permission.SET_SANDBOX_POLICY` |
| `StopAccessingPolicy()` | Deactivate persistent policies | [sandbox_manager_kit.h](interfaces/inner_api/sandbox_manager/include/sandbox_manager_kit.h) | `ohos.permission.SET_SANDBOX_POLICY` |
| `CheckPersistPolicy()` | Check if policies are persisted | [sandbox_manager_kit.h](interfaces/inner_api/sandbox_manager/include/sandbox_manager_kit.h) | None |
| `CheckPolicy()` | Check if policies exist in MAC layer | [sandbox_manager_kit.h](interfaces/inner_api/sandbox_manager/include/sandbox_manager_kit.h) | None |

### Error Codes

Error codes are defined in [sandbox_manager_err_code.h](interfaces/inner_api/sandbox_manager/include/sandbox_manager_err_code.h)

**Common Error Codes:**

| Error Code | Value | Description |
|------------|-------|-------------|
| `ERR_OK` | 0 | Success |
| `ERR_API_FAILED` | -1 | API call failed |
| `ERR_PARAM_INVALID` | 2 | Invalid parameter (e.g., empty path, invalid mode) |
| `ERR_PERMISSION_DENIED` | 201 | Permission denied (missing `ohos.permission.SET_SANDBOX_POLICY`) |
| `ERR_POLICY_SIZE_EXCEED` | 401 | Policy batch size exceeds 500 limit |
| `ERR_DB_FAIL` | 501 | Database operation failed |
| `ERR_MAC_FAIL` | 601 | MAC layer operation failed |

### Policy Types

Policy information structures and enums are defined in [policy_info.h](interfaces/inner_api/sandbox_manager/include/policy_info.h):

| Type | Description |
|------|-------------|
| `PolicyInfo` | Policy information structure |
| `SandboxRetType` | Policy return value type |
| `OperateMode` | Operation mode (READ/WRITE/CREATE/DELETE/REVOKE/DENY_READ/DENY_WRITE) |

---

## Architecture Design

### Core Components

| Component | Location | Responsibility |
|-----------|----------|----------------|
| SandboxManagerService | services/sandbox_manager/main/cpp/src/service/ | Main service, SystemAbility implementation |
| PolicyInfoManager | services/sandbox_manager/main/cpp/src/service/ | Core policy management logic |
| SandboxManagerRDB | services/sandbox_manager/main/cpp/src/database/ | RDB database operations |
| MacAdapter | services/sandbox_manager/main/cpp/src/mac/ | MAC layer security adaptation |

---

## Policy Lifecycle Management

### Persistent vs Temporary Policies

Sandbox Manager provides two types of policies with different lifecycles and use cases:

| Aspect | Persistent Policies | Temporary Policies |
|--------|---------------------|-------------------|
| **API** | `PersistPolicy()` / `UnPersistPolicy()` | `SetPolicy()` / `UnSetPolicy()` |
| **Storage** | RDB database | Memory only |
| **Lifecycle** | Until app uninstallation | Current app lifecycle only |
| **Activation** | Requires `StartAccessingPolicy()` | Immediate (auto-activated) |
| **Persistence** | Survives app restart | Lost on app restart |
| **Use Case** | Long-term file sharing needs | Temporary/session-based access |

---

### Persistent Policy Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│ 1. PERSIST PHASE (PersistPolicy)                             │
│    - Policy stored in RDB database                          │
│    - Survives app restarts                                   │
│    - Valid until app uninstallation                          │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. ACTIVATION PHASE (StartAccessingPolicy)                  │
│    - Policy loaded into MAC layer                            │
│    - Takes effect immediately                                │
│    - File access granted                                     │
└─────────────────────────────────────────────────────────────┘
                            ↓
                    ┌───────────────┐
                    │  Active State │  ← Policy is effective
                    └───────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. DEACTIVATION PHASE (StopAccessingPolicy)                 │
│    - Policy removed from MAC layer                           │
│    - File access revoked                                     │
│    - Still in database (can be reactivated)                  │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. CLEANUP PHASE (UnPersistPolicy)                           │
│    - Policy removed from database                            │
│    - Permanently deleted                                     │
└─────────────────────────────────────────────────────────────┘
```

---

### Temporary Policy Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│ 1. SET PHASE (SetPolicy)                                     │
│    - Policy stored in memory only                             │
│    - Auto-activated immediately                               │
│    - Takes effect right away                                  │
└─────────────────────────────────────────────────────────────┘
                            ↓
                    ┌───────────────┐
                    │  Active State │  ← Policy is effective
                    └───────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. AUTO-UNSET PHASE (On app lifecycle end)                   │
│    - Automatically revoked when:                             │
│      • App process terminates                                │
│      • System reboots                                        │
│      • Explicitly called UnSetPolicy()                       │
└─────────────────────────────────────────────────────────────┘
```

---

## Common Pitfalls

### Pitfall 1: Exceeding Policy Size Limit

**Problem Description**: The size limit of `std::vector<PolicyInfo>` is 500, exceeding this will cause the call to fail.

**Incorrect Example**:
```cpp
std::vector<PolicyInfo> policies;
// Loop to add more than 500 policies...
for (int i = 0; i < 1000; i++) {
    policies.push_back(policy);
}
int32_t ret = SandboxManagerKit::PersistPolicy(policies, results); // Fails
```

**Correct Approach**:
```cpp
const size_t MAX_POLICY_SIZE = 500;
std::vector<PolicyInfo> policies;
// Process in batches
for (size_t i = 0; i < allPolicies.size(); i += MAX_POLICY_SIZE) {
    size_t batchEnd = std::min(i + MAX_POLICY_SIZE, allPolicies.size());
    std::vector<PolicyInfo> batch(allPolicies.begin() + i, allPolicies.begin() + batchEnd);
    int32_t ret = SandboxManagerKit::PersistPolicy(batch, results);
}
```

### Pitfall 2: Missing Permission Check

**Problem Description**: Calling API without checking permissions causes runtime failure.

**Correct Approach**:
- `SetPolicy` requires `ohos.permission.SET_SANDBOX_POLICY` permission

### Pitfall 3: Persistent Policy Not Activated

**Problem Description**: After calling `PersistPolicy`, the policy is only stored in the database and not loaded into the MAC layer, so it won't take effect.

**Correct Approach**:
```cpp
// 1. Persist policy
int32_t ret = SandboxManagerKit::PersistPolicy(policies, results);

// 2. Activate policy (load to MAC layer)
ret = SandboxManagerKit::StartAccessingPolicy(policies, results);
```

### Pitfall 4: Misunderstanding Temporary Policy Lifecycle

**Problem Description**: Mistakenly believing that policies set by `SetPolicy` are persistent.

**Explanation**:
- Persistent policies (`PersistPolicy`): Valid until application uninstallation
- Temporary policies (`SetPolicy`): Valid only during the current application lifecycle

---

## Development Guide

### Policy Lifecycle

```
    Set Persistent Policy (PersistPolicy)
         ↓
    Store to RDB Database
         ↓
    Activate Policy (StartAccessingPolicy)
         ↓
    Load to MAC Layer (Effective)
         ↓
    Deactivate Policy (StopAccessingPolicy)
         ↓
    Remove from MAC Layer (Still in database)
         ↓
    Remove Persistent Policy (UnPersistPolicy)
         ↓
    Delete from Database
```

---

## Feature Flags

| Feature Flag | Default | Description |
|--------------|---------|-------------|
| sandbox_manager_feature_coverage | false | Code coverage support |
| sandbox_manager_process_resident | false | Process resident mode |
| sandbox_manager_with_dec | false | DEC (Data Execution Prevention) support |
| sandbox_manager_dec_ext | false | DEC extension support |

---

## Version History

| Version | Date | Changes | Maintainer |
|---------|------|---------|------------|
| v1.0 | 2026-01-31 | Initial version | AI Assistant |
