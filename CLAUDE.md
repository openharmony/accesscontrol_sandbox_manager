# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Sandbox Manager is a system service that manages file sharing rules between application sandboxes. It provides persistent and temporary policy management for inter-app file access.

**Language**: C++
**Build System**: GN (Generate Ninja)
**Subsystem**: accesscontrol
**Component**: sandbox_manager

## Build Commands
# Build the module

./build.sh --product-name {product_name} --build-target sandbox_manager

## Test Structure

Tests are organized by component:
- `frameworks/inner_api/sandbox_manager/test` - SDK API tests
- `frameworks/test` - Framework layer tests
- `services/sandbox_manager/test` - Service layer tests
- `test/fuzztest/` - Fuzz tests

Unit test targets use `ohos_unittest` and are grouped under `sandbox_manager_build_module_test`.

## Architecture
### Layered Structure

interfaces/inner_api/sandbox_manager/    # Public API definitions
  ├── include/                            # Header files (sandbox_manager_kit.h, policy_info.h, etc.)
  └── src/                                # SDK implementation

frameworks/                                # Framework layer
  ├── common/                             # Shared utilities
  ├── sandbox_manager/                    # Framework implementation
  └── inner_api/sandbox_manager/          # Inner API framework

services/                                  # Service layer
  ├── common/                             # Service utilities
  └── sandbox_manager/main/               # Main service implementation (SystemAbility)

### Key Components

1. **SandboxManagerService** (`services/sandbox_manager/main/cpp/src/`)
   - SystemAbility-based main service
   - Handles IPC communication and policy management

2. **SandboxManagerKit** (`interfaces/inner_api/sandbox_manager/src/`)
   - C++ API for internal system use
   - Provides static methods for policy operations

3. **PolicyInfoManager**
   - Core policy management logic
   - Handles persistent and temporary policies

4. **RDB Storage** (`services/sandbox_manager/main/cpp/src/database/`)
   - Relational database for policy persistence

5. **MAC Layer** (`services/sandbox_manager/main/cpp/src/mac/`)
   - Message Authentication Code and security enforcement

## Public API (SandboxManagerKit)

Main header: `interfaces/inner_api/sandbox_manager/include/sandbox_manager_kit.h`

### Persistent Policy Operations
- `PersistPolicy()` - Add persistent rules (valid until app uninstall)
- `UnPersistPolicy()` - Remove persistent rules
- `CheckPersistPolicy()` - Check if policies are persisted

### Temporary Policy Operations
- `SetPolicy()` - Set temporary rules (valid for current app lifecycle)
- `UnSetPolicy()` - Remove temporary rules
- `CheckPolicy()` - Check if policies exist in MAC layer

### Policy Activation
- `StartAccessingPolicy()` - Enable persisted policies
- `StopAccessingPolicy()` - Disable persisted policies
- `StartAccessingByTokenId()` - Auto-load policies for a token

### Utility Operations
- `UnSetAllPolicyByToken()` - Clear all policies for a token
- `CleanPersistPolicyByPath()` - Clean policies by file path
- `CleanPolicyByUserId()` - Clean policies by user ID

## Policy Types (from policy_info.h)

- **SELF_PATH** - Own app file access
- **AUTHORIZATION_PATH** - Authorized file access
- **OTHERS_PATH** - Other app's file access

## Operation Modes

- **READ, WRITE, CREATE, DELETE, REVOKE** - Allow operations
- **DENY_READ, DENY_WRITE** - Deny operations

## Important Constraints

1. **Permissions Required**:
   - `ohos.permission.SET_SANDBOX_POLICY` for SetPolicy
   - `ohos.permission.FILE_ACCESS_PERSIST` for most operations

2. **API Limits**: Maximum 500 policies per std::vector<PolicyInfo>

3. **Policy Lifecycle**:
   - Persistent policies: Valid until app uninstallation
   - Temporary policies: Valid only during current app lifecycle

## Dependencies (from bundle.json)

Key internal dependencies:
- `ability_base`, `access_token`, `bundle_framework`
- `cJSON` (JSON processing)
- `hisysevent` (logging and monitoring)
- `ipc` (inter-process communication)
- `relational_store` (database)
- `samgr` (system ability manager)

## Code Organization Patterns

- Headers in `include/` directories, implementations in `src/` subdirectories
- Test files co-located with implementations
- Each layer has its own `common/` directory for shared utilities
- Database operations in `database/` subdirectory
- MAC security in `mac/` subdirectory

## Feature Flags (defined in sandbox_manager.gni)

- `sandbox_manager_feature_coverage` - Code coverage support
- `sandbox_manager_process_resident` - Process resident mode
- `sandbox_manager_with_dec` - DEC (Data Execution Prevention) support
- `sandbox_manager_dec_ext` - DEC extension support

## Error Codes

Error codes defined in `interfaces/inner_api/sandbox_manager/include/sandbox_manager_err_code.h`

Return results use `SandboxRetType` enum from `policy_info.h`
