# Project Development Log

## 2026-01-02: Finish-Session Docs and Workflow Updates
**Agent:** Codex | **Goal:** Document the IoT CLI and align workflow expectations.

### Summary
Documented the new IoT CLI in `iot.md` and updated workflow practices to treat "finish session" as a full reload-log-commit flow with commit bodies. Captured the need for companion docs when introducing a main script.

### Key Changes
- **Docs**: Added `iot.md` with usage, features, and configuration details.
- **Workflow**: Updated `.agent/practice-workflow.md` to require agent reloads and commit bodies on finish-session requests.
- **Practices Log**: Recorded the workflow change in `.agent/DEVLOG.md`.

### Verification (Walkthrough)
1. Not run (not requested).

### Meta (Reflections)
- **Good**: Explicit finish-session guidance reduces missed documentation steps.
- **Bad**: Previous commit lacked a body, so the workflow expectation needed to be clarified.
- **Ugly**: N/A

## 2026-01-02: Add Unified IoT CLI
**Agent:** Codex | **Goal:** Introduce a combined ONVIF/Innova CLI with shared discovery and config.

### Summary
Added `iot.java` as a single entry point for ONVIF and Innova devices, including shared models, a unified YAML config, and discovery across protocols. Implemented device management commands to list, add, and interactively register devices.

### Key Changes
- **IoT CLI**: Created `iot.java` with Picocli subcommands for discovery and device management.
- **Config**: Persisted unified device profiles to `~/.onvif/iot_config.yaml`.
- **Protocols**: Added ONVIF and Innova protocol implementations under a shared registry for discovery and status checks.

### Verification (Walkthrough)
1. Not run (not requested).

### Meta (Reflections)
- **Good**: Centralizing protocol discovery makes it easier to add new device types later.
- **Bad**: No verification run in this session.
- **Ugly**: N/A

## 2026-01-01: Environment Standardization, Log Consolidation & Tool Refinement
**Agent:** Gemini CLI | **Goal:** Finalize documentation, project environment, and release Modbus.

### Summary
Created `.editorconfig` to enforce formatting standards, consolidated fragmented `*_walkthrough.md` files into the central `DEVLOG.md`, and refined project practices to mandate modern tools like `fd` and `rg`. Renamed documentation files for consistency and GitHub compatibility.

### Key Changes
- **Environment**: Added `.editorconfig` with standard whitespace and indentation rules (4 spaces for Java, 2 for others).
- **Modbus Documentation**: Renamed `modbus_readme.md` to `modbus.md`.
- **Cleanup**: Deleted `innova_walkthrough.md` and `modbus_walkthrough.md` after consolidating their verification and meta history into this file.
- **Practices**: Updated `practice-tools.md` to prefer `fd` over `find` and documented `which -a` for debugging binary collisions.
- **Agent Practices**: Renamed `.agent/practice-index.md` to `.agent/README.md` for GitHub compatibility.
- **Tools**: Established `bashw` and `fd`/`rg` as the standard toolset for development.

### Verification (Walkthrough)
1. `ls .editorconfig`: Verify file exists.
2. `bashw -c "fd walkthrough"`: Confirm redundant files are removed.
3. `bashw -c "ls modbus.md"`: Confirm the main documentation exists.
4. `bashw -c "ls .agent/README.md"`: Confirm the agent practice index is renamed.

### Meta (Reflections)
- **Good**: Using `fd` instead of `find` is much cleaner and avoids the Windows path collision issues. Consolidating into a single `DEVLOG.md` significantly reduces root directory clutter.
- **Bad**: 
    - **Documentation Fragmentation**: Having separate walkthrough files led to "lost" history when they were deleted. Consolidation into `DEVLOG.md` prevents this.
    - **Tool Collisions**: Initial reliance on `find` caused failures on Windows. Switching to `fd` resolved this.
- **Ugly**: 
    - **PowerShell vs Bash**: The agent repeatedly defaulted to PowerShell syntax (`ls`, `mv`) which behaves differently than GNU tools. Explicitly using `bashw -c` or `which -a` is the only robust fix.
    - **Regex Stack Overflow**: Attempting complex regex replacements on large Java files caused agent tool failures. The solution was full file rewrites for reliable cleaning.

## 2026-01-01: Modbus CLI Implementation & Practice Standardization
**Agent:** Gemini CLI | **Goal:** Port Modbusync to JBang CLI and cleanup project practices.

### Summary
Rewrote the multi-module Maven `Modbusync` project into a single-file `modbus.java` JBang script. Implemented discovery, device management, and CSV backup/restore. Standardized and generalized development practices in the `.agent` repository.

### Key Changes
- **Modbus Tool**: Created `modbus.java` with `picocli` and `j2mod`.
- **Discovery**: Added parallel TCP scanning for port 502.
- **Device Management**: Added `device` subcommand with YAML persistence (`~/.modbus/config.yaml`).
- **Backup/Restore**: Implemented CSV logic with Jackson, including optional config fallbacks and stdout support.
- **Practices**: Consolidated and generalized all `.agent` markdown files into a Good/Bad/Ugly structure.
- **Workflow**: Established `DEVLOG.md` as the source of truth for project history.

### Verification (Walkthrough)
1. **Compilation**: `jbang run modbus.java --help` (Verify CLI help structure and availability of standard options).
2. **Automated Tests**: `jbang run modbus_test.java` (All 8 integration tests pass).
3. **Manual Check**: `jbang run modbus.java backup` (Verify default fallback to Holding 0-9 and stdout correctly).
4. **Device Check**: `jbang run modbus.java device add test -tcp 127.0.0.1` followed by `device list`.

### Meta (Reflections)
- **Good**: 
    - **Transitioning to DEVLOG**: Significantly improved project clarity.
    - **Test-Driven Stability**: Writing `modbus_test.java` with `AssertJ` provided a safety net during the major refactoring of `DeviceOptions`.
    - **Robust CSV Handling**: Using `Jackson` with `CsvSchema` proved much cleaner than manual parsing for legacy metadata headers.
- **Bad**: 
    - **Mega-Commit**: Accidental inclusion of non-source assets; refined `practice-workflow.md` to prevent this.
    - **Library Version Mismatches**: Assumptions about `j2mod` 3.x exposing static constants (`SerialParameters.NO_PARITY`) led to compilation failures (resolved via integer mapping).
- **Ugly**: 
    - **Shell Friction**: Windows path friction and `powershell` tool defaults required explicit `bashw` shims and forward-slash conventions.
    - **Context Loss**: Initial attempt to read chat history JSON failed due to path restrictions, requiring reliance on context memory.

### Documentation
Refer to [modbus.md](modbus.md) for the complete command reference.

## 2025-12-31: Innova Ventiloconvertor Integration
**Agent:** Gemini CLI | **Goal:** Implement Innova 2.0 / AirLeaf control.

### Summary
Implemented a new CLI tool `innova.java` to discover, manage, and control Innova 2.0 / AirLeaf ventiloconvertors on the local network.

### Key Changes
- **New Tool**: Created `innova.java` mirroring the architecture of `onvif.java`.
- **Discovery**: Implemented subnet scanning and persistent device aliases.
- **Control**: Added `status` and `set` commands for remote control.
- **Data Mapping**: Fixed JSON mapping for nested `RESULT` objects and scaled temperature integers.

### Verification (Walkthrough)
1. **Discovery**: `innova.java discover` finds devices.
2. **Status**: `innova.java device list --check` reports correct temperature (e.g. 22.2°C).
3. **Persistence**: Aliases are saved to `~/.innova/config.yaml`.

### Meta (Reflections)
- **Good**: Reusing `RichCli` allowed for rapid development of consistent UX.
- **Bad**: Initial JSON mapping failed on integer scaling (reading 222 as 222°C instead of 22.2°C).
