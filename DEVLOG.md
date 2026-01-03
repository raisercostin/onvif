# Project Development Log

## 2026-01-03: Unified Native IoT CLI
**Agent:** Antigravity | **Goal:** Create `iot3.java` as a native, single-file CLI replacing `onvif.java`, `modbus.java`, `innova.java`.

### Summary
Created `iot3.java` with **native** integration for Onvif (UDP/SOAP), Modbus (j2mod), and Innova (HTTP). Replaced the earlier "shell-out" strategy with in-process logic to ensure zero external dependencies (aside from JBang libs). Updated `.gitignore` to exclude large media files.

### Key Changes
- **Native Implementation**: `iot3.java` now directly imports `j2mod` and uses Java `HttpClient` / `DatagramSocket` instead of shelling out.
- **Probe Interface**: Unified `discover`, `checkStatus`, `describe` contract across all protocols.
- **Testing**: Added `iot3_test.java` validating discovery and command dispatch.
- **Ignore Rules**: Added `*.mkv`, `*.jpg` to `.gitignore` to prevent agent context overload.

### Verification (Walkthrough)
1. `jbang run iot3_test.java` -> All tests passed.
2. `jbang run iot3.java discover` -> Validated logic compiles (device output depends on network).

### Meta (Reflections)
- **Good**: Pivot to native integration avoids fragility of shell parsing and process management. `iot3.java` is now a true self-contained tool.
- **Bad**: Compilation error (rogue backticks) slowed down verification.
- **Ugly**: Large capture files (`.mkv` > 1GB) were cluttering the workspace; ignore rules added but deletion was aborted per user request.


## 2026-01-03: Document IoT2 CLI
**Agent:** Codex | **Goal:** Add usage documentation for the probe-based IoT2 CLI.

### Summary
Added `iot2.md` to document probe commands, probe-all usage with prefixed options, and raw pass-through examples.

### Key Changes
- **Docs**: Added `iot2.md` with common commands and examples.

### Verification (Walkthrough)
1. Not run (documentation only).

### Meta (Reflections)
- **Good**: Quick usage examples clarify probe-all and prefixed options.
- **Bad**: N/A
- **Ugly**: N/A

## 2026-01-02: Accept Prefixed Options Without Probe Id
**Agent:** Codex | **Goal:** Allow `probe --modbus.ports=...` without a protocol argument.

### Summary
Adjusted `iot2` probe dispatch so prefixed arguments can be passed without a protocol id and are still routed to the correct probe. Also ensured subcommand parsing treats unmatched options as positional for probe-all flows.

### Key Changes
- **IoT2 CLI**: Handle prefixed args as probe-all when `probeId` is missing or looks like an option in `iot2.java`.

### Verification (Walkthrough)
1. Not run (disk space error during JBang compile).

### Meta (Reflections)
- **Good**: Prefix routing keeps the probe-all experience concise.
- **Bad**: Lack of disk space blocked verification.
- **Ugly**: N/A

## 2026-01-02: Add Probe-All and Modbus Port Prefixes
**Agent:** Codex | **Goal:** Support protocol-less probing and modbus port prefixes.

### Summary
Allowed `iot2 probe` without a protocol to run discovery across all probes and added modbus-prefixed port arguments. Updated tests to cover `--modbus.ports` and probe-all behavior, and verified with JBang.

### Key Changes
- **IoT2 CLI**: Made probe id optional, added probe-all discovery dispatch, and prefixed-argument filtering in `iot2.java`.
- **Modbus Args**: Normalize `--modbus.ports` into Modbus discovery options in `iot2.java`.
- **Tests**: Added/updated integration coverage in `iot2_test.java`.

### Verification (Walkthrough)
1. `jbang iot2_test.java`

### Meta (Reflections)
- **Good**: Prefix-scoped arguments enable protocol-specific discovery in probe-all mode.
- **Bad**: Probe-all tests can be slow due to network scanning.
- **Ugly**: N/A

## 2026-01-02: Support Modbus Probe by Port
**Agent:** Codex | **Goal:** Allow Modbus probe discovery using only a port argument.

### Summary
Added Modbus probe argument normalization so `probe modbus probe -p <port>` triggers discovery rather than requiring a TCP host. Expanded tests to cover the port-only probe path and verified with JBang.

### Key Changes
- **IoT2 CLI**: Normalize Modbus discovery arguments and route port-only probes to discovery in `iot2.java`.
- **Tests**: Added `modbusProbeWithPortRunsDiscovery` in `iot2_test.java`.

### Verification (Walkthrough)
1. `jbang iot2_test.java`

### Meta (Reflections)
- **Good**: Argument normalization preserves Modbus semantics while matching user expectations.
- **Bad**: N/A
- **Ugly**: N/A

## 2026-01-02: Expand IoT2 Probe CLI and Tests
**Agent:** Codex | **Goal:** Complete probe-based IoT2 CLI wiring and run tests.

### Summary
Expanded `iot2.java` with probe-style dispatch (`probe`), raw pass-through execution, and robust argument forwarding for underlying CLIs. Grew `iot2_test.java` with additional probe/action coverage and verified via JBang.

### Key Changes
- **IoT2 CLI**: Added probe-style discovery/check, raw pass-through, and global unmatched argument handling in `iot2.java`.
- **Tests**: Extended `iot2_test.java` to cover Innova actions, raw pass-through, and probe checks.

### Verification (Walkthrough)
1. `jbang iot2_test.java`

### Meta (Reflections)
- **Good**: Using raw pass-through keeps feature parity with existing CLIs while the probe design evolves.
- **Bad**: Picocli option forwarding required parser tuning to avoid unknown option errors.
- **Ugly**: N/A

## 2026-01-02: Introduce Probe-Based IoT CLI Prototype
**Agent:** Codex | **Goal:** Add a probe-based IoT CLI and tests without touching existing sources.

### Summary
Created `iot2.java` as a probe-driven entry point that delegates to ONVIF, Modbus, and Innova CLIs. Added `iot2_test.java` to drive the initial probe list, actions, and integration behavior via CLI calls.

### Key Changes
- **IoT CLI**: Added `iot2.java` with probe registry, action descriptions, and command delegation.
- **Tests**: Added `iot2_test.java` covering probe listing, action listing, and ONVIF/Modbus integration.

### Verification (Walkthrough)
1. Not run (not requested).

### Meta (Reflections)
- **Good**: Delegating to existing CLIs keeps consolidation low-risk while design evolves.
- **Bad**: No automated verification run in this session.
- **Ugly**: N/A

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
