# IoT Context: Unified ONVIF and Innova CLI

## Project Overview
This project provides a single command-line interface (CLI) for discovering and managing ONVIF cameras and Innova ventiloconvertors. It is designed as a single-file JBang script that shares a unified device registry and configuration file.

## Key Features
- **Unified Discovery:** Scans for ONVIF and Innova devices in one command.
- **Device Registry:** Stores device aliases and credentials in a shared YAML config.
- **Status Checks:** Reports device status via protocol-specific checks.

## Building and Running

Since this project uses JBang, there is no traditional build step. The source files are compiled and executed on the fly.

### Prerequisites
- **Java:** JDK 11 or higher.
- **JBang:** Must be installed and available in the path.

### Execution
Run the main application:
```bash
jbang run iot.java [COMMAND] [FLAGS]
```

**Common Commands:**
*   `jbang run iot.java discover` - Scan for ONVIF and Innova devices.
*   `jbang run iot.java device list` - List registered devices.
*   `jbang run iot.java device list --check` - List devices with live status checks.
*   `jbang run iot.java device add [alias] --type onvif --url [url] -u [user] -p [pass]` - Add a device.
*   `jbang run iot.java device register` - Interactive discovery and registration.

## Key Files

*   **`iot.java`**: The core CLI entry point. Defines shared models, protocol discovery, and device management commands.
*   **`com/namekis/utils/RichCli.java`**: Shared utility for logging and console formatting.

## Development Conventions

*   **Dependency Management:** Dependencies declared via JBang `//DEPS` directives.
*   **Architecture:** Protocol implementations register into a shared registry for discovery and status checks.
*   **Configuration:** Persistent configuration stored in YAML at `~/.onvif/iot_config.yaml`.
