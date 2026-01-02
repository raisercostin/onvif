# Innova Context: Ventiloconvertor CLI Project

## Project Overview
This project is a lightweight, command-line interface (CLI) tool for discovering, managing, and controlling Innova 2.0 and AirLeaf ventiloconvertors. Like the ONVIF tool, it is designed to be run as a single-file script using [JBang](https://www.jbang.dev/). The tool communicates directly with devices using their local HTTP REST API.

## Key Features
- **Discovery:** Scans the local network (1-254) for Innova devices via HTTP probing.
- **Management:** Stores device aliases and IP addresses persistently in `~/.innova/config.yaml`.
- **Status:** Retrieves real-time status (Power, Room Temp, Setpoint, Mode, Fan) with correct data mapping (scaling integers to decimals).
- **Control:** commands to set power, temperature, operating mode, and fan speed.

## Building and Running

Since this project uses JBang, there is no traditional build step. The source files are compiled and executed on the fly.

### Prerequisites
- **Java:** JDK 11 or higher.
- **JBang:** Must be installed and available in the path.

### Execution
Run the main application:
```bash
jbang run innova.java [COMMAND] [FLAGS]
```

**Common Commands:**
*   `jbang run innova.java discover` - Scan for devices.
*   `jbang run innova.java device add [alias] --ip [ip]` - Register a device.
*   `jbang run innova.java device list --check` - List devices with live status check.
*   `jbang run innova.java status [alias]` - Get detailed status.
*   `jbang run innova.java set [alias] --power on --temp 22 --mode cooling` - Control device.

## Key Files

*   **`innova.java`**: The core application logic. Contains the CLI definition (Picocli), HTTP client, JSON mapping (`InnovaStatus`, `Result`), discovery logic, and configuration management.
*   **`com/namekis/utils/RichCli.java`**: Shared utility for logging and console formatting.

## Development Conventions

*   **Dependency Management:** Dependencies declared via JBang `//DEPS` (e.g., `info.picocli:picocli`, `com.fasterxml.jackson...`).
*   **Architecture:**
    *   **Simple REST:** Uses Java 11 `HttpClient` for zero-dependency HTTP interactions.
    *   **JSON Mapping:** Manually maps nested `RESULT` objects and handles integer scaling (e.g. `222` -> `22.2`) to ensure accurate readings.
*   **Configuration:** Persistent configuration stored in YAML format in `~/.innova/config.yaml`.
