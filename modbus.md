# Modbus CLI

A lightweight, single-file CLI tool for discovering, inspecting, and managing Modbus TCP and Serial devices. Designed for quick diagnostics, backups, and scripting.

## Features

- **Discovery**: Scan local subnet for Modbus TCP devices (port 502).
- **Device Management**: Store aliases and connection details (TCP/Serial) in `~/.modbus/config.yaml`.
- **Describe**: Fingerprint devices by reading standard registers (Holding/Input 0-19).
- **Poll**: Continuously monitor specific registers.
- **Backup/Restore**: Dump parameter values to CSV and restore them to the device.

## Installation & Usage

### Prerequisites
*   **Java 17+**
*   **JBang**: `scoop install jbang` (Windows) or see [jbang.dev](https://www.jbang.dev).

### Running
Run directly via JBang:
```bash
jbang run modbus.java <command> [options]
```

## Commands

### 1. Discovery
Scan the local network for devices listening on port 502.

```bash
# Auto-detect subnet and scan
jbang run modbus.java discover

# Scan specific subnet with custom timeout
jbang run modbus.java discover --subnet 192.168.1 --timeout 200
```

### 2. Device Management
Save connection profiles to avoid repeated typing.

```bash
# Add a TCP device
jbang run modbus.java device add my-pump -tcp 192.168.1.10 -p 502 --unit-id 1

# Add a Serial device
jbang run modbus.java device add my-meter -serial /dev/ttyUSB0 --baud 9600 --parity even

# List devices
jbang run modbus.java device list

# Set active device (default for subsequent commands)
jbang run modbus.java device use my-pump
```

### 3. Inspection (Describe & Poll)
Quickly check device status.

```bash
# Fingerprint the active device
jbang run modbus.java describe

# Fingerprint a specific target (ad-hoc)
jbang run modbus.java describe -tcp 192.168.1.50

# Poll specific registers (e.g., Read 5 Holding registers starting at 100)
jbang run modbus.java poll -t holding -a 100 -c 5 --loop 1000
```

### 4. Backup & Restore
Manage configuration using CSV files.

**Backup:**
Reads parameters defined in `modbus.csv` (or specified config) and saves values.
```bash
jbang run modbus.java backup --output backup-2026.csv
```

**Restore:**
Writes values from a CSV back to the device.
```bash
# Dry run first to verify
jbang run modbus.java restore --input backup-2026.csv --dry-run

# Actual restore
jbang run modbus.java restore --input backup-2026.csv
```

## Configuration

### CSV Format
The tool uses a standard CSV format for mapping parameters. Key columns required:
- `Type`: `holding`, `input`, `coil`, `discrete`
- `Address`: Register address (0-based)
- `Value` / `ModbusValue`: The value to write (for restore)

### Persistence
Configuration is stored in `~/.modbus/config.yaml`.

## Development

**Testing:**
```bash
jbang run modbus_test.java
```
