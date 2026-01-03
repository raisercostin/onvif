# IoT CLI (`iot.java`)

A unified, extensible CLI for managing and interacting with various IoT devices (ONVIF, Innova, Modbus).

## Architecture: Probes
The tool is built around a **Probe** architecture. Each protocol (e.g., `onvif`, `modbus`, `innova`) implements a probe that handles:
- **Discovery**: Scanning the network for devices.
- **Liveness**: Checking device status.
- **Description**: Dumping full device configuration or state.
- **Actions**: Protocol-specific operations (PTZ, register polling, etc.).

## Usage

### Discovery
Discover all devices on the local network across all supported probes:
```bash
jbang run iot.java discover
```

For Modbus, you can specify custom ports to scan:
```bash
jbang run iot.java discover --modbus.ports 502,8899
```

### Device Management
List registered devices and check their status:
```bash
jbang run iot.java device list --check
```

Scan the network and show both registered and new devices:
```bash
jbang run iot.java device list --all
```

Automatically register all discovered devices with default credentials:
```bash
jbang run iot.java device autoregister
```

### Actions & Execution
List possible actions for a specific probe:
```bash
jbang run iot.java actions modbus
```

Execute an action on a device:
```bash
jbang run iot.java call <alias> poll -Paddress=0 -Pcount=10
jbang run iot.java call <alias> set -Ppower=on -Ptemp=22.5
```

### Inspection
Dump detailed information about a device:
```bash
jbang run iot.java describe <alias>
```

## Configuration
Configuration is stored in `~/.onvif/iot_config.yaml`. It contains the list of registered devices and their credentials.

## Testing
Run the integration test suite:
```bash
jbang run iot_test.java
```