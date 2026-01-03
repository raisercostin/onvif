# iot3.java - Unified Native IoT CLI

`iot3.java` is a self-contained, native Java CLI tool for discovering and managing ONVIF, Modbus, and Innova devices. It replaces the legacy `onvif.java`, `modbus.java`, and `innova.java` scripts with an in-process integration (no shelling out).

## Features
- **Native Integration**: Uses `j2mod` for Modbus, `java.net.http` for Innova/Onvif. No external runtime dependencies beyond JDK and JBang libs.
- **Unified Discovery**: `discover` command scans for all supported protocols in parallel.
- **Common Interface**: All protocols implement a `Probe` interface (`discover`, `checkStatus`, `describe`).

## Usage

### Discovery
Scan local network for devices:
```bash
jbang run iot3.java discover
# or specifiy a subnet
jbang run iot3.java discover --subnet 192.168.1
```

### device Check
Check the status of a specific device (by Alias or URL):
```bash
jbang run iot3.java check <target>
```

### Describe
Dump detailed information (Modbus registers, Onvif Metadata, Innova Status):
```bash
jbang run iot3.java describe <target>
```

## Configuration
Devices are stored in `~/.onvif/iot_config.yaml`.
You can manage them via the `device` subcommand:
```bash
jbang run iot3.java device list
jbang run iot3.java device add my-cam --type onvif --url http://192.168.1.50 ...
```
