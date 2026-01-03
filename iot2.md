# iot2.md

Probe-based IoT CLI that delegates to ONVIF, Innova, and Modbus tools while exposing a unified probe model.

## Origin / History

This CLI was grown in-session using TDD to unify existing ONVIF, Modbus, and Innova behaviors without changing their sources. The implementation delegates to the existing CLIs and adds a probe layer plus prefixed options for probe-all discovery.

## Run

```bash
jbang run iot2.java --help
jbang run iot2.java probes
```

## Probes

List available probes:

```bash
jbang run iot2.java probes
```

List actions for a probe:

```bash
jbang run iot2.java probe onvif actions
jbang run iot2.java probe modbus actions
```

## Probe All

Run discovery across all probes:

```bash
jbang run iot2.java probe
```

Probe-all with per-probe options (prefix with `--<probe>.`):

```bash
jbang run iot2.java probe --modbus.ports=8899,502
```

## Per-Probe Commands

Discover:

```bash
jbang run iot2.java probe onvif discover
jbang run iot2.java probe innova discover
jbang run iot2.java probe modbus discover --modbus.ports=8899,502
```

Check (probe = discover or check device):

```bash
jbang run iot2.java probe onvif check cam-21
jbang run iot2.java probe innova check 192.168.1.50
jbang run iot2.java probe modbus check -tcp 192.168.1.7 -p 502
```

Describe:

```bash
jbang run iot2.java probe onvif describe cam-21
jbang run iot2.java probe modbus describe -tcp 192.168.1.7
```

Backup/restore (Modbus only):

```bash
jbang run iot2.java probe modbus backup -d chofu --config mapping.csv --output backup.csv
jbang run iot2.java probe modbus restore -d chofu --config mapping.csv --input backup.csv
```

Raw pass-through to the underlying CLI:

```bash
jbang run iot2.java probe onvif raw device list
jbang run iot2.java probe modbus raw discover --subnet 192.168.1 --ports 502
```
