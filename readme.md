# ONVIF CLI

A professional, hardened command-line utility for discovering and managing ONVIF-compatible IP cameras, built with Java and JBang.

## Usage



### Installation & Execution

1. install jbang - https://www.jbang.dev/documentation/jbang/latest/installation.html#build-tools (on windows: `scoop install https://github.com/jbangdev/scoop-bucket/blob/main/bucket/jbang.json`)
2. run without install `
jbang https://raw.githubusercontent.com/raisercostin/onvif/onvif.java discover`
3. install `jbang app install --name onvif https://raw.githubusercontent.com/raisercostin/onvif/onvif.java`
 and then run
 `onvif discover`


### List & Discover ONVIF devices/cams

List all devices (registred and discovered) and check also availability and status.

```bash
λ onvif.java device list --all --check
Scanning network...
Found configured device: http://192.168.1.247:80/onvif/device_service
Found configured device: http://192.168.1.81:2020/onvif/device_service
Found 0 new devices, confirmed 2 devices, configured 5 devices.
   ALIAS           URL                                           USER       STATUS
------------------------------------------------------------------------------------------
  cam-247              http://192.168.1.247:80/onvif/device_service admin      ✅ AUTHORIZED
* cam-21               http://192.168.1.21:2020/onvif/device_service costin     ✅ AUTHORIZED
  cam-81               http://192.168.1.81:2020/onvif/device_service localadmin ✅ AUTHORIZED
  cam-wrong-ip         http://192.168.1.111:2020/onvif/device_service admin      ❌ TIMEOUT. WRONG IP?
  cam-wrong-port       http://192.168.1.81:80/onvif/device_service localadmin ❌ REFUSED. WRONG PORT?
  cam-wrong-creds      http://192.168.1.81:2020/onvif/device_service admin      � AUTH REQ
```

### Register and configure credentials

Autoregister discovered devices.

```bash
λ onvif device register
Found configured device: http://192.168.1.247:80/onvif/device_service
Found configured device: http://192.168.1.81:2020/onvif/device_service
Found configured device: http://192.168.1.21:2020/onvif/device_service
Found 0 new devices, confirmed 3 devices, configured 3 devices.
```

Update device credentials
```bash
λ onvif.java device list --check
λ onvif device update cam-81 --user localadmin --pass pass1
λ onvif.java device list --check
```

### List device/cam streams

```bash
> onvif device use cam-21
> onvif stream
Found 3 profiles.
Profile: mainStream      | Token: profile_1  | Res: 1920x1080  | URI: rtsp://192.168.1.21:554/stream1
Profile: minorStream     | Token: profile_2  | Res: 1280x720   | URI: rtsp://192.168.1.21:554/stream2
Profile: jpegStream      | Token: profile_3  | Res: 640x360    | URI: rtsp://192.168.1.21:554/stream8
> onvif stream -d cam-21
...same
> onvif stream cam-21
...same
```

#### JSON Dump

Export the complete camera configuration (resolution, codecs, analytics, etc.) as structured JSON:

```bash
onvif dump <device> --quiet | jq .
```

### Global Options

All commands inherit standard flags for execution control and logging:

* `-v, --verbose`: Increase verbosity levels (more v can be given -vvv is DEBUG, -vvvv is TRACE).
* `-q, --quiet`: Decrease verbosity levels (more q can be given -q is WARN, -qq is ERROR).
* `-de, --debug`: Displays full logs with source, category and other details.
* `-tr, --trace`: Show full stack traces for errors.
* `-co, --[no-]color`: Enable colored output (default: true).

## Development

### Requirements

* **Multi-Interface Discovery**: Launch UDP probes in parallel across all valid IPv4 interfaces.
* **SOAP & WS-Security**: Communication is handled via manual XML templates to eliminate heavy dependencies, using `PasswordDigest` (Nonce + Timestamp + SHA1) for secure authentication.

### TDD

Run tests with `jbang onvif_test.java`

### Running locally

```bash
git clone https://github.com/raisercostin/onvif.git
cd onvif
jbang onvif.java discover
```
