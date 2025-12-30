# ONVIF CLI

Discover, manage, and interact with your ONVIF IP cameras directly from the terminal. A powerful, standalone utility for scripting and device management.

## Features

- autodiscovery of onvif devices/cams in the local network
- device database (credentials, aliases, urls)
- device list (--check)
- device describe (profiles, capabilities, device-info, system-time, services, event-properties)
- device events
- media streaming (play via VLC)
- media capture (snapshot and record via ffmpeg)

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
```

### Play live stream

Launch VLC to view the live stream for a device or specific profile.

```bash
# Play default profile
onvif play cam-21

# Play specific profile
onvif play cam-21 --profile profile_2
```
*Underlying Spec*: `vlc rtsp://admin:pass@IP:554/stream1`

### Take a snapshot

Capture a single JPEG frame using ffmpeg.

```bash
# Snapshot with auto-generated filename
onvif snapshot cam-21

# Specify output file
onvif snapshot cam-21 --out capture.jpg
```
*Underlying Spec*: `ffmpeg -y -i <rtsp_url> -vframes 1 <outFile>`

### Record stream

Record the stream directly to disk without re-encoding.

```bash
# Basic recording
onvif record cam-21

# Segmented recording (every 1 hour)
onvif record cam-21 --segment
```
*Underlying Spec*: `ffmpeg -rtsp_transport tcp -i <rtsp_url> -map 0 -c copy -f segment -segment_time 3600 -segment_format matroska -reset_timestamps 1 "capture-%03d.mkv"`

### Device describe

Export the complete camera configuration (resolution, codecs, analytics, etc.) as structured JSON:

```bash
λ onvif describe cam-21 --device-info --system-time | jq .
```
```json
{
  "deviceInfo": {
    "Manufacturer": "tp-link",
    "Model": "Tapo C200",
    "FirmwareVersion": "1.3.1 Build 250910 Rel.65017n",
    "SerialNumber": "7461a8dd",
    "HardwareId": "5.0"
  },
  "systemTime": {
    "SystemDateAndTime": {
      "DateTimeType": "NTP",
      "DaylightSavings": "true",
      "TimeZone": {
        "TZ": "GMT-02:00"
      },
      "UTCDateTime": {
        "Time": {
          "Hour": "17",
          "Minute": "19",
          "Second": "2"
        },
        "Date": {
          "Year": "2025",
          "Month": "12",
          "Day": "28"
        }
      },
      "LocalDateTime": {
        "Time": {
          "Hour": "19",
          "Minute": "19",
          "Second": "2"
        },
        "Date": {
          "Year": "2025",
          "Month": "12",
          "Day": "28"
        }
      }
    }
  }
}
```

### Global Options

Standard help and version flags:

* `-h, --help`: Show help message and exit.
* `-V, --version`: Print version information and exit.

### Device Options

All commands that interact with a device support these overrides:

* `-d, --device=<device>`: Target device alias or URL.
* `-u, --user=<user>`: Override username for this command.
* `-p, --pass=<pass>`: Override password (masked by default).
* `-t, --timeout=<n>`: Network timeout in seconds (default: 5).
* `-r, --retries=<n>`: Number of discovery retries.
* `--dry-run`: Log the command that would be executed without running it.

### Development options

Standard flags for execution control and logging:

* `-v, --verbose`: Increase verbosity levels (-v INFO, -vv DEBUG, -vvv TRACE).
* `-q, --quiet`: Decrease verbosity levels (-q WARN, -qq ERROR).
* `-de, --debug`: Detailed logging with class names and timestamps.
* `-tr, --trace`: Show full stack traces for errors.
* `-co, --[no-]color`: Enable colored output (default: true).
* `--workdir=<dir>`: Change base folder for config and logs.

## Development

### Requirements

* **Multi-Interface Discovery**: Launch UDP probes in parallel across all valid IPv4 interfaces.
* **SOAP & WS-Security**: Communication is handled via manual XML templates to eliminate heavy dependencies, using `PasswordDigest` (Nonce + Timestamp + SHA1) for secure authentication.

### Testing

Run tests with `jbang onvif_test.java`

```bash
λ jbang onvif_test.java
Executing command with arguments:
Found 3 profiles.
Profile: mainStream      | Token: profile_1  | Res: 1920x1080  | URI: rtsp://192.168.1.21:554/stream1
Profile: minorStream     | Token: profile_2  | Res: 1280x720   | URI: rtsp://192.168.1.21:554/stream2
Profile: jpegStream      | Token: profile_3  | Res: 640x360    | URI: rtsp://192.168.1.21:554/stream8

╷
└─ JUnit Jupiter ✔
   ├─ onvif_test$CommandTests ✔
   │  ├─ streamByDeviceAliasPrintsProfiles() ✔
   │  ├─ deviceUseSetsActiveAlias() ✔
   │  ├─ deviceListShowsHeader() ✔
   │  └─ dumpByDeviceAliasPrintsProfiles() ✔
   └─ onvif_test$SoapEnvelopeTests ✔
      ├─ calculateDigestUsesDecodedNonce() ✔
      └─ buildSoapEnvelopeContainsBodyAndUsername() ✔

Test run finished after 2244 ms
[         3 containers found      ]
[         0 containers skipped    ]
[         3 containers started    ]
[         0 containers aborted    ]
[         3 containers successful ]
[         0 containers failed     ]
[         6 tests found           ]
[         0 tests skipped         ]
[         6 tests started         ]
[         0 tests aborted         ]
[         6 tests successful      ]
[         0 tests failed          ]
```

### Running locally

```bash
git clone https://github.com/raisercostin/onvif.git
cd onvif
jbang onvif.java discover
```

## History

- 2025-12-24 - initial version for discovery, device management
- 2025-12-26 - stream discovery
- 2025-12-28 - add device events pulling
- 2025-12-30 - implement play, snapshot, record; refine CLI help structure

## Roadmap

### DONE
- [x] **Discovery**: Autodiscovery of ONVIF devices via UDP multicast probing.
- [x] **Device Management**: Secure storage of credentials and aliases in `~/.onvif/config.yaml`.
- [x] **Stream Discovery**: Enumeration of RTSP URIs for all device profiles.
- [x] **Events**: Real-time event subscription via PullPoint model.
- [x] **Native Recording**: Capture video streams directly to disk using ffmpeg.
- [x] **Snapshot**: Capture static JPEG images from the main stream.
- [x] **Stream Viewer**: Launch VLC for live stream playback.

### Upcoming Features & Target Syntax
The following commands act as the specification for planned features.

- [ ] **PTZ Control**: Pan, Tilt, and Zoom control for supported devices.
  - *Target*: `onvif ptz [device-alias] --move-left`

## Thanks

- Simple, sane and state of the art cli commands: git, kube, adb, helm, docker swarm.
- AgentDVR for showing what is possible with onvif devices including autodiscovery
  - https://www.ispyconnect.com/download
  - https://github.com/ispysoftware/iSpy
- ONVIF(Open Network Video Interface Forum) standards
  - https://www.onvif.org/wp-content/uploads/2016/12/ONVIF_WG-APG-Application_Programmers_Guide-1.pdf
  - https://www.onvif.org/specs/core/ONVIF-Core-Specification-v1712.pdf

## Notes

> The ONVIF PullPoint model is a long‑poll loop: the client sends PullMessages with a timeout, the device holds the HTTP connection until it has events or the timeout expires, then the client immediately issues another PullMessages. Many devices cap the timeout (often ~10s) regardless of what you ask, so you end up reconnecting every ~10s. For fewer reconnects, the alternative is the push/Notify model (device calls back to your endpoint), but that requires exposing a listener and is less reliable in NAT setups. Usually they have a short buffer, if any. PullPoint is “fetch what’s available now” with a per‑subscription queue; devices often keep a small FIFO and drop old events. There’s no standard “give me the last hour” query in ONVIF events. You can set MessageLimit and use short timeouts to drain the current queue, but if the device didn’t buffer them (or already dropped them), you can’t retrieve older events. Some vendors have proprietary history APIs, but it’s not part of the core ONVIF Events spec.
