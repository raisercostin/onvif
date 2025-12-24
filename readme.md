# ONVIF CLI

A professional, hardened command-line utility for discovering and managing ONVIF-compatible IP cameras, built with Java and JBang.

## Usage

### Installation & Execution

You can run or install ONVIF CLI using [JBang](https://www.jbang.dev/) without needing to manually manage a Java project or dependencies.

**1. Direct Execution (Remote)**
Run the script directly from GitHub without downloading it:

```bash
jbang https://raw.githubusercontent.com/raisercostin/onvif/onvif.java discover
```

**2. Local Installation**
Install the script as a global binary on your system:

```bash
jbang app install --name onvif https://raw.githubusercontent.com/raisercostin/onvif/onvif.java
# Now you can just use 'onvif' anywhere
onvif discover
```

### Commands

jbang onvif.java stream http://192.168.1.247:80/onvif/device_service -u admin -p ***
jbang onvif.java dump http://192.168.1.247:80/onvif/device_service -u admin -p ***

#### Discovery

Scans the local network on all active interfaces to identify ONVIF services:

```bash
onvif discover --timeout 5 --retries 3
```

#### Stream URI

Retrieve RTSP links for all available profiles (High/Low Res):

```bash
onvif stream <SERVICE_URL> -u <user> -p <pass>
```

#### JSON Dump

Export the complete camera configuration (resolution, codecs, analytics, etc.) as structured JSON:

```bash
onvif dump <SERVICE_URL> -u <user> -p <pass> --quiet | jq .
```

### Global Options

All commands inherit standard flags for execution control and logging:

* `-v, --verbose`: Enables Debug logs.
* `-vv`: Enables Trace logs.
* `-q, --quiet`: Silent mode; suppresses info logs, outputting only raw data to STDOUT.
* `--debug`: Displays full troubleshooting details for network handshakes.

---

## Development

### Architectural Principles

The script is designed following strict hardening standards for CLI utilities:

* **Centralized Logging Control**: Utilizes `RichLogback` to configure the logging context in the first line of the `main` method, ensuring verbosity consistency before any subcommand executes.
* **Sneaky Throw Pattern**: Implements `throw sneakyThrow(e)` to propagate checked exceptions without polluting method signatures with `throws` clauses. This avoids the anti-pattern of logging and throwing an exception simultaneously.
* **Multi-Interface Discovery**: Uses `CompletableFuture` to launch UDP probes in parallel across all valid IPv4 interfaces, preventing blocks caused by inactive or virtual network adapters.
* **SOAP & WS-Security**: Communication is handled via manual XML templates to eliminate heavy dependencies, using `PasswordDigest` (Nonce + Timestamp + SHA1) for secure authentication.

### Running locally

```bash
git clone https://github.com/raisercostin/onvif.git
cd onvif
jbang onvif.java discover
```

### Adding New Commands

To extend the utility, add a method annotated with `@Command` inside the `MainCommand` static class. It will automatically inherit `BaseOptions` and the logging context.

```java
@Command(description = "Description of the new action")
public void myNewAction(@Parameters String param) {
    try {
        // Business logic here
    } catch (Exception e) {
        throw sneakyThrow(e);
    }
}
