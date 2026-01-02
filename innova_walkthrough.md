# Innova Ventiloconvertor Integration

Implemented a new CLI tool `innova.java` to discover, manage, and control Innova 2.0 / AirLeaf ventiloconvertors on the local network.

**Key Changes**
-   **New Tool `innova.java`**: A standalone JBang script using Picocli, mirroring the architecture of `onvif.java`.
-   **Discovery & Registration**: Implemented `discover` command to scan subnets and `device add/list/use` commands to manage device aliases persistently in `~/.innova/config.yaml`.
-   **Control & Status**: Added `status` command (reporting power, temp, mode, fan) and `set` command for remote control.
-   **Data Mapping Fix**: Correctly mapped the nested `RESULT` JSON object and scaled integer temperature values (e.g., `222` -> `22.2°C`) to fix initial `0.0` reading issues.
-   **Rich CLI Experience**: Reused `RichCli` for consistent logging, verbosity control, and color output.

**Verification results**
-   **Discovery**: Verified scanning finds devices `192.168.1.138` and `192.168.1.253` on the local network.
-   **Status Check**: Verified `device list --check` correctly reports "OFF" and "22.2°C" (room temp) instead of previous "0.0" errors.
-   **Persistence**: Confirmed device aliases ("living", "timix") are saved and loaded from config.

```bash
$ jbang run innova.java device list --check
  ALIAS           IP              POWER      ROOM       SET        MODE      
--------------------------------------------------------------------------------
* living          192.168.1.138   ON         21.0°C     28.2°C     Dehumid   
  timix           192.168.1.253   OFF        22.2°C     23.5°C     Dehumid   
```
