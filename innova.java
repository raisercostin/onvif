///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.7.5
//DEPS org.slf4j:slf4j-api:2.0.9
//DEPS ch.qos.logback:logback-classic:1.4.11
//DEPS com.fasterxml.jackson.core:jackson-databind:2.15.2
//DEPS com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.15.2
//SOURCES com/namekis/utils/RichCli.java

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import com.namekis.utils.RichCli;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;
import picocli.CommandLine.ScopeType;

import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

@Command(name = "innova", mixinStandardHelpOptions = true, version = "1.1", description = "CLI for Innova 2.0 / AirLeaf Ventiloconvertors", subcommands = {
        innova.DiscoverCommand.class,
        innova.DeviceCmd.class,
        innova.StatusCommand.class,
        innova.SetCommand.class
})
class innova implements Runnable {
    private static final Logger log = LoggerFactory.getLogger(innova.class);
    private static final Path CONFIG_PATH = Paths.get(System.getProperty("user.home"), ".innova", "config.yaml");
    final Config cfg = Config.load();

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }

    public static void main(String... args) {
        RichCli.main(args, () -> new innova());
    }

    public boolean isQuiet() {
        // Simple check for quiet mode from RichCli context if needed
        return false;
    }

    // --- Configuration & Models ---

    static class DeviceProfile {
        public String alias, ip, name;

        public DeviceProfile() {
        }

        public DeviceProfile(String ip, String name) {
            this.ip = ip;
            this.name = name;
        }
    }

    static class Config {
        public String activeDevice;
        public Map<String, DeviceProfile> devices = new HashMap<>();

        static Config load() {
            try {
                if (Files.exists(CONFIG_PATH)) {
                    return new YAMLMapper().readValue(CONFIG_PATH.toFile(), Config.class);
                }
            } catch (Exception e) {
                log.debug("Failed to load config: {}", e.getMessage());
            }
            return new Config();
        }

        void save() {
            try {
                Files.createDirectories(CONFIG_PATH.getParent());
                new YAMLMapper().writerWithDefaultPrettyPrinter().writeValue(CONFIG_PATH.toFile(), this);
            } catch (Exception e) {
                log.error("Failed to save config: {}", e.getMessage());
            }
        }
    }

    DeviceProfile resolveTarget(String target) {
        if (target == null) {
            if (cfg.activeDevice != null)
                target = cfg.activeDevice;
            else
                throw new RuntimeException("No target specified and no active device set.");
        }
        if (cfg.devices.containsKey(target)) {
            DeviceProfile p = cfg.devices.get(target);
            p.alias = target;
            return p;
        }
        // Assume target is an IP if not found in registered devices
        DeviceProfile p = new DeviceProfile();
        p.ip = target;
        p.alias = target;
        return p;
    }

    // --- Subcommands ---

    @Command(name = "discover", description = "Scan local network for Innova devices")
    static class DiscoverCommand implements Callable<Integer> {
        @ParentCommand
        innova parent;
        @Option(names = "--subnet", description = "Subnet to scan (e.g. 192.168.1)")
        String subnet;

        @Override
        public Integer call() throws Exception {
            String targetSubnet = subnet;
            if (targetSubnet == null) {
                InetAddress localHost = InetAddress.getLocalHost();
                String hostAddress = localHost.getHostAddress();
                int lastDot = hostAddress.lastIndexOf('.');
                if (lastDot > 0)
                    targetSubnet = hostAddress.substring(0, lastDot);
            }
            if (targetSubnet == null) {
                System.err.println("Could not detect subnet. Use --subnet.");
                return 1;
            }

            System.out.printf("Scanning %s.1-254...%n", targetSubnet);
            ExecutorService executor = Executors.newFixedThreadPool(50);
            List<Future<DeviceProfile>> futures = new ArrayList<>();

            for (int i = 1; i < 255; i++) {
                final String ip = targetSubnet + "." + i;
                futures.add(executor.submit(() -> {
                    InnovaClient client = new InnovaClient(ip);
                    try {
                        InnovaResponse status = client.getStatus();
                        if (status != null && status.success) {
                            return new DeviceProfile(ip, status.setup != null ? status.setup.name : "Unknown");
                        }
                    } catch (Exception ignored) {
                    }
                    return null;
                }));
            }

            List<DeviceProfile> found = new ArrayList<>();
            for (Future<DeviceProfile> f : futures) {
                try {
                    DeviceProfile p = f.get();
                    if (p != null)
                        found.add(p);
                } catch (Exception ignored) {
                }
            }
            executor.shutdown();

            if (found.isEmpty()) {
                System.out.println("No devices found.");
            } else {
                System.out.println("Found devices:");
                for (DeviceProfile p : found) {
                    System.out.printf(" - %-15s (Name: %s)%n", p.ip, p.name);
                }
                System.out.println("\nUse 'device add <alias> --ip <ip>' to register them.");
            }
            return 0;
        }
    }

    @Command(name = "device", description = "Manage registered devices")
    static class DeviceCmd {
        @ParentCommand
        innova parent;

        @Command(name = "add", description = "Register a device")
        void add(@Parameters(index = "0") String alias, @Option(names = "--ip", required = true) String ip) {
            parent.cfg.devices.put(alias, new DeviceProfile(ip, null));
            parent.cfg.save();
            System.out.printf("Device '%s' registered at %s%n", alias, ip);
        }

        @Command(name = "list", description = "List registered devices")
        void list(@Option(names = "--check", description = "Check status") boolean check) {
            if (parent.cfg.devices.isEmpty()) {
                System.out.println("No devices registered.");
                return;
            }

            System.out.printf("%-1s %-15s %-15s %-10s %-10s %-10s %-10s%n", "", "ALIAS", "IP", "POWER", "ROOM", "SET",
                    "MODE");
            System.out.println("-".repeat(80));

            parent.cfg.devices.forEach((alias, p) -> {
                String marker = alias.equals(parent.cfg.activeDevice) ? "*" : " ";
                String power = "-", room = "-", set = "-", mode = "-";

                if (check) {
                    try {
                        InnovaResponse res = new InnovaClient(p.ip).getStatus();
                        if (res != null && res.result != null) {
                            power = res.result.power == 1 ? "ON" : "OFF";
                            room = String.format("%.1f°C", res.result.roomTemp / 10.0);
                            set = String.format("%.1f°C", res.result.targetTemp / 10.0);
                            mode = decodeMode(res.result.mode);
                        } else {
                            power = "OFFLINE";
                        }
                    } catch (Exception e) {
                        power = "ERROR";
                    }
                }
                System.out.printf("%s %-15s %-15s %-10s %-10s %-10s %-10s%n", marker, alias, p.ip, power, room, set,
                        mode);
            });
        }

        @Command(name = "use", description = "Select active device")
        void use(@Parameters(index = "0") String alias) {
            if (!parent.cfg.devices.containsKey(alias))
                throw new RuntimeException("Unknown alias: " + alias);
            parent.cfg.activeDevice = alias;
            parent.cfg.save();
            System.out.println("Active device set to: " + alias);
        }

        private String decodeMode(int mode) {
            switch (mode) {
                case 0:
                    return "Auto";
                case 1:
                    return "Heating";
                case 2:
                    return "Cooling";
                case 3:
                    return "Dehumid";
                case 4:
                    return "FanOnly";
                default:
                    return "M" + mode;
            }
        }
    }

    @Command(name = "status", description = "Get status of a device")
    static class StatusCommand implements Callable<Integer> {
        @ParentCommand
        innova parent;
        @Parameters(index = "0", arity = "0..1", description = "Alias or IP")
        String target;

        @Override
        public Integer call() throws Exception {
            DeviceProfile p = parent.resolveTarget(target);
            InnovaClient client = new InnovaClient(p.ip);
            try {
                InnovaResponse res = client.getStatus();
                if (res == null || res.result == null)
                    throw new IOException("No data received");

                System.out.printf("Device: %s (%s)%n", p.alias, p.ip);
                if (res.setup != null && res.setup.name != null)
                    System.out.println("Name:   " + res.setup.name);
                System.out.println("Power:  " + (res.result.power == 1 ? "ON" : "OFF"));
                System.out.printf("Temp:   %.1f°C (Room) / %.1f°C (Set)%n", res.result.roomTemp / 10.0,
                        res.result.targetTemp / 10.0);
                System.out.println("Mode:   " + decodeMode(res.result.mode));
                System.out.println("Fan:    " + (res.result.fanSpeed == 0 ? "Auto" : res.result.fanSpeed));
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
                return 1;
            }
            return 0;
        }

        private String decodeMode(int mode) {
            switch (mode) {
                case 0:
                    return "Auto";
                case 1:
                    return "Heating";
                case 2:
                    return "Cooling";
                case 3:
                    return "Dehumidification";
                case 4:
                    return "Fan Only";
                default:
                    return "Unknown (" + mode + ")";
            }
        }
    }

    @Command(name = "set", description = "Control device settings")
    static class SetCommand implements Callable<Integer> {
        @ParentCommand
        innova parent;
        @Parameters(index = "0", arity = "0..1")
        String target;
        @Option(names = "--power")
        String power;
        @Option(names = "--temp")
        Double temp;
        @Option(names = "--mode")
        String mode;
        @Option(names = "--fan")
        Integer fan;

        @Override
        public Integer call() throws Exception {
            DeviceProfile p = parent.resolveTarget(target);
            InnovaClient client = new InnovaClient(p.ip);
            boolean changed = false;

            if (power != null) {
                if ("on".equalsIgnoreCase(power))
                    client.post("/power/on", null);
                else
                    client.post("/power/off", null);
                System.out.println("Power set to: " + power);
                changed = true;
            }
            if (temp != null) {
                client.post("/set/setpoint", "p_temp=" + (int) (temp * 10));
                System.out.println("Temp set to: " + temp);
                changed = true;
            }
            if (mode != null) {
                client.post("/set/mode/" + mode.toLowerCase(), null);
                System.out.println("Mode set to: " + mode);
                changed = true;
            }
            if (fan != null) {
                client.post("/set/fan", "value=" + fan);
                System.out.println("Fan set to: " + fan);
                changed = true;
            }

            if (!changed)
                System.out.println("No changes specified.");
            return 0;
        }
    }

    // --- Client & Mapping ---

    static class InnovaClient {
        private final String baseUrl;
        private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
        private final ObjectMapper mapper = new ObjectMapper();

        InnovaClient(String ip) {
            this.baseUrl = "http://" + ip + "/api/v/1";
        }

        InnovaResponse getStatus() throws IOException, InterruptedException {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(baseUrl + "/status")).GET().build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            return mapper.readValue(resp.body(), InnovaResponse.class);
        }

        void post(String endpoint, String body) throws IOException, InterruptedException {
            HttpRequest.Builder b = HttpRequest.newBuilder().uri(URI.create(baseUrl + endpoint));
            if (body != null)
                b.header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(body));
            else
                b.POST(HttpRequest.BodyPublishers.noBody());
            http.send(b.build(), HttpResponse.BodyHandlers.discarding());
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class InnovaResponse {
        public boolean success;
        @JsonProperty("RESULT")
        public Result result;
        @JsonProperty("setup")
        public Setup setup;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class Result {
        @JsonProperty("ps")
        public int power;
        @JsonProperty("ta")
        public int roomTemp; // 222 = 22.2
        @JsonProperty("sp")
        public int targetTemp; // 235 = 23.5
        @JsonProperty("wm")
        public int mode;
        @JsonProperty("fn")
        public int fanSpeed;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class Setup {
        public String name;
    }
}
