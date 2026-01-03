///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.7.5
//DEPS org.slf4j:slf4j-api:2.0.9
//DEPS ch.qos.logback:logback-classic:1.4.11
//DEPS com.fasterxml.jackson.dataformat:jackson-dataformat-xml:2.15.2
//DEPS com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.15.2
//DEPS com.fasterxml.jackson.core:jackson-databind:2.15.2
//DEPS com.ghgande:j2mod:3.2.0
//DEPS com.fasterxml.jackson.dataformat:jackson-dataformat-csv:2.15.2
//DEPS org.zeroturnaround:zt-exec:1.12
//SOURCES com/namekis/utils/RichCli.java

import picocli.CommandLine;
import picocli.CommandLine.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.namekis.utils.RichCli;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import com.fasterxml.jackson.dataformat.csv.*;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.ghgande.j2mod.modbus.Modbus;
import com.ghgande.j2mod.modbus.facade.ModbusTCPMaster;
import com.ghgande.j2mod.modbus.procimg.InputRegister;
import com.ghgande.j2mod.modbus.procimg.SimpleRegister;
import com.ghgande.j2mod.modbus.util.BitVector;
import com.ghgande.j2mod.modbus.util.SerialParameters;
import com.ghgande.j2mod.modbus.facade.ModbusSerialMaster;

import java.io.Console;
import java.io.IOException;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;
import java.util.stream.Collectors;
import java.util.function.Consumer;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.lang.reflect.Method;

@Command(name = "iot", mixinStandardHelpOptions = true, version = "1.0", 
    description = "Unified IoT CLI for ONVIF and Innova devices.",
    subcommands = {
        iot.DiscoverCmd.class,
        iot.DeviceCmd.class,
        iot.ProbesCmd.class,
        iot.ActionsCmd.class,
        iot.DescribeCmd.class,
        iot.CallCmd.class
})
public class iot {
    private static final Logger log = LoggerFactory.getLogger("iot");
    private static final Path CONFIG_PATH = Paths.get(System.getProperty("user.home"), ".onvif", "iot_config.yaml"); // Unified config
    
    // Global Registry
    private static final List<Probe> PROBES = new ArrayList<>();
    
    static {
        // Auto-register probes
        PROBES.add(new OnvifProbe());
        PROBES.add(new InnovaProbe());
        PROBES.add(new ModbusProbe());
    }

    final Config cfg = Config.load();

    static class StandardOptions extends RichCli.BaseOptions {}

    public static void main(String[] args) {
        RichCli.main(args, () -> new iot());
    }

    public static ExecutorService createExecutor() {
        try {
            // Use Virtual Threads if available (Java 21+)
            Method m = Executors.class.getMethod("newVirtualThreadPerTaskExecutor");
            log.debug("Using virtual thread executor");
            return (ExecutorService) m.invoke(null);
        } catch (Exception e) {
            log.debug("Virtual threads not available, falling back to cached thread pool");
            return Executors.newCachedThreadPool();
        }
    }

    // --- SHARED MODELS ---

    static class Config {
        public String activeDevice;
        public Map<String, DeviceProfile> devices = new HashMap<>();

        static Config load() {
            try {
                if (Files.exists(CONFIG_PATH)) {
                    return new YAMLMapper().readValue(CONFIG_PATH.toFile(), Config.class);
                }
                return new Config();
            } catch (Exception e) {
                log.warn("Failed to load config: {}", e.getMessage());
                return new Config();
            }
        }

        void save() {
            try {
                Files.createDirectories(CONFIG_PATH.getParent());
                new YAMLMapper().writerWithDefaultPrettyPrinter().writeValue(CONFIG_PATH.toFile(), this);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    static class DeviceProfile {
        public String type; // "onvif", "innova", "modbus-tcp", "modbus-serial"
        public String url;  // IP for TCP, or Port Name for Serial
        public String user;
        public String pass;
        
        // Modbus/Serial specific
        public Integer port = 502;
        public String serialPort; // For explicit serial port if url is ambiguous
        public Integer baudRate = 19200;
        public Integer dataBits = 8;
        public Integer stopBits = 1;
        public String parity = "none";
        public Integer unitId = 1;
        
        // Extra meta
        public String meta; 

        public DeviceProfile() {}
        public DeviceProfile(String type, String url, String user, String pass) {
            this.type = type;
            this.url = url;
            this.user = user;
            this.pass = pass;
        }
    }

    static class DiscoveredDevice {
        String type;
        String url; // or IP
        String label; // Friendly name or model
        String extra; // Protocol specific data

        public DiscoveredDevice(String type, String url, String label) {
            this.type = type;
            this.url = url;
            this.label = label;
        }
        
        @Override
        public String toString() {
            return String.format("[%s] %s (%s)", type.toUpperCase(), url, label);
        }
    }

    // --- ACTION DESCRIPTORS ---
    
    static class ParamDesc {
        public String name;
        public String description;
        public String type; // string, number, boolean
        public String defaultValue;
        public List<String> samples = new ArrayList<>();
        public boolean required;
        
        public ParamDesc() {}
        public ParamDesc(String name, String desc, String type, boolean required, String defaultValue) {
            this.name = name; this.description = desc; this.type = type; this.required = required; this.defaultValue = defaultValue;
        }
        public ParamDesc addSample(String s) { samples.add(s); return this; }
    }

    static class ResponseDesc {
        public String type; // json, xml, text
        public String description;
        
        public ResponseDesc() {}
        public ResponseDesc(String type, String desc) { this.type = type; this.description = desc; }
    }

    static class ActionDesc {
        public String name;
        public List<String> aliases = new ArrayList<>();
        public String description;
        public List<ParamDesc> params = new ArrayList<>();
        public ResponseDesc response;
        
        public ActionDesc() {}
        public ActionDesc(String name, String description) {
            this.name = name; this.description = description;
        }
        
        public ActionDesc addParam(String name, String desc, String type, boolean required) {
            params.add(new ParamDesc(name, desc, type, required, null));
            return this;
        }
        public ActionDesc withResponse(String type, String desc) {
            this.response = new ResponseDesc(type, desc);
            return this;
        }
    }

    // Explicit Action Instance (as requested)
    static class Action {
        public ActionDesc desc;
        public List<Param> params = new ArrayList<>();
        
        public Action(ActionDesc desc) { this.desc = desc; }
    }

    static class Param {
        public ParamDesc desc;
        public String value;
        
        public Param(ParamDesc desc, String value) {
            this.desc = desc;
            this.value = value;
        }
    }

    // --- PROBE INTERFACE ---

    interface Probe {
        String getId();
        /**
         * Performs discovery.
         * @param onFound Callback when a device is found.
         * @param options Discovery options (subnet, ports, etc.)
         * @param executor Shared executor for parallel tasks.
         */
        void probe(Consumer<DiscoveredDevice> onFound, Map<String, Object> options, ExecutorService executor);
        
        String checkStatus(DeviceProfile profile);
        
        default String describe(DeviceProfile profile) { return "Not implemented"; }
        default void backup(DeviceProfile profile, Path destination) { throw new UnsupportedOperationException("Backup not supported"); }
        default void restore(DeviceProfile profile, Path source) { throw new UnsupportedOperationException("Restore not supported"); }
        
        default List<ActionDesc> getActions() { return Collections.emptyList(); }
        default Object executeAction(DeviceProfile profile, String actionName, Map<String, String> args) {
             throw new IllegalArgumentException("Unknown action: " + actionName);
        }
    }

    // --- COMMANDS ---

    @Command(name = "call", description = "Execute a probe action on a device.", mixinStandardHelpOptions = true)
    public static class CallCmd implements Runnable {
        @ParentCommand iot parent;

        @Parameters(index = "0", description = "Device alias")
        String alias;

        @Parameters(index = "1", description = "Action name")
        String actionName;

        @Option(names = "-P", description = "Parameters (param=value)")
        Map<String, String> params = new HashMap<>();

        @Override
        public void run() {
            DeviceProfile p = parent.cfg.devices.get(alias);
            if (p == null) {
                System.err.println("Unknown device: " + alias);
                return;
            }
            Probe probe = PROBES.stream().filter(pr -> pr.getId().equals(p.type)).findFirst().orElse(null);
            if (probe == null) {
                System.err.println("Unknown probe type: " + p.type);
                return;
            }
            try {
                Object result = probe.executeAction(p, actionName, params);
                if (result != null) {
                    if (result instanceof String) System.out.println(result);
                    else {
                        System.out.println(new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(result));
                    }
                }
            } catch (Exception e) {
                System.err.println("Action failed: " + e.getMessage());
            }
        }
    }

    @Command(name = "probes", description = "List available probes.")
    public static class ProbesCmd implements Runnable {
        @Override
        public void run() {
            System.out.println("Available Probes:");
            PROBES.forEach(p -> System.out.println(" - " + p.getId()));
        }
    }

    @Command(name = "actions", description = "List actions supported by a probe.")
    public static class ActionsCmd implements Runnable {
        @ParentCommand iot parent;
        
        @Parameters(index = "0", description = "Probe name (e.g. modbus)")
        String probeName;

        @Override
        public void run() {
            Probe p = PROBES.stream().filter(pr -> pr.getId().equals(probeName)).findFirst().orElse(null);
            if (p == null) {
                System.err.println("Unknown probe: " + probeName);
                return;
            }
            List<ActionDesc> actions = p.getActions();
            if (actions.isEmpty()) {
                System.out.println("No actions defined for " + probeName);
                return;
            }
            System.out.printf("Actions for %s:%n", probeName);
            for(ActionDesc a : actions) {
                System.out.printf(" - %-15s : %s%n", a.name, a.description);
                for(ParamDesc param : a.params) {
                    System.out.printf("      --%-10s (%s) %s%n", param.name, param.type, param.description);
                }
            }
        }
    }

    @Command(name = "describe", description = "Describe a device configuration/state.")
    public static class DescribeCmd implements Runnable {
        @ParentCommand iot parent;

        @Parameters(index = "0", description = "Device alias")
        String alias;

        @Override
        public void run() {
             DeviceProfile p = parent.cfg.devices.get(alias);
             if (p == null) {
                 System.err.println("Unknown device: " + alias);
                 return;
             }
             Probe probe = PROBES.stream().filter(pr -> pr.getId().equals(p.type)).findFirst().orElse(null);
             if (probe == null) {
                 System.err.println("Unknown probe type: " + p.type);
                 return;
             }
             try {
                 System.out.println(probe.describe(p));
             } catch (Exception e) {
                 log.error("Describe failed", e);
             }
        }
    }

    public Set<DiscoveredDevice> runDiscovery(Map<String, Object> options, Consumer<DiscoveredDevice> liveFeedback) {
        log.info("Starting discovery for probes: {}", PROBES.stream().map(Probe::getId).collect(Collectors.joining(", ")));
        Set<String> foundKeys = Collections.synchronizedSet(new HashSet<>());
        Set<DiscoveredDevice> devices = Collections.synchronizedSet(new HashSet<>());
        
        ExecutorService executor = createExecutor();
        List<CompletableFuture<Void>> futures = new ArrayList<>();

        for (Probe p : PROBES) {
            futures.add(CompletableFuture.runAsync(() -> {
                log.info("Probe {} starting...", p.getId());
                try {
                    p.probe(device -> {
                        String key = device.type + ":" + device.url;
                        if (foundKeys.add(key)) {
                            devices.add(device);
                            if (liveFeedback != null) {
                                liveFeedback.accept(device);
                                System.out.flush();
                            }
                        }
                    }, options, executor);
                    log.info("Probe {} finished.", p.getId());
                } catch (Exception e) {
                    log.error("Error in probe {}: {}", p.getId(), e.getMessage());
                }
            }, executor));
        }

        try {
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        } finally {
            executor.shutdown();
        }
        log.info("Discovery finished. Found {} devices.", devices.size());
        return devices;
    }

    @Command(name = "discover", description = "Discover devices across all registered probes.", mixinStandardHelpOptions = true)
    public static class DiscoverCmd implements Runnable {
        @ParentCommand iot parent;

        @ArgGroup(exclusive = false, heading = "Development options:%n", order = 100)
        StandardOptions standardOpts = new StandardOptions();

        @Option(names = "--subnet", description = "Subnet to scan (for Innova/TCP scanners).")
        String subnet;

        @Option(names = "--modbus.ports", description = "Ports to scan for Modbus (default: 502). Split by comma.")
        String modbusPorts;

        @Override
        public void run() {
            Map<String, Object> options = new HashMap<>();
            if (subnet != null) options.put("subnet", subnet);
            if (modbusPorts != null) options.put("modbus.ports", modbusPorts);
            
            parent.runDiscovery(options, d -> {
                System.out.printf("FOUND: %-8s %-20s %s%n", d.type.toUpperCase(), d.url, d.label);
            });
        }
    }

    @Command(name = "device", description = "Manage devices.")
    public static class DeviceCmd {
        @ParentCommand iot parent;

        @ArgGroup(exclusive = false, heading = "Development options:%n", order = 100)
        StandardOptions standardOpts = new StandardOptions();

        @Command(name = "list", description = "List registered devices.")
        public void list(
            @Option(names = {"-c", "--check"}, description = "Check status") boolean check,
            @Option(names = {"-a", "--all"}, description = "Show registered and scan for new") boolean all
        ) {
            Map<String, DiscoveredDevice> onNetwork = new HashMap<>();
            if (all) {
                log.info("Scanning network...");
                Set<DiscoveredDevice> discovered = parent.runDiscovery(new HashMap<>(), null);
                for(DiscoveredDevice d : discovered) onNetwork.put(d.url, d);
            }

            if (parent.cfg.devices.isEmpty() && !all) {
                System.out.println("No devices registered.");
                return;
            }
            
            System.out.printf("%s %-12s %-8s %-30s %-15s %s%n", "", "ALIAS", "TYPE", "URL/IP", "USER", check ? "STATUS" : "");
            System.out.println("-".repeat(90));
            
            parent.cfg.devices.forEach((alias, p) -> {
                String marker = alias.equals(parent.cfg.activeDevice) ? "*" : " ";
                String status = "";
                if (check) {
                    Probe proto = PROBES.stream().filter(pr -> pr.getId().equals(p.type)).findFirst().orElse(null);
                    if (proto != null) {
                        status = proto.checkStatus(p);
                    } else {
                        status = "UNKNOWN PROBE";
                    }
                }
                System.out.printf("%s %-12s %-8s %-30s %-15s %s%n", marker, alias, p.type, p.url, p.user != null ? p.user : "-", status);
                onNetwork.remove(p.url);
            });
            
            if (all) {
                for (DiscoveredDevice d : onNetwork.values()) {
                     System.out.printf("  %-12s %-8s %-30s %-15s %s%n", "[NEW]", d.type, d.url, "-", "NOT SAVED");
                }
            }
        }
        
        @Command(name = "autoregister", description = "Automatically register discovered devices.", mixinStandardHelpOptions = true)
        public void autoregister() {
            log.info("Scanning network...");
            Set<DiscoveredDevice> discovered = parent.runDiscovery(new HashMap<>(), null);
            int added = 0;
            for (DiscoveredDevice d : discovered) {
                // Check if URL exists in config
                boolean exists = parent.cfg.devices.values().stream().anyMatch(p -> p.url.equals(d.url));
                if (!exists) {
                    String alias = d.type + "-" + UUID.randomUUID().toString().substring(0,4);
                    String user = "admin"; // Defaults
                    String pass = "admin";
                    parent.cfg.devices.put(alias, new DeviceProfile(d.type, d.url, user, pass));
                    System.out.println("Registered " + alias + " (" + d.url + ")");
                    added++;
                }
            }
            if (added > 0) parent.cfg.save();
            System.out.println("Autoregistered " + added + " new devices.");
        }
        
        @Command(name = "add", description = "Manually add a device.")
        public void add(
            @Parameters(index = "0") String alias,
            @Option(names = "--type", required = true, description = "Probe type (onvif, innova)") String type,
            @Option(names = "--url", required = true, description = "URL or IP") String url,
            @Option(names = "-u") String user,
            @Option(names = "-p") String pass
        ) {
            if (PROBES.stream().noneMatch(p -> p.getId().equals(type))) {
                throw new RuntimeException("Unknown probe type: " + type);
            }
            parent.cfg.devices.put(alias, new DeviceProfile(type, url, user, pass));
            parent.cfg.save();
            System.out.println("Added " + alias);
        }

        @Command(name = "register", description = "Interactive discovery and registration.")
        public void register(@Option(names = "--subnet") String subnet) {
            Map<Integer, DiscoveredDevice> scanResults = new HashMap<>();
            List<DiscoveredDevice> list = new ArrayList<>();
            Map<String, Object> options = new HashMap<>();
            if (subnet != null) options.put("subnet", subnet);
            
            System.out.println("Scanning...");
            Set<DiscoveredDevice> discovered = parent.runDiscovery(options, d -> {
                // Optional: print as found? 
                // The original code waited and then printed list.
                // But for better UX, maybe print "Found: ..." ?
                // The interactive menu comes AFTER scanning.
                // So let's just collect.
            });
            list.addAll(discovered);
            
            if (list.isEmpty()) {
                System.out.println("No devices found.");
                return;
            }

            System.out.println("\nDiscovered Devices:");
            for (int i = 0; i < list.size(); i++) {
                DiscoveredDevice d = list.get(i);
                System.out.printf("[%d] %-8s %-25s %s%n", i + 1, d.type, d.url, d.label);
            }

            Console console = System.console();
            if (console == null) return;
            
            String selection = console.readLine("\nEnter number to register (or 'all', 'q'): ");
            if ("q".equalsIgnoreCase(selection)) return;
            
            List<DiscoveredDevice> toRegister = new ArrayList<>();
            if ("all".equalsIgnoreCase(selection)) {
                toRegister.addAll(list);
            } else {
                try {
                    int idx = Integer.parseInt(selection) - 1;
                    if (idx >= 0 && idx < list.size()) toRegister.add(list.get(idx));
                } catch (NumberFormatException e) {
                    System.err.println("Invalid selection.");
                    return;
                }
            }

            for (DiscoveredDevice d : toRegister) {
                String alias = console.readLine("Alias for " + d.url + " [" + d.type + "]: ");
                if (alias == null || alias.isBlank()) alias = d.type + "-" + UUID.randomUUID().toString().substring(0,4);
                
                String user = null, pass = null;
                if ("onvif".equals(d.type)) {
                    user = console.readLine("Username [admin]: ");
                    if (user == null || user.isBlank()) user = "admin";
                    pass = new String(console.readPassword("Password: "));
                }
                
                parent.cfg.devices.put(alias, new DeviceProfile(d.type, d.url, user, pass));
                System.out.println("Registered " + alias);
            }
            parent.cfg.save();
        }
    }

    // ==========================================
    // INNOVA PROBE IMPLEMENTATION
    // ==========================================
    static class InnovaProbe implements Probe {
        @Override
        public String getId() { return "innova"; }

        @Override
        public void probe(Consumer<DiscoveredDevice> onFound, Map<String, Object> options, ExecutorService executor) {
            String targetSubnet = (String) options.get("subnet");
            if (targetSubnet == null) {
                try {
                    InetAddress localHost = InetAddress.getLocalHost();
                    String hostAddress = localHost.getHostAddress();
                    int lastDot = hostAddress.lastIndexOf('.');
                    if (lastDot > 0)
                        targetSubnet = hostAddress.substring(0, lastDot);
                } catch (Exception e) {}
            }
            if (targetSubnet == null) return; // Cannot scan without subnet

            log.info("Innova sweep starting on subnet {}...", targetSubnet);
            List<Future<Void>> futures = new ArrayList<>();

            // Scan .1 to .254
            for (int i = 1; i < 255; i++) {
                final String ip = targetSubnet + "." + i;
                futures.add(executor.submit(() -> {
                    InnovaClient client = new InnovaClient(ip);
                    try {
                        InnovaResponse status = client.getStatus();
                        if (status != null && status.success) {
                            String name = status.setup != null ? status.setup.name : "Unknown Innova";
                            onFound.accept(new DiscoveredDevice("innova", ip, name));
                        }
                    } catch (Exception ignored) {}
                    return null;
                }));
            }
            
            for(Future<Void> f : futures) {
                try { f.get(); } catch(Exception e) {}
            }
            log.info("Innova sweep finished.");
        }

        @Override
        public String describe(DeviceProfile p) {
            try {
                InnovaResponse res = new InnovaClient(p.url).getStatus(); // url holds IP
                return new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(res);
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }

        @Override
        public List<ActionDesc> getActions() {
            return List.of(
                new ActionDesc("set", "Control device settings")
                    .addParam("power", "Power state (on, off)", "string", false)
                    .addParam("temp", "Target temperature", "number", false)
                    .addParam("mode", "Mode (auto, heating, cooling, dehumid, fanonly)", "string", false)
                    .addParam("fan", "Fan speed (0-3)", "number", false)
                    .withResponse("text", "Confirmation message")
            );
        }

        @Override
        public Object executeAction(DeviceProfile profile, String actionName, Map<String, String> args) {
            if ("set".equals(actionName)) {
                try {
                    InnovaClient client = new InnovaClient(profile.url);
                    if (args.containsKey("power")) {
                        client.post("/power/" + args.get("power").toLowerCase(), null);
                    }
                    if (args.containsKey("temp")) {
                        double temp = Double.parseDouble(args.get("temp"));
                        client.post("/set/setpoint", "p_temp=" + (int) (temp * 10));
                    }
                    if (args.containsKey("mode")) {
                        client.post("/set/mode/" + args.get("mode").toLowerCase(), null);
                    }
                    if (args.containsKey("fan")) {
                        client.post("/set/fan", "value=" + args.get("fan"));
                    }
                    return "Settings applied";
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
            throw new IllegalArgumentException("Unknown action: " + actionName);
        }

        @Override
        public String checkStatus(DeviceProfile p) {
            try {
                InnovaResponse res = new InnovaClient(p.url).getStatus(); // url holds IP
                if (res != null && res.result != null) {
                     return String.format("ON: %s | Temp: %.1f", res.result.power == 1, res.result.roomTemp / 10.0);
                }
                return "OFFLINE";
            } catch (Exception e) {
                return "ERROR";
            }
        }

        // --- Client Helpers ---
        static class InnovaClient {
            private final String baseUrl;
            private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).build();
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
            @JsonProperty("RESULT") public Result result;
            @JsonProperty("setup") public Setup setup;
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        static class Result {
            @JsonProperty("ps") public int power;
            @JsonProperty("ta") public int roomTemp;
            @JsonProperty("sp") public int targetTemp;
            @JsonProperty("wm") public int mode;
            @JsonProperty("fn") public int fanSpeed;
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        static class Setup { public String name; }
    }


    // ==========================================
    // ONVIF PROBE IMPLEMENTATION
    // ==========================================
    static class OnvifProbe implements Probe {
        private static final Logger log = LoggerFactory.getLogger("onvif-proto");
        private static final XmlMapper XML_MAPPER = new XmlMapper();
        static { XML_MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false); }

        @Override
        public String getId() { return "onvif"; }

        @Override
        public void probe(Consumer<DiscoveredDevice> onFound, Map<String, Object> ignored, ExecutorService executor) {
            List<InetAddress> interfaces = getActiveIPv4Interfaces();
            log.info("Onvif probing on {} interfaces...", interfaces.size());
            try {
                List<CompletableFuture<Void>> futures = interfaces.stream()
                    .map(addr -> CompletableFuture.runAsync(() -> {
                        sendProbes(addr, onFound);
                    }, executor)).collect(Collectors.toList());
                CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
            } finally {
            }
            log.info("Onvif probing finished.");
        }
        
        @Override
        public List<ActionDesc> getActions() {
            return List.of(
                new ActionDesc("ptz", "Move camera (Pan/Tilt/Zoom)")
                    .addParam("x", "Pan velocity (-1.0 to 1.0)", "number", false)
                    .addParam("y", "Tilt velocity (-1.0 to 1.0)", "number", false)
                    .addParam("z", "Zoom velocity (-1.0 to 1.0)", "number", false)
                    .addParam("timeout", "Duration in ms", "number", false)
                    .withResponse("text", "Confirmation")
            );
        }

        @Override
        public Object executeAction(DeviceProfile profile, String actionName, Map<String, String> args) {
            if ("ptz".equals(actionName)) {
                return "PTZ command received (stub implementation)";
            }
            throw new IllegalArgumentException("Unknown action: " + actionName);
        }

        @Override
        public String describe(DeviceProfile p) {
            try {
                 // Minimal implementation - Fetch DeviceInfo
                 String body = "<GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>";
                 return postSoap(p, body);
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
        
        private String postSoap(DeviceProfile p, String body) throws Exception {
             URI uri = URI.create(p.url);
             String soap = buildSoapEnvelope(p.user, p.pass, body);
             HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
             HttpRequest request = HttpRequest.newBuilder()
                .uri(uri)
                .header("Content-Type", "application/soap+xml; charset=utf-8")
                .POST(HttpRequest.BodyPublishers.ofString(soap))
                .build();
             HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
             return response.body(); // Return raw XML for now
        }

        @Override
        public String checkStatus(DeviceProfile p) {
             // L4 TCP Check
            URI uri = URI.create(p.url);
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(uri.getHost(), uri.getPort() != -1 ? uri.getPort() : 80), 2000);
            } catch (Exception e) {
                return "UNREACHABLE";
            }
            
            // L7 Auth Check
            try {
                 String body = "<GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>";
                 String soap = buildSoapEnvelope(p.user, p.pass, body);
                 HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
                 HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .header("Content-Type", "application/soap+xml; charset=utf-8")
                    .POST(HttpRequest.BodyPublishers.ofString(soap))
                    .build();
                 HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                 if (response.statusCode() == 200) return "OK (Auth)";
                 if (response.statusCode() == 401) return "AUTH FAILED";
                 return "HTTP " + response.statusCode();
            } catch(Exception e) {
                return "ERROR " + e.getMessage();
            }
        }

        private void sendProbes(InetAddress source, Consumer<DiscoveredDevice> callback) {
            try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(source, 0))) {
                socket.setSoTimeout(2000); // 2s window
                String probeXml = buildProbeXml();
                byte[] data = probeXml.getBytes(StandardCharsets.UTF_8);
                DatagramPacket packet = new DatagramPacket(data, data.length, InetAddress.getByName("239.255.255.250"), 3702);
                
                // Send 2 probes
                for(int i=0; i<2; i++) {
                    socket.send(packet);
                }

                long end = System.currentTimeMillis() + 2000;
                while (System.currentTimeMillis() < end) {
                    try {
                        byte[] buf = new byte[8192];
                        DatagramPacket reply = new DatagramPacket(buf, buf.length);
                        socket.receive(reply);
                        String xml = new String(reply.getData(), 0, reply.getLength(), StandardCharsets.UTF_8);
                        String url = extractUrl(xml);
                        if (url != null) {
                            callback.accept(new DiscoveredDevice("onvif", url, "ONVIF Device"));
                        }
                    } catch (SocketTimeoutException e) {
                        break;
                    }
                }
            } catch (Exception e) {
                log.debug("Probe failed on {}: {}", source, e.getMessage());
            }
        }

        private List<InetAddress> getActiveIPv4Interfaces() {
            try {
                return Collections.list(NetworkInterface.getNetworkInterfaces()).stream()
                    .filter(ni -> {
                        try { return ni.isUp() && !ni.isLoopback() && ni.supportsMulticast(); } catch (Exception e) { return false; }
                    })
                    .flatMap(ni -> ni.getInterfaceAddresses().stream()).map(InterfaceAddress::getAddress)
                    .filter(addr -> addr instanceof Inet4Address).collect(Collectors.toList());
            } catch (Exception e) { return Collections.emptyList(); }
        }

        private String buildProbeXml() {
            return "<?xml version=\"1.0\" encoding=\"utf-8\"?><e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"><e:Header><w:MessageID>uuid:"
            + UUID.randomUUID() + "</w:MessageID><w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To><w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>";
        }

        private String extractUrl(String xml) {
            Matcher m = Pattern.compile("(http://[0-9\\.:]+/onvif/[a-zA-Z0-9_]+)").matcher(xml);
            return m.find() ? m.group(1) : null;
        }
        
        private String buildSoapEnvelope(String user, String pass, String body) {
            try {
                byte[] nonceBytes = new byte[16];
                new SecureRandom().nextBytes(nonceBytes);
                String nonce = Base64.getEncoder().encodeToString(nonceBytes);
                String created = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
                
                MessageDigest md = MessageDigest.getInstance("SHA-1");
                md.update(Base64.getDecoder().decode(nonce));
                md.update(created.getBytes(StandardCharsets.UTF_8));
                md.update(pass.getBytes(StandardCharsets.UTF_8));
                String digest = Base64.getEncoder().encodeToString(md.digest());

                return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">" +
                    "<s:Header><Security s:mustUnderstand=\"1\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">" +
                    "<UsernameToken><Username>" + user + "</Username>" +
                    "<Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">" + digest + "</Password>" +
                    "<Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">" + nonce + "</Nonce>" +
                    "<Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">" + created + "</Created>" +
                    "</UsernameToken></Security></s:Header>" +
                    "<s:Body>" + body + "</s:Body></s:Envelope>";
            } catch (Exception e) { throw new RuntimeException(e); }
        }
    }

    // ==========================================
    // MODBUS PROBE IMPLEMENTATION
    // ==========================================
    static class ModbusProbe implements Probe {
        @Override
        public String getId() { return "modbus"; }

        @Override
        public void probe(Consumer<DiscoveredDevice> onFound, Map<String, Object> options, ExecutorService executor) {
            String targetSubnet = (String) options.get("subnet");
            String portsParam = (String) options.get("modbus.ports");
            
            if (targetSubnet == null) {
                try {
                    InetAddress localHost = InetAddress.getLocalHost();
                    String hostAddress = localHost.getHostAddress();
                    int lastDot = hostAddress.lastIndexOf('.');
                    if (lastDot > 0)
                        targetSubnet = hostAddress.substring(0, lastDot);
                } catch (Exception e) {}
            }
            if (targetSubnet == null) return;

            List<Integer> ports = new ArrayList<>();
            if (portsParam != null) {
                for (String s : portsParam.split(",")) {
                    try { ports.add(Integer.parseInt(s.trim())); } catch (Exception e) {}
                }
            }
            if (ports.isEmpty()) ports.add(502);

            log.info("Modbus sweep starting on subnet {} for ports {}...", targetSubnet, ports);
            // Scan Modbus ports
            List<Future<Void>> futures = new ArrayList<>();

            for (int i = 1; i < 255; i++) {
                final String ip = targetSubnet + "." + i;
                for (int port : ports) {
                    futures.add(executor.submit(() -> {
                        if (checkPort(ip, port, 500)) {
                            onFound.accept(new DiscoveredDevice("modbus", ip, "Modbus Device (" + port + ")"));
                        }
                        return null;
                    }));
                }
            }
            
            for(Future<Void> f : futures) {
                try { f.get(); } catch(Exception e) {}
            }
            log.info("Modbus sweep finished.");
        }

        private boolean checkPort(String host, int port, int timeout) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), timeout);
                return true;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public String checkStatus(DeviceProfile p) {
            try (ModbusClient client = new ModbusClient(p)) {
                // Try reading holding register 0 as a ping
                client.read(ModbusType.holding, 0, 1);
                return "ONLINE";
            } catch (Exception e) {
                return "ERROR: " + e.getMessage();
            }
        }
        
        @Override
        public String describe(DeviceProfile p) {
            StringBuilder sb = new StringBuilder();
            try (ModbusClient client = new ModbusClient(p)) {
                sb.append("Device: ").append(p.url).append("\n");
                sb.append("Unit: ").append(p.unitId).append("\n");
                
                sb.append("[Holding Registers 0-19]\n");
                try {
                    int[] holding = client.read(ModbusType.holding, 0, 20);
                    sb.append(formatRegisters(0, holding));
                } catch (Exception e) { sb.append("Error: ").append(e.getMessage()).append("\n"); }

                sb.append("[Input Registers 0-19]\n");
                try {
                    int[] input = client.read(ModbusType.input, 0, 20);
                    sb.append(formatRegisters(0, input));
                } catch (Exception e) { sb.append("Error: ").append(e.getMessage()).append("\n"); }
            } catch(Exception e) {
                return "Failed to connect: " + e.getMessage();
            }
            return sb.toString();
        }
        
        private String formatRegisters(int start, int[] values) {
            StringBuilder sb = new StringBuilder();
            boolean empty = true;
            for (int i = 0; i < values.length; i++) {
                if (values[i] != 0) {
                    sb.append(String.format("  %04d: %-6d (0x%04X)\n", start + i, values[i], values[i]));
                    empty = false;
                }
            }
            if (empty) sb.append("  (All zeros)\n");
            return sb.toString();
        }

        @Override
        public List<ActionDesc> getActions() {
            return List.of(
                new ActionDesc("poll", "Read registers from the device")
                    .addParam("type", "Register type (holding, input, coil, discrete)", "string", false)
                    .addParam("address", "Start address", "number", true)
                    .addParam("count", "Number of registers", "number", false)
                    .withResponse("json", "Array of values"),
                new ActionDesc("write", "Write a value to a register")
                    .addParam("type", "Register type (holding, coil)", "string", false)
                    .addParam("address", "Register address", "number", true)
                    .addParam("value", "Value to write", "number", true)
                    .withResponse("text", "Success message")
            );
        }

        @Override
        public Object executeAction(DeviceProfile profile, String actionName, Map<String, String> args) {
            try (ModbusClient client = new ModbusClient(profile)) {
                if ("poll".equals(actionName)) {
                    String typeStr = args.getOrDefault("type", "holding");
                    ModbusType type = ModbusType.valueOf(typeStr.toLowerCase());
                    int address = Integer.parseInt(args.get("address"));
                    int count = Integer.parseInt(args.getOrDefault("count", "1"));
                    int[] values = client.read(type, address, count);
                    return values;
                } else if ("write".equals(actionName)) {
                    String typeStr = args.getOrDefault("type", "holding");
                    ModbusType type = ModbusType.valueOf(typeStr.toLowerCase());
                    int address = Integer.parseInt(args.get("address"));
                    int value = Integer.parseInt(args.get("value"));
                    
                    ModbusParam p = new ModbusParam();
                    p.type = type;
                    p.address = address;
                    p.modbusValue = value;
                    client.write(p);
                    return "Write successful";
                }
                throw new IllegalArgumentException("Unknown action: " + actionName);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }


        
        // --- Modbus Helpers (Consolidated from modbus.java) ---
        
        enum ModbusType { coil, discrete, holding, input; 
            boolean isWritable() { return this == coil || this == holding; }
        }

        static class ModbusClient implements AutoCloseable {
            private ModbusTCPMaster tcpMaster;
            private ModbusSerialMaster serialMaster;
            private final int unitId;
            private static final int MAX_BATCH = 120;

            public ModbusClient(DeviceProfile p) {
                this.unitId = p.unitId != null ? p.unitId : 1;
                try {
                    boolean isSerial = "modbus-serial".equals(p.type) || "serial".equals(p.type) || p.serialPort != null;
                    if (!isSerial) {
                        // Assume TCP if not serial
                        String host = p.url;
                        int port = p.port != null ? p.port : 502;
                        tcpMaster = new ModbusTCPMaster(host, port);
                        tcpMaster.connect();
                    } else {
                        String portName = p.serialPort != null ? p.serialPort : p.url;
                        SerialParameters params = new SerialParameters();
                        params.setPortName(portName);
                        params.setBaudRate(p.baudRate != null ? p.baudRate : 19200);
                        params.setDatabits(p.dataBits != null ? p.dataBits : 8);
                        params.setStopbits(p.stopBits != null ? p.stopBits : 1);
                        params.setParity(parseParity(p.parity));
                        params.setEncoding(Modbus.SERIAL_ENCODING_RTU);
                        params.setEcho(false);
                        serialMaster = new ModbusSerialMaster(params);
                        serialMaster.connect();
                    }
                } catch (Exception e) {
                    throw new RuntimeException("Connection failed: " + e.getMessage(), e);
                }
            }

            private int parseParity(String p) {
                if (p == null) return 0;
                switch (p.toLowerCase()) {
                    case "even": return 2;
                    case "odd": return 1;
                    case "mark": return 3;
                    case "space": return 4;
                    default: return 0;
                }
            }

            public int[] read(ModbusType type, int start, int count) throws Exception {
                int[] result = new int[count];
                int read = 0;
                while (read < count) {
                    int batchSize = Math.min(MAX_BATCH, count - read);
                    int currentAddr = start + read;
                    int[] batch = readBatch(type, currentAddr, batchSize);
                    System.arraycopy(batch, 0, result, read, batchSize);
                    read += batchSize;
                }
                return result;
            }

            private int[] readBatch(ModbusType type, int start, int count) throws Exception {
                if (tcpMaster != null) {
                    switch (type) {
                        case coil: return bitsToInts(tcpMaster.readCoils(unitId, start, count));
                        case discrete: return bitsToInts(tcpMaster.readInputDiscretes(unitId, start, count));
                        case holding: return regsToInts(tcpMaster.readMultipleRegisters(unitId, start, count));
                        case input: return regsToInts(tcpMaster.readInputRegisters(unitId, start, count));
                    }
                } else if (serialMaster != null) {
                    switch (type) {
                        case coil: return bitsToInts(serialMaster.readCoils(unitId, start, count));
                        case discrete: return bitsToInts(serialMaster.readInputDiscretes(unitId, start, count));
                        case holding: return regsToInts(serialMaster.readMultipleRegisters(unitId, start, count));
                        case input: return regsToInts(serialMaster.readInputRegisters(unitId, start, count));
                    }
                }
                throw new IllegalArgumentException("Not connected or unknown type: " + type);
            }

            private int[] bitsToInts(BitVector bv) {
                int[] res = new int[bv.size()];
                for (int i = 0; i < bv.size(); i++) res[i] = bv.getBit(i) ? 1 : 0;
                return res;
            }

            private int[] regsToInts(InputRegister[] regs) {
                int[] res = new int[regs.length];
                for (int i = 0; i < regs.length; i++) res[i] = regs[i].toShort() & 0xFFFF;
                return res;
            }

            @Override
            public void close() {
                if (tcpMaster != null) tcpMaster.disconnect();
                if (serialMaster != null) serialMaster.disconnect();
            }
            
            public void write(ModbusParam p) throws Exception {
                 if (tcpMaster != null) {
                     switch (p.type) {
                         case coil: tcpMaster.writeCoil(unitId, p.address, p.modbusValue != 0); break;
                         case holding: tcpMaster.writeSingleRegister(unitId, p.address, new SimpleRegister(p.modbusValue)); break;
                         default: throw new IllegalArgumentException("Cannot write type: " + p.type);
                     }
                 } else if (serialMaster != null) {
                     switch (p.type) {
                         case coil: serialMaster.writeCoil(unitId, p.address, p.modbusValue != 0); break;
                         case holding: serialMaster.writeSingleRegister(unitId, p.address, new SimpleRegister(p.modbusValue)); break;
                         default: throw new IllegalArgumentException("Cannot write type: " + p.type);
                     }
                 }
            }
        }

        @Override
        public void backup(DeviceProfile profile, Path destination) {
             // If destination doesn't exist or is directory? 
             // Logic from Modbusync: uses a config file map.
             // We can assume a default map or require one?
             // For now, let's just dump 0-20 holding regs if no map provided, 
             // but `backup` implies saving state.
             // Since we don't have the `config` file argument passed easily to `backup` in this signature,
             // we might rely on a convention or just throw "Not fully implemented" for now.
             // However, I can implement a basic dump.
             
             // Real implementation would need the map file.
             // Let's assume we read 20 holding regs and save to CSV.
             
             List<ModbusParam> params = new ArrayList<>();
             for(int i=0; i<20; i++) {
                 ModbusParam p = new ModbusParam();
                 p.name = "Holding_" + i;
                 p.type = ModbusType.holding;
                 p.address = i;
                 params.add(p);
             }
             
             try (ModbusClient client = new ModbusClient(profile)) {
                 int[] values = client.read(ModbusType.holding, 0, 20);
                 for(int i=0; i<20; i++) {
                     params.get(i).setModbusValue(values[i]);
                 }
                 CsvUtil.write(destination.toFile(), params);
                 System.out.println("Backup to " + destination);
             } catch (Exception e) {
                 throw new RuntimeException("Backup failed: " + e.getMessage(), e);
             }
        }

        @JsonPropertyOrder({ "param", "group", "level", "name", "description", "values", "Default", "Min", "Max", "remarks", "unit", "step", "precision", "offset", "scale", "value", "type", "address", "modbusValue" })
        public static class ModbusParam {
            public String param, group, level, name, description, values, defaultValue, minValue, maxValue, remarks, unit, step;
            public Integer precision;
            public BigDecimal offset, scale, value;
            public ModbusType type;
            public int address;
            public Integer modbusValue;

            public void setModbusValue(int raw) {
                this.modbusValue = raw;
                BigDecimal v = new BigDecimal(raw);
                if (scale != null) v = v.multiply(scale);
                if (offset != null) v = v.add(offset);
                this.value = v;
            }
        }

        static class CsvUtil {
            private static final CsvMapper CSV_MAPPER = new CsvMapper();
            static {
                CSV_MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
                CSV_MAPPER.enable(CsvParser.Feature.TRIM_SPACES);
            }
            static void write(java.io.File file, List<ModbusParam> params) throws IOException {
                CsvSchema schema = CSV_MAPPER.schemaFor(ModbusParam.class).withHeader();
                CSV_MAPPER.writer(schema).writeValue(file, params);
            }
        }
    }
}
