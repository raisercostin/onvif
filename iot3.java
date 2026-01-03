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
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.ghgande.j2mod.modbus.Modbus;
import com.ghgande.j2mod.modbus.facade.ModbusTCPMaster;
import com.ghgande.j2mod.modbus.facade.ModbusSerialMaster;
import com.ghgande.j2mod.modbus.util.SerialParameters;
import com.ghgande.j2mod.modbus.procimg.SimpleRegister;
import com.ghgande.j2mod.modbus.procimg.InputRegister;
import com.ghgande.j2mod.modbus.util.BitVector;

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

@Command(name = "iot3", mixinStandardHelpOptions = true, version = "1.0", description = "Unified IoT CLI for ONVIF, Modbus and Innova devices.", subcommands = {
        iot3.DiscoverCmd.class,
        iot3.DeviceCmd.class,
        iot3.CheckCmd.class,
        iot3.DescribeCmd.class
})
public class iot3 {
    private static final Logger log = LoggerFactory.getLogger("iot3");
    private static final Path CONFIG_PATH = Paths.get(System.getProperty("user.home"), ".onvif", "iot_config.yaml");

    // Global Registry
    private static final List<Probe> PROBES = new ArrayList<>();

    static {
        PROBES.add(new OnvifProbe());
        PROBES.add(new InnovaProbe());
        PROBES.add(new ModbusProbe());
    }

    final Config cfg = Config.load();

    public static void main(String[] args) {
        RichCli.main(args, () -> new iot3());
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

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class DeviceProfile {
        public String type; // "onvif", "innova", "modbus"
        public String url; // Main address/URL (IP for Innova/ModbusTCP, Service URL for ONVIF)
        public String user;
        public String pass;

        // Modbus specific
        public Integer port = 502;
        public Integer unitId = 1;
        public String serialPort; // For serial modbus
        public Integer baudRate;
        public String parity; // even, odd, none...

        public String meta;

        public DeviceProfile() {
        }

        public DeviceProfile(String type, String url, String user, String pass) {
            this.type = type;
            this.url = url;
            this.user = user;
            this.pass = pass;
        }
    }

    static class DiscoveredDevice {
        String type;
        String url;
        String label;
        String extra;

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

    // --- PROBE INTERFACE ---

    interface Probe {
        String getName();

        void discover(Consumer<DiscoveredDevice> onFound, String subnetOrInterface);

        String checkStatus(DeviceProfile profile);

        String describe(DeviceProfile profile);
    }

    // --- COMMANDS ---

    @Command(name = "discover", description = "Discover devices using all available probes.")
    public static class DiscoverCmd implements Runnable {
        @Option(names = "--dry-run", description = "Simulate discovery.")
        boolean dryRun;

        @Option(names = "--subnet", description = "Subnet to scan (e.g. 192.168.1).")
        String subnet;

        @Override
        public void run() {
            System.out.println("Starting discovery...");

            ExecutorService executor = Executors.newCachedThreadPool();
            List<CompletableFuture<Void>> futures = new ArrayList<>();
            Set<String> foundKeys = Collections.synchronizedSet(new HashSet<>());

            for (Probe probe : PROBES) {
                futures.add(CompletableFuture.runAsync(() -> {
                    try {
                        probe.discover(d -> {
                            String key = d.type + ":" + d.url;
                            if (foundKeys.add(key)) {
                                System.out.println("FOUND: " + d);
                            }
                        }, subnet);
                    } catch (Exception e) {
                        log.error("Error in probe {}: {}", probe.getName(), e.getMessage());
                    }
                }, executor));
            }

            try {
                CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
            } finally {
                executor.shutdown();
            }
        }
    }

    @Command(name = "device", description = "Manage registered devices.")
    public static class DeviceCmd {
        @ParentCommand
        iot3 parent;

        @Command(name = "list", description = "List registered devices.")
        public void list(@Option(names = { "-c", "--check" }, description = "Check status") boolean check) {
            if (parent.cfg.devices.isEmpty()) {
                System.out.println("No devices registered.");
                return;
            }

            System.out.printf("%c %-12s %-8s %-30s %-15s %s%n", ' ', "ALIAS", "TYPE", "URL/IP", "USER",
                    check ? "STATUS" : "");
            System.out.println("-".repeat(90));

            parent.cfg.devices.forEach((alias, p) -> {
                String marker = alias.equals(parent.cfg.activeDevice) ? "*" : " ";
                String status = "";
                if (check) {
                    Probe proto = PROBES.stream().filter(pr -> pr.getName().equals(p.type)).findFirst().orElse(null);
                    if (proto != null) {
                        status = proto.checkStatus(p);
                    } else {
                        status = "UNKNOWN TYPE";
                    }
                }
                System.out.printf("%s %-12s %-8s %-30s %-15s %s%n", marker, alias, p.type, p.url,
                        p.user != null ? p.user : "-", status);
            });
        }

        @Command(name = "add", description = "Manually add a device.")
        public void add(
                @Parameters(index = "0") String alias,
                @Option(names = "--type", required = true) String type,
                @Option(names = "--url", required = true) String url,
                @Option(names = "-u") String user,
                @Option(names = "-p") String pass,
                @Option(names = "--port") Integer port,
                @Option(names = "--unit") Integer unitId) {
            DeviceProfile p = new DeviceProfile(type, url, user, pass);
            if (port != null)
                p.port = port;
            if (unitId != null)
                p.unitId = unitId;
            parent.cfg.devices.put(alias, p);
            parent.cfg.save();
            System.out.println("Added " + alias);
        }

        @Command(name = "use", description = "Select active device.")
        public void use(@Parameters(index = "0") String alias) {
            if (!parent.cfg.devices.containsKey(alias))
                throw new RuntimeException("Unknown alias");
            parent.cfg.activeDevice = alias;
            parent.cfg.save();
            System.out.println("Active device: " + alias);
        }
    }

    @Command(name = "check", description = "Check device status.")
    public static class CheckCmd implements Runnable {
        @ParentCommand
        iot3 parent;
        @Parameters(index = "0", arity = "0..1", description = "Device alias or IP")
        String target;

        @Override
        public void run() {
            DeviceProfile p = resolveDevice(parent.cfg, target);
            if (p == null) {
                System.out.println("Device not found or not specified.");
                return;
            }
            Probe probe = PROBES.stream().filter(pr -> pr.getName().equals(p.type)).findFirst().orElse(null);
            if (probe != null) {
                System.out.println("Status: " + probe.checkStatus(p));
            } else {
                System.out.println("No probe found for type: " + p.type);
            }
        }
    }

    @Command(name = "describe", description = "Describe device details.")
    public static class DescribeCmd implements Runnable {
        @ParentCommand
        iot3 parent;
        @Parameters(index = "0", arity = "0..1", description = "Device alias or IP")
        String target;

        @Override
        public void run() {
            DeviceProfile p = resolveDevice(parent.cfg, target);
            if (p == null) {
                System.out.println("Device not found.");
                return;
            }
            Probe probe = PROBES.stream().filter(pr -> pr.getName().equals(p.type)).findFirst().orElse(null);
            if (probe != null) {
                System.out.println(probe.describe(p));
            } else {
                System.out.println("No probe found for type: " + p.type);
            }
        }
    }

    private static DeviceProfile resolveDevice(Config cfg, String target) {
        if (target == null)
            target = cfg.activeDevice;
        if (target != null && cfg.devices.containsKey(target)) {
            return cfg.devices.get(target);
        }
        return null; // Could imply ad-hoc check if we deduce type, but for now strict alias
    }

    // --- ONVIF PROBE ---

    static class OnvifProbe implements Probe {
        private static final Logger log = LoggerFactory.getLogger("onvif-probe");

        @Override
        public String getName() {
            return "onvif";
        }

        @Override
        public void discover(Consumer<DiscoveredDevice> onFound, String subnet) {
            List<InetAddress> interfaces = getActiveIPv4Interfaces();
            ExecutorService executor = Executors.newFixedThreadPool(Math.max(1, interfaces.size()));
            try {
                List<CompletableFuture<Void>> futures = interfaces.stream()
                        .map(addr -> CompletableFuture.runAsync(() -> sendProbes(addr, onFound), executor))
                        .collect(Collectors.toList());
                CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
            } finally {
                executor.shutdown();
            }
        }

        @Override
        public String checkStatus(DeviceProfile p) {
            URI uri = URI.create(p.url);
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(uri.getHost(), uri.getPort() != -1 ? uri.getPort() : 80), 2000);
            } catch (Exception e) {
                return "UNREACHABLE (L4)";
            }

            try {
                String body = "<GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>";
                String soap = buildSoapEnvelope(p.user, p.pass, body);
                HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
                HttpRequest request = HttpRequest.newBuilder().uri(uri)
                        .header("Content-Type", "application/soap+xml; charset=utf-8")
                        .POST(HttpRequest.BodyPublishers.ofString(soap)).build();
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() == 200)
                    return "OK (Authenticated)";
                if (response.statusCode() == 401)
                    return "AUTH FAILED";
                return "HTTP " + response.statusCode();
            } catch (Exception e) {
                return "ERROR " + e.getMessage();
            }
        }

        @Override
        public String describe(DeviceProfile p) {
            // Simplified describe - just raw device info or profile list
            try {
                String body = "<GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>";
                String soap = buildSoapEnvelope(p.user, p.pass, body);
                HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
                HttpRequest request = HttpRequest.newBuilder().uri(URI.create(p.url))
                        .header("Content-Type", "application/soap+xml; charset=utf-8")
                        .POST(HttpRequest.BodyPublishers.ofString(soap)).build();
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                return response.body();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }

        // Helpers
        private void sendProbes(InetAddress source, Consumer<DiscoveredDevice> callback) {
            try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(source, 0))) {
                socket.setSoTimeout(2500);
                String probeXml = buildProbeXml();
                byte[] data = probeXml.getBytes(StandardCharsets.UTF_8);
                DatagramPacket packet = new DatagramPacket(data, data.length, InetAddress.getByName("239.255.255.250"),
                        3702);
                socket.send(packet);
                socket.send(packet);
                long end = System.currentTimeMillis() + 2000;
                while (System.currentTimeMillis() < end) {
                    try {
                        byte[] buf = new byte[8192];
                        DatagramPacket reply = new DatagramPacket(buf, buf.length);
                        socket.receive(reply);
                        String xml = new String(reply.getData(), 0, reply.getLength(), StandardCharsets.UTF_8);
                        String url = extractUrl(xml);
                        if (url != null)
                            callback.accept(new DiscoveredDevice("onvif", url, "ONVIF Camera"));
                    } catch (SocketTimeoutException e) {
                        break;
                    }
                }
            } catch (Exception e) {
            }
        }

        private List<InetAddress> getActiveIPv4Interfaces() {
            try {
                return Collections.list(NetworkInterface.getNetworkInterfaces()).stream()
                        .filter(ni -> {
                            try {
                                return ni.isUp() && !ni.isLoopback() && ni.supportsMulticast();
                            } catch (Exception e) {
                                return false;
                            }
                        })
                        .flatMap(ni -> ni.getInterfaceAddresses().stream()).map(InterfaceAddress::getAddress)
                        .filter(addr -> addr instanceof Inet4Address).collect(Collectors.toList());
            } catch (Exception e) {
                return Collections.emptyList();
            }
        }

        private String buildProbeXml() {
            return "<?xml version=\"1.0\" encoding=\"utf-8\"?><e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"><e:Header><w:MessageID>uuid:"
                    + UUID.randomUUID()
                    + "</w:MessageID><w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To><w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>";
        }

        private String extractUrl(String xml) {
            Matcher m = Pattern.compile("(http://[0-9\\.:]+/onvif/[a-zA-Z0-9_]+)").matcher(xml);
            return m.find() ? m.group(1) : null;
        }

        private String buildSoapEnvelope(String user, String pass, String body) {
            // Simplified WS-Security
            try {
                byte[] nonceBytes = new byte[16];
                new SecureRandom().nextBytes(nonceBytes);
                String nonce = Base64.getEncoder().encodeToString(nonceBytes);
                String created = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
                MessageDigest md = MessageDigest.getInstance("SHA-1");
                md.update(Base64.getDecoder().decode(nonce));
                md.update(created.getBytes(StandardCharsets.UTF_8));
                if (pass != null)
                    md.update(pass.getBytes(StandardCharsets.UTF_8));
                String digest = Base64.getEncoder().encodeToString(md.digest());
                return "<?xml version=\"1.0\" encoding=\"UTF-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Header><Security s:mustUnderstand=\"1\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><UsernameToken><Username>"
                        + (user != null ? user : "")
                        + "</Username><Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">"
                        + digest
                        + "</Password><Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">"
                        + nonce
                        + "</Nonce><Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
                        + created + "</Created></UsernameToken></Security></s:Header><s:Body>" + body
                        + "</s:Body></s:Envelope>";
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    // --- INNOVA PROBE ---

    static class InnovaProbe implements Probe {
        @Override
        public String getName() {
            return "innova";
        }

        @Override
        public void discover(Consumer<DiscoveredDevice> onFound, String subnet) {
            String targetSubnet = subnet;
            if (targetSubnet == null)
                targetSubnet = detectSubnet();
            if (targetSubnet == null)
                return;

            ExecutorService executor = Executors.newFixedThreadPool(50);
            List<Future<Void>> futures = new ArrayList<>();
            for (int i = 1; i < 255; i++) {
                final String ip = targetSubnet + "." + i;
                futures.add(executor.submit(() -> {
                    InnovaClient client = new InnovaClient(ip);
                    try {
                        InnovaResponse status = client.getStatus();
                        if (status != null && status.success) {
                            String name = status.setup != null ? status.setup.name : "Unknown";
                            onFound.accept(new DiscoveredDevice("innova", ip, name));
                        }
                    } catch (Exception ignored) {
                    }
                    return null;
                }));
            }
            for (Future<Void> f : futures) {
                try {
                    f.get();
                } catch (Exception e) {
                }
            }
            executor.shutdown();
        }

        @Override
        public String checkStatus(DeviceProfile p) {
            try {
                InnovaResponse res = new InnovaClient(p.url).getStatus();
                if (res != null)
                    return String.format("ON: %s | Temp: %.1f", res.result != null && res.result.power == 1,
                            res.result != null ? res.result.roomTemp / 10.0 : 0);
            } catch (Exception e) {
                return "ERROR: " + e.getMessage();
            }
            return "OFFLINE";
        }

        @Override
        public String describe(DeviceProfile p) {
            try {
                InnovaResponse res = new InnovaClient(p.url).getStatus();
                return new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(res);
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }

        private String detectSubnet() {
            try {
                String host = InetAddress.getLocalHost().getHostAddress();
                return host.substring(0, host.lastIndexOf('.'));
            } catch (Exception e) {
                return null;
            }
        }

        static class InnovaClient {
            String base;
            HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).build();

            InnovaClient(String ip) {
                base = "http://" + ip + "/api/v/1";
            }

            InnovaResponse getStatus() throws Exception {
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(base + "/status")).GET().build();
                return new ObjectMapper().readValue(http.send(req, HttpResponse.BodyHandlers.ofString()).body(),
                        InnovaResponse.class);
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
            public int roomTemp;
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        static class Setup {
            public String name;
        }
    }

    // --- MODBUS PROBE ---

    static class ModbusProbe implements Probe {
        @Override
        public String getName() {
            return "modbus";
        }

        @Override
        public void discover(Consumer<DiscoveredDevice> onFound, String subnet) {
            String targetSubnet = subnet;
            if (targetSubnet == null)
                targetSubnet = detectSubnet();
            if (targetSubnet == null)
                return;

            ExecutorService executor = Executors.newFixedThreadPool(50);
            List<Future<Void>> futures = new ArrayList<>();
            for (int i = 1; i < 255; i++) {
                final String ip = targetSubnet + "." + i;
                futures.add(executor.submit(() -> {
                    try (Socket s = new Socket()) {
                        s.connect(new InetSocketAddress(ip, 502), 500);
                        onFound.accept(new DiscoveredDevice("modbus", ip, "Modbus Device"));
                    } catch (Exception e) {
                    }
                    return null;
                }));
            }
            for (Future<Void> f : futures) {
                try {
                    f.get();
                } catch (Exception e) {
                }
            }
            executor.shutdown();
        }

        @Override
        public String checkStatus(DeviceProfile p) {
            // TCP check
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(p.url, p.port != null ? p.port : 502), 2000);
                return "ONLINE (TCP PORT OPEN)";
            } catch (Exception e) {
                return "UNREACHABLE";
            }
        }

        @Override
        public String describe(DeviceProfile p) {
            // Try to read first 10 holding registers
            try (ModbusClient client = new ModbusClient(p)) {
                int[] regs = client.read(0, 10);
                return "Holding Registers [0-9]: " + Arrays.toString(regs);
            } catch (Exception e) {
                return "Read failed: " + e.getMessage();
            }
        }

        private String detectSubnet() {
            try {
                String host = InetAddress.getLocalHost().getHostAddress();
                return host.substring(0, host.lastIndexOf('.'));
            } catch (Exception e) {
                return null;
            }
        }

        static class ModbusClient implements AutoCloseable {
            ModbusTCPMaster master;
            int unitId;

            ModbusClient(DeviceProfile p) throws Exception {
                master = new ModbusTCPMaster(p.url, p.port != null ? p.port : 502);
                unitId = p.unitId != null ? p.unitId : 1;
                master.connect();
            }

            int[] read(int start, int count) throws Exception {
                InputRegister[] regs = master.readMultipleRegisters(unitId, start, count);
                int[] res = new int[regs.length];
                for (int i = 0; i < regs.length; i++)
                    res[i] = regs[i].toShort() & 0xFFFF;
                return res;
            }

            @Override
            public void close() {
                master.disconnect();
            }
        }
    }
}
