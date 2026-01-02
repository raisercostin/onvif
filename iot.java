///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.7.5
//DEPS org.slf4j:slf4j-api:2.0.9
//DEPS ch.qos.logback:logback-classic:1.4.11
//DEPS com.fasterxml.jackson.dataformat:jackson-dataformat-xml:2.15.2
//DEPS com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.15.2
//DEPS com.fasterxml.jackson.core:jackson-databind:2.15.2
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

@Command(name = "iot", mixinStandardHelpOptions = true, version = "1.0", 
    description = "Unified IoT CLI for ONVIF and Innova devices.",
    subcommands = {
        iot.DiscoverCmd.class,
        iot.DeviceCmd.class
})
public class iot {
    private static final Logger log = LoggerFactory.getLogger("iot");
    private static final Path CONFIG_PATH = Paths.get(System.getProperty("user.home"), ".onvif", "iot_config.yaml"); // Unified config
    
    // Global Registry
    private static final List<Protocol> PROTOCOLS = new ArrayList<>();
    
    static {
        // Auto-register protocols
        PROTOCOLS.add(new OnvifProtocol());
        PROTOCOLS.add(new InnovaProtocol());
    }

    final Config cfg = Config.load();

    public static void main(String[] args) {
        RichCli.main(args, () -> new iot());
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
        public String type; // "onvif" or "innova"
        public String url;  // Main address/URL
        public String user;
        public String pass;
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

    // --- PROTOCOL INTERFACE ---

    interface Protocol {
        String getId();
        /**
         * Performs discovery.
         * @param onFound Callback when a device is found.
         * @param networkInterface specific interface (optional)
         */
        void discover(Consumer<DiscoveredDevice> onFound, String subnetOrInterface);
        
        String checkStatus(DeviceProfile profile);
        
        // Factory for specific commands could go here, but for now we keep it simple
    }

    // --- COMMANDS ---

    @Command(name = "discover", description = "Discover devices across all registered protocols.")
    public static class DiscoverCmd implements Runnable {
        @ParentCommand iot parent;

        @Option(names = "--subnet", description = "Subnet to scan (for Innova/TCP scanners).")
        String subnet;

        @Override
        public void run() {
            log.info("Starting discovery for protocols: {}", PROTOCOLS.stream().map(Protocol::getId).collect(Collectors.joining(", ")));
            
            Set<String> foundKeys = Collections.synchronizedSet(new HashSet<>());
            ExecutorService executor = Executors.newCachedThreadPool();
            List<CompletableFuture<Void>> futures = new ArrayList<>();

            for (Protocol p : PROTOCOLS) {
                futures.add(CompletableFuture.runAsync(() -> {
                    try {
                        p.discover(device -> {
                            String key = device.type + ":" + device.url;
                            if (foundKeys.add(key)) {
                                System.out.printf("FOUND: %-8s %-20s %s%n", device.type.toUpperCase(), device.url, device.label);
                            }
                        }, subnet);
                    } catch (Exception e) {
                        log.error("Error in protocol {}: {}", p.getId(), e.getMessage());
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

    @Command(name = "device", description = "Manage devices.")
    public static class DeviceCmd {
        @ParentCommand iot parent;

        @Command(name = "list", description = "List registered devices.")
        public void list(@Option(names = {"-c", "--check"}, description = "Check status") boolean check) {
            if (parent.cfg.devices.isEmpty()) {
                System.out.println("No devices registered.");
                return;
            }
            
            System.out.printf("%c %-12s %-8s %-30s %-15s %s%n", "", "ALIAS", "TYPE", "URL/IP", "USER", check ? "STATUS" : "");
            System.out.println("-".repeat(90));
            
            parent.cfg.devices.forEach((alias, p) -> {
                String marker = alias.equals(parent.cfg.activeDevice) ? "*" : " ";
                String status = "";
                if (check) {
                    Protocol proto = PROTOCOLS.stream().filter(pr -> pr.getId().equals(p.type)).findFirst().orElse(null);
                    if (proto != null) {
                        status = proto.checkStatus(p);
                    } else {
                        status = "UNKNOWN PROTOCOL";
                    }
                }
                System.out.printf("%s %-12s %-8s %-30s %-15s %s%n", marker, alias, p.type, p.url, p.user != null ? p.user : "-", status);
            });
        }
        
        @Command(name = "add", description = "Manually add a device.")
        public void add(
            @Parameters(index = "0") String alias,
            @Option(names = "--type", required = true, description = "Protocol type (onvif, innova)") String type,
            @Option(names = "--url", required = true, description = "URL or IP") String url,
            @Option(names = "-u") String user,
            @Option(names = "-p") String pass
        ) {
            if (PROTOCOLS.stream().noneMatch(p -> p.getId().equals(type))) {
                throw new RuntimeException("Unknown protocol type: " + type);
            }
            parent.cfg.devices.put(alias, new DeviceProfile(type, url, user, pass));
            parent.cfg.save();
            System.out.println("Added " + alias);
        }

        @Command(name = "register", description = "Interactive discovery and registration.")
        public void register(@Option(names = "--subnet") String subnet) {
            Map<Integer, DiscoveredDevice> scanResults = new HashMap<>();
            List<DiscoveredDevice> list = new ArrayList<>();
            
            System.out.println("Scanning...");
            // Run discovery synchronously for the UI
            for (Protocol p : PROTOCOLS) {
                p.discover(d -> {
                    synchronized(list) { list.add(d); }
                }, subnet);
            }
            
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
    // INNOVA PROTOCOL IMPLEMENTATION
    // ==========================================
    static class InnovaProtocol implements Protocol {
        @Override
        public String getId() { return "innova"; }

        @Override
        public void discover(Consumer<DiscoveredDevice> onFound, String subnetOverride) {
            String targetSubnet = subnetOverride;
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

            ExecutorService executor = Executors.newFixedThreadPool(50);
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
            executor.shutdown();
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
    // ONVIF PROTOCOL IMPLEMENTATION
    // ==========================================
    static class OnvifProtocol implements Protocol {
        private static final Logger log = LoggerFactory.getLogger("onvif-proto");
        private static final XmlMapper XML_MAPPER = new XmlMapper();
        static { XML_MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false); }

        @Override
        public String getId() { return "onvif"; }

        @Override
        public void discover(Consumer<DiscoveredDevice> onFound, String ignored) {
            List<InetAddress> interfaces = getActiveIPv4Interfaces();
            ExecutorService executor = Executors.newFixedThreadPool(Math.max(1, interfaces.size()));
            try {
                List<CompletableFuture<Void>> futures = interfaces.stream()
                    .map(addr -> CompletableFuture.runAsync(() -> {
                        sendProbes(addr, onFound);
                    }, executor)).collect(Collectors.toList());
                CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
            } finally {
                executor.shutdown();
            }
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
}
