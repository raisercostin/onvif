///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.7.5
//DEPS org.slf4j:slf4j-api:2.0.9
//DEPS ch.qos.logback:logback-classic:1.4.11
//DEPS com.fasterxml.jackson.dataformat:jackson-dataformat-xml:2.15.2
//DEPS com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.15.2
//DEPS com.fasterxml.jackson.core:jackson-databind:2.15.2
//SOURCES com/namekis/utils/RichLogback.java

import picocli.CommandLine;
import picocli.CommandLine.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.namekis.utils.RichLogback;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;

import java.io.Console;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;
import java.util.stream.Collectors;

public class onvif {
  private static final Logger log = LoggerFactory.getLogger("onvif");
  private static final Path CONFIG_PATH = Paths.get(System.getProperty("user.home"), ".onvif", "config.yaml");

  public static void main(String[] args) {
    RichLogback.configureLogbackByVerbosity(args);
    int exitCode = new CommandLine(new MainCommand()).execute(args);
    System.exit(exitCode);
  }

  @SuppressWarnings("unchecked")
  public static <E extends Throwable> RuntimeException sneakyThrow(Throwable e) throws E {
    throw (E) e;
  }

  @Command(name = "onvif", mixinStandardHelpOptions = true, version = "1.9.0", subcommands = {
      MainCommand.DeviceCmd.class,
      CommandLine.HelpCommand.class
  })
  public static class MainCommand extends RichLogback.BaseOptions implements Runnable {

    @Option(names = { "-t", "--timeout" }, defaultValue = "5", scope = ScopeType.INHERIT)
    int timeout;

    @Option(names = { "-r", "--retries" }, defaultValue = "3", scope = ScopeType.INHERIT)
    int retries;

    @Option(names = { "-d", "--device" }, description = "Target device alias", scope = ScopeType.INHERIT)
    String deviceAlias;

    @Option(names = { "-u", "--user" }, description = "Override username", scope = ScopeType.INHERIT)
    String user;

    @Option(names = { "-p", "--pass" }, description = "Override password", scope = ScopeType.INHERIT)
    String pass;

    @Spec
    Model.CommandSpec spec;

    @Override
    public void run() {
      discover();
    }

    // --- DEVICE MANAGEMENT MODULE ---
    @Command(name = "device", description = "Manage ONVIF device inventory.")
    public static class DeviceCmd {

      @ParentCommand
      MainCommand parent;

      @Command(description = "Manually add a device profile.")
      public void add(
          @Parameters(index = "0", description = "Device alias") String name,
          @Option(names = "--url", required = true, description = "Service URL") String url) {
        // Logic: CLI flags take priority for registration credentials
        if (parent.user == null || parent.pass == null) {
          throw new RuntimeException(
              "Provide credentials: onvif -u <user> -p <pass> device add " + name + " --url <url>");
        }
        Config cfg = Config.load();
        cfg.devices.put(name, new DeviceProfile(url, parent.user, parent.pass));
        cfg.save();
        System.out.println("Device '" + name + "' added manually.");
      }

      @Command(name = "register", description = "Scan and auto-register new devices.")
      public void register() {
        Set<String> discovered = Collections.synchronizedSet(new HashSet<>());
        parent.runDiscovery(discovered, true);
        if (discovered.isEmpty())
          return;

        Config cfg = Config.load();
        Console console = System.console();

        // Interactive TTY fallback for bulk registration
        if (parent.user == null && parent.pass == null && console != null) {
          System.out.println("\n--- Registration Credentials ---");
          parent.user = console.readLine("Default Username [admin]: ");
          if (parent.user.isEmpty())
            parent.user = "admin";
          parent.pass = new String(console.readPassword("Default Password: "));
        }

        for (String url : discovered) {
          String alias = generateAlias(url);
          if (!cfg.devices.containsKey(alias)) {
            cfg.devices.put(alias, new DeviceProfile(url,
                parent.user != null ? parent.user : "admin",
                parent.pass != null ? parent.pass : "admin"));
            System.out.printf("Registered: %-12s -> %s%n", alias, url);
          }
        }
        cfg.save();
      }

      @Command(description = "Update credentials or URL for an existing device.")
      public void update(
          @Parameters(description = "Device alias") String name,
          @Option(names = "--url", description = "New service URL") String url // Added this
      ) {
        Config cfg = Config.load();
        DeviceProfile p = cfg.devices.get(name);
        if (p == null)
          throw new RuntimeException("Device '" + name + "' not found.");

        if (url != null)
          p.url = url; // Update URL if provided
        if (parent.user != null)
          p.user = parent.user;
        if (parent.pass != null)
          p.pass = parent.pass;

        cfg.save();
        System.out.println("Device '" + name + "' updated.");
      }

      @Command(description = "List devices with optional liveness check and network discovery.")
      public void list(
          @Option(names = { "--all", "-a" }, description = "Show registered and scan for new") boolean all,
          @Option(names = {
              "--unregistered" }, description = "Show only discovered but not saved") boolean unregistered,
          @Option(names = { "--check", "-c" }, description = "Perform liveness ping") boolean check) {
        Config cfg = Config.load();
        Set<String> onNetwork = new HashSet<>();

        if (all || unregistered) {
          log.info("Scanning network...");
          parent.runDiscovery(onNetwork, true);
        }

        // Header - Hidden if --quiet is used
        if (!parent.isQuiet()) {
          System.out.printf("%-2s %-15s %-45s %-10s %-10s%n", "", "ALIAS", "URL", "USER", check ? "STATUS" : "");
          System.out.println("-".repeat(90));
        }

        // 1. Process Registered Devices
        if (!unregistered) {
          cfg.devices.forEach((name, p) -> {
            String marker = name.equals(cfg.activeDevice) ? "*" : " ";
            String status = check ? (isAlive(p.url) ? "✅ ONLINE" : "❌ OFFLINE") : "";
            System.out.printf("%s %-15s %-45s %-10s %-10s%n", marker, name, p.url, p.user, status);
            onNetwork.remove(p.url);
          });
        }

        // 2. Process Unregistered Devices
        if (all || unregistered) {
          for (String url : onNetwork) {
            System.out.printf("  %-15s %-45s %-10s %-10s%n", "[NEW]", url, "-", "NOT SAVED");
          }
        }
      }

      @Command(description = "Select the default device.")
      public void use(@Parameters String name) {
        Config cfg = Config.load();
        if (!cfg.devices.containsKey(name))
          throw new RuntimeException("Unknown alias: " + name);
        cfg.activeDevice = name;
        cfg.save();
        System.out.println("Active device: " + name);
      }

      // --- PRIVATE HELPERS ---

      private boolean isAlive(String url) {
        try {
          HttpClient client = HttpClient.newBuilder()
              .connectTimeout(java.time.Duration.ofMillis(1000)).build();
          HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url))
              .method("HEAD", HttpRequest.BodyPublishers.noBody()).build();
          return client.send(req, HttpResponse.BodyHandlers.discarding()).statusCode() == 200;
        } catch (Exception e) {
          return false;
        }
      }

      private String generateAlias(String url) {
        try {
          String host = URI.create(url).getHost();
          return "cam-" + host.substring(host.lastIndexOf('.') + 1);
        } catch (Exception e) {
          return "cam-" + UUID.randomUUID().toString().substring(0, 4);
        }
      }
    }

    // --- CORE COMMANDS ---

    @Command(description = "Discover ONVIF devices.")
    public void discover() {
      Set<String> discovered = Collections.synchronizedSet(new HashSet<>());
      runDiscovery(discovered, false);
      log.info("Found {} devices.", discovered.size());
    }

    public void runDiscovery(Set<String> discovered, boolean silent) {
      if (!silent)
        log.info("Starting discovery...");
      List<InetAddress> interfaces = getActiveIPv4Interfaces();
      ExecutorService executor = Executors.newFixedThreadPool(interfaces.size());
      try {
        List<CompletableFuture<Void>> futures = interfaces.stream()
            .map(addr -> CompletableFuture.runAsync(() -> {
              sendProbes(addr, discovered, silent);
            }, executor)).collect(Collectors.toList());
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
      } finally {
        executor.shutdown();
      }
      log.info("Found {} devices.", discovered.size());
    }

    @Command(description = "Get all available RTSP Stream URIs.")
    public void stream(@Parameters(arity = "0..1") String urlParam) {
      Target t = resolveTarget(urlParam);
      try {
        String capRes = postSoap(t.url, buildSoapEnvelope(t.user, t.pass,
            "<GetCapabilities xmlns=\"http://www.onvif.org/ver10/device/wsdl\"><Category>Media</Category></GetCapabilities>"));
        String mediaUrl = extractTag(capRes, "tt:XAddr");
        String targetUrl = (mediaUrl != null) ? mediaUrl : t.url;

        String profRes = postSoap(targetUrl,
            buildSoapEnvelope(t.user, t.pass, "<GetProfiles xmlns=\"http://www.onvif.org/ver10/media/wsdl\"/>"));
        List<OnvifProfile> profiles = parseProfiles(profRes);

        for (OnvifProfile profile : profiles) {
          String streamSoap = buildSoapEnvelope(t.user, t.pass,
              "<GetStreamUri xmlns=\"http://www.onvif.org/ver10/media/wsdl\"><StreamSetup>" +
                  "<Stream xmlns=\"http://www.onvif.org/ver10/schema\">RTP-Unicast</Stream>" +
                  "<Transport xmlns=\"http://www.onvif.org/ver10/schema\"><Protocol>RTSP</Protocol></Transport></StreamSetup>"
                  +
                  "<ProfileToken>" + profile.token + "</ProfileToken></GetStreamUri>");
          String streamRes = postSoap(targetUrl, streamSoap);
          System.out.printf("Profile: %-15s | Token: %-10s | Res: %-10s | URI: %s%n",
              profile.name, profile.token, profile.resolution, extractTag(streamRes, "tt:Uri"));
        }
      } catch (Exception e) {
        throw sneakyThrow(e);
      }
    }

    @Command(description = "Dump full camera profiles as JSON.")
    public void dump(@Parameters(arity = "0..1") String urlParam) {
      Target t = resolveTarget(urlParam);
      try {
        String xmlResponse = postSoap(t.url,
            buildSoapEnvelope(t.user, t.pass, "<GetProfiles xmlns=\"http://www.onvif.org/ver10/media/wsdl\"/>"));
        JsonNode profiles = new XmlMapper().readTree(xmlResponse.getBytes()).get("Body").get("GetProfilesResponse");
        System.out.println(new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(profiles));
      } catch (Exception e) {
        throw sneakyThrow(e);
      }
    }

    // --- INTERNAL HELPERS ---

    private Target resolveTarget(String positionalUrl) {
      Config cfg = Config.load();
      String targetName = (deviceAlias != null) ? deviceAlias : cfg.activeDevice;
      DeviceProfile profile = cfg.devices.getOrDefault(targetName, new DeviceProfile());

      Target t = new Target();
      t.url = (positionalUrl != null) ? positionalUrl : profile.url;
      t.user = (user != null) ? user : profile.user;
      t.pass = (pass != null) ? pass : profile.pass;

      if (t.url == null)
        throw new RuntimeException("Target URL missing. Run 'device register' or pass URL.");
      if (t.user == null || t.pass == null)
        throw new RuntimeException("Credentials missing. Use -u/-p or 'device update'.");
      return t;
    }

    private String postSoap(String url, String xml) {
      log.debug("POST to {}: {}", url, xml);
      int attempts = 0;
      try {
        while (true) {
          try {
            attempts++;
            log.debug("POST attempt {}/{} to {}", attempts, retries, url);

            HttpClient client = HttpClient.newBuilder()
                .connectTimeout(java.time.Duration.ofSeconds(timeout))
                .build();
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/soap+xml; charset=utf-8")
                .POST(HttpRequest.BodyPublishers.ofString(xml))
                .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
              // If it's a 401 Unauthorized, don't bother retrying
              if (response.statusCode() == 401)
                throw new RuntimeException("Authentication failed (401)");
              throw new RuntimeException("HTTP " + response.statusCode() + ": " + response.body());
            }
            return response.body();
          } catch (Exception e) {
            if (attempts >= retries)
              throw sneakyThrow(e); // Last attempt failed, propagate
            log.warn("Attempt {} failed: {}. Retrying.... Enable trace for full stacktrace.", attempts, e.getMessage());
            log.trace("Attempt {} failed: {}. Retrying...", attempts, e);
            Thread.sleep(500); // Small backoff
          }
        }
      } catch (InterruptedException e) {
        throw sneakyThrow(e);
      }
    }

    private String buildSoapEnvelope(String user, String pass, String body) throws Exception {
      String nonce = Base64.getEncoder().encodeToString(UUID.randomUUID().toString().getBytes());
      String created = Instant.now().toString();
      String digest = calculateDigest(nonce, created, pass);
      return "<?xml version=\"1.0\" encoding=\"UTF-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tt=\"http://www.onvif.org/ver10/schema\"><s:Header><Security s:mustUnderstand=\"1\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><UsernameToken><Username>"
          + user
          + "</Username><Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">"
          + digest
          + "</Password><Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">"
          + nonce
          + "</Nonce><Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
          + created + "</Created></UsernameToken></Security></s:Header><s:Body>" + body + "</s:Body></s:Envelope>";
    }

    private String calculateDigest(String nonceB64, String created, String pass) throws Exception {
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      md.update(Base64.getDecoder().decode(nonceB64));
      md.update(created.getBytes(StandardCharsets.UTF_8));
      md.update(pass.getBytes(StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(md.digest());
    }

    private void sendProbes(InetAddress source, Set<String> discovered, boolean silent) {
      try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(source, 0))) {
        socket.setSoTimeout(500);
        String probeXml = "<?xml version=\"1.0\" encoding=\"utf-8\"?><e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"><e:Header><w:MessageID>uuid:"
            + UUID.randomUUID()
            + "</w:MessageID><w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To><w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>";
        byte[] data = probeXml.getBytes(StandardCharsets.UTF_8);
        DatagramPacket packet = new DatagramPacket(data, data.length, InetAddress.getByName("239.255.255.250"), 3702);

        for (int i = 0; i < retries; i++) {
          socket.send(packet);
          long end = System.currentTimeMillis() + 1000;
          byte[] buf = new byte[8192];
          while (System.currentTimeMillis() < end) {
            try {
              DatagramPacket reply = new DatagramPacket(buf, buf.length);
              socket.receive(reply);
              String url = extractUrl(new String(reply.getData(), 0, reply.getLength(), StandardCharsets.UTF_8));
              if (url != null && discovered.add(url)) {
                if (!silent)
                  System.out.println(url);
                else
                  log.info("Found device: {}", url);
              }
            } catch (Exception e) {
              log.warn("No response received on interface {}.", source.getHostAddress(), e);
            }
          }
        }
      } catch (java.net.SocketTimeoutException e) {
        log.warn("No response received on interface {}.", source.getHostAddress());
      } catch (Exception e) {
        throw sneakyThrow(e);
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
        throw sneakyThrow(e);
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

    private String extractTag(String xml, String tag) {
      Matcher m = Pattern.compile("<" + tag + "[^>]*>(.*?)</" + tag + ">").matcher(xml);
      return m.find() ? m.group(1) : null;
    }

    private List<OnvifProfile> parseProfiles(String xml) {
      List<OnvifProfile> list = new ArrayList<>();
      Matcher m = Pattern.compile("token=\"([^\"]+)\".*?<tt:Name>([^<]+)", Pattern.DOTALL).matcher(xml);
      while (m.find()) {
        OnvifProfile p = new OnvifProfile();
        p.token = m.group(1);
        p.name = m.group(2);
        Matcher resM = Pattern.compile("<tt:Width>(\\d+)</tt:Width>.*?<tt:Height>(\\d+)</tt:Height>", Pattern.DOTALL)
            .matcher(xml.substring(m.start()));
        p.resolution = resM.find() ? resM.group(1) + "x" + resM.group(2) : "N/A";
        list.add(p);
      }
      return list;
    }
  }

  static class Target {
    String url, user, pass;
  }

  static class OnvifProfile {
    String token, name, resolution;
  }

  static class DeviceProfile {
    public String url, user, pass;

    public DeviceProfile() {
    }

    public DeviceProfile(String url, String user, String pass) {
      this.url = url;
      this.user = user;
      this.pass = pass;
    }
  }

  static class Config {
    public String activeDevice;
    public Map<String, DeviceProfile> devices = new HashMap<>();

    static Config load() {
      try {
        return Files.exists(CONFIG_PATH) ? new YAMLMapper().readValue(CONFIG_PATH.toFile(), Config.class)
            : new Config();
      } catch (Exception e) {
        return new Config();
      }
    }

    void save() {
      try {
        Files.createDirectories(CONFIG_PATH.getParent());
        new YAMLMapper().writerWithDefaultPrettyPrinter().writeValue(CONFIG_PATH.toFile(), this);
      } catch (Exception e) {
        throw sneakyThrow(e);
      }
    }
  }
}
