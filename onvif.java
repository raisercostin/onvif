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
import java.io.IOException;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;
import java.util.stream.Collectors;

public class onvif {
  private static final Logger log = LoggerFactory.getLogger("onvif");
  private static final Path CONFIG_PATH = Paths.get(System.getProperty("user.home"), ".onvif", "config.yaml");

  public static void main(String[] args) {
    RichLogback.main(args, new MainCommand());
  }

  @SuppressWarnings("unchecked")
  public static <E extends Throwable> RuntimeException sneakyThrow(Throwable e) throws E {
    throw (E) e;
  }

  @Command(name = "onvif", mixinStandardHelpOptions = true, version = "0.9.0", subcommands = {
      MainCommand.DeviceCmd.class,
      CommandLine.HelpCommand.class
  })
  public static class MainCommand extends RichLogback.BaseOptions {
    @Option(names = { "-t",
        "--timeout" }, defaultValue = "5", description = "Network timeout in seconds (default: 5).", scope = ScopeType.INHERIT)
    int timeout;

    @Option(names = { "-r",
        "--retries" }, defaultValue = "3", description = "Number of UDP probe attempts per interface (default: 3).", scope = ScopeType.INHERIT)
    int retries;

    @Option(names = { "-d", "--device" }, description = "Target device alias", scope = ScopeType.INHERIT)
    String deviceAlias;

    @Option(names = { "-u", "--user" }, description = "Override username", scope = ScopeType.INHERIT)
    String user;

    @Option(names = { "-p", "--pass" }, description = "Override password", scope = ScopeType.INHERIT)
    String pass;

    @Spec
    Model.CommandSpec spec;

    // @Override
    // public void run() {
    // discover();
    // }

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
          System.out.println("The following credentials will be applied to ALL newly discovered devices.");
          parent.user = console.readLine("Default Username [admin]: ");
          if (parent.user == null || parent.user.isEmpty())
            parent.user = "admin";
          char[] passwordChars = console.readPassword("Default Password: ");
          parent.pass = (passwordChars != null) ? new String(passwordChars) : "";
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
          cfg.devices.forEach((id, p) -> {
            String marker = id.equals(cfg.activeDevice) ? "*" : " ";
            String status = check ? checkStatus(p.url, p.user, p.pass) : "NOT CHECKED";
            System.out.printf("%s %-20s %-40s %-10s %-15s%n",
                marker, id, p.url, p.user, status);
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
      private String checkStatus(String url, String user, String pass) {
        URI uri = URI.create(url);
        String host = uri.getHost();
        int port = uri.getPort() != -1 ? uri.getPort() : 80;

        // --- PHASE 1: L4 TCP CHECK (Reachability) ---
        // We do this first to avoid the overhead of building SOAP if the wire is dead.
        try (Socket socket = new Socket()) {
          socket.connect(new InetSocketAddress(host, port), parent.timeout * 1000);
        } catch (Exception e) {
          // Use parent.info for diagnostic transparency
          parent.info(log, "L4 TCP connection failed to " + host + ":" + port, e);
          return "❌ OFFLINE";
        }

        // --- PHASE 2: L7 SOAP & AUTH CHECK (Identity) ---
        try {
          // Minimal ONVIF command to verify credentials and service health
          String body = "<GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>";

          // Reusing your established buildSoapEnvelope logic
          // Ensure this method is static or called via parent if in a different context
          String soap = buildSoapEnvelope(user, pass, body);

          HttpClient client = HttpClient.newBuilder()
              .connectTimeout(Duration.ofSeconds(parent.timeout))
              .build();

          HttpRequest request = HttpRequest.newBuilder()
              .uri(uri)
              .header("Content-Type", "application/soap+xml; charset=utf-8")
              .POST(HttpRequest.BodyPublishers.ofString(soap))
              .build();

          HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

          // Protocol success
          if (response.statusCode() == 200) {
            return "✅ AUTHORIZED";
          }

          // Protocol-level Auth rejection (401 or SOAP Fault containing "Unauthorized")
          if (response.statusCode() == 401 || response.body().contains("Unauthorized")
              || response.body().contains("NotAuthorized")) {
            return "🔐 AUTH REQ";
          }

          // Other HTTP failures (500, 404, etc.)
          return "⚠️ HTTP " + response.statusCode();

        } catch (java.net.http.HttpConnectTimeoutException e) {
          parent.info(log, "L7 Protocol timeout for " + host, e);
          return "❌ TIMEOUT";
        } catch (Exception e) {
          // Catch-all for parser errors, EOF, or SSL issues
          parent.info(log, "L7 Auth check failed for " + user + "@" + host, e);
          return "❓ ERROR";
        }
      }

      // Helper for ONVIF Password Digest
      private String createOnvifAuthHeader(String user, String pass) {
        if (user == null || pass == null)
          return "";
        String nonce = Long.toString(new Random().nextLong());
        String created = Instant.now().toString();
        // Simplified for logic: in real PTZ we'll use a proper SHA-1 Digest helper
        return String.format(
            "<Security xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">" +
                "<UsernameToken><Username>%s</Username><Password>%s</Password></UsernameToken></Security>",
            user, pass);
      }

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

    @Command(name = "stream", description = "Get all available RTSP Stream URIs.")
    public void stream(@Parameters(arity = "0..1") String urlParam) {
      DeviceProfile t = resolveTarget(urlParam);
      try {
        String capRes = postSoap(t.alias, t.url, buildSoapEnvelope(t.user, t.pass,
            "<GetCapabilities xmlns=\"http://www.onvif.org/ver10/device/wsdl\"><Category>Media</Category></GetCapabilities>"),
            "GetCapabilities");

        // Fallback-friendly extraction
        String mediaUrl = extractTag(capRes, "XAddr");
        if (mediaUrl == null)
          mediaUrl = extractTag(capRes, "tt:XAddr");

        String targetUrl = (mediaUrl != null) ? mediaUrl : t.url;

        String profRes = postSoap(t.alias, targetUrl,
            buildSoapEnvelope(t.user, t.pass, "<GetProfiles xmlns=\"http://www.onvif.org/ver10/media/wsdl\"/>"),
            "GetProfiles");

        List<OnvifProfile> profiles = parseProfiles(profRes);

        if (profiles.isEmpty()) {
          System.err.println("No media profiles found. Raw XML length: " + profRes.length());
          // Log the first 500 chars of the response to help debug if it fails again
          info(log, "Raw Response Preview: " + profRes.substring(0, Math.min(500, profRes.length())), null);
          return;
        }
        log.info("Found {} profiles.", profiles.size());
        for (OnvifProfile profile : profiles) {
          try {
            String streamSoap = buildSoapEnvelope(t.user, t.pass,
                "<GetStreamUri xmlns=\"http://www.onvif.org/ver10/media/wsdl\"><StreamSetup>" +
                    "<Stream xmlns=\"http://www.onvif.org/ver10/schema\">RTP-Unicast</Stream>" +
                    "<Transport xmlns=\"http://www.onvif.org/ver10/schema\"><Protocol>RTSP</Protocol></Transport></StreamSetup>"
                    +
                    "<ProfileToken>" + profile.token + "</ProfileToken></GetStreamUri>");

            String streamRes = postSoap(t.alias, targetUrl, streamSoap, "GetStreamUri");
            String uri = extractTag(streamRes, "Uri");
            if (uri == null)
              uri = extractTag(streamRes, "tt:Uri");

            if (uri != null && !uri.isBlank()) {
              System.out.printf("Profile: %-15s | Token: %-10s | Res: %-10s | URI: %s%n",
                  profile.name, profile.token, profile.resolution, uri);
            } else {
              info(log, "Profile " + profile.name + " (Token: " + profile.token + ") returned empty URI.", null);
            }
          } catch (Exception e) {
            // Log failure to info without swallowing
            info(log, "Profile " + profile.name + " (Token: " + profile.token + ") failed.", e);
          }
        }
      } catch (Exception e) {
        throw sneakyThrow(e);
      }
    }

    private List<OnvifProfile> parseProfiles(String xml) {
      List<OnvifProfile> list = new ArrayList<>();
      // 1. Find all Profile blocks. We look for 'Profiles' tags regardless of
      // namespace.
      Pattern profileBlockPattern = Pattern.compile("<[^>]*Profiles[^>]*token=\"([^\"]+)\"[^>]*>(.*?)</[^>]*Profiles>",
          Pattern.DOTALL);
      Matcher m = profileBlockPattern.matcher(xml);

      while (m.find()) {
        String token = m.group(1);
        String content = m.group(2);

        // 2. Extract Name within the block
        String name = "Unknown";
        Matcher nameMatcher = Pattern.compile("<[^>]*Name[^>]*>([^<]+)</[^>]*Name>").matcher(content);
        if (nameMatcher.find())
          name = nameMatcher.group(1);

        // 3. Extract Resolution within the block
        String res = "N/A";
        Matcher resM = Pattern.compile("<[^>]*Width[^>]*>(\\d+)</[^>]+>.*?<[^>]*Height[^>]*>(\\d+)</", Pattern.DOTALL)
            .matcher(content);
        if (resM.find())
          res = resM.group(1) + "x" + resM.group(2);

        list.add(new OnvifProfile(name, token, res));
      }
      return list;
    }

    @Command(description = "Dump full camera profiles as JSON.")
    public void dump(@Parameters(arity = "0..1") String urlParam) {
      DeviceProfile t = resolveTarget(urlParam);
      try {
        String xmlResponse = postSoap(t.alias, t.url,
            buildSoapEnvelope(t.user, t.pass, "<GetProfiles xmlns=\"http://www.onvif.org/ver10/media/wsdl\"/>"),
            "GetProfiles");
        JsonNode profiles = new XmlMapper().readTree(xmlResponse.getBytes()).get("Body").get("GetProfilesResponse");
        System.out.println(new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(profiles));
      } catch (Exception e) {
        throw sneakyThrow(e);
      }
    }

    // --- INTERNAL HELPERS ---
    private DeviceProfile resolveTarget(String positionalUrl) {
      Config cfg = Config.load();
      String targetName = (deviceAlias != null) ? deviceAlias : cfg.activeDevice;
      boolean hasAlias = targetName != null && !targetName.isBlank();

      if (hasAlias && !cfg.devices.containsKey(targetName))
        throw new RuntimeException("Unknown alias: " + targetName + ". Run 'device list' or 'device register'.");
      if (!hasAlias && positionalUrl == null)
        throw new RuntimeException("No device selected. Run 'device use <alias>' or pass URL.");

      DeviceProfile profile = hasAlias ? cfg.devices.get(targetName) : new DeviceProfile();
      DeviceProfile t = new DeviceProfile();
      t.alias = hasAlias ? targetName : "direct";
      t.url = (positionalUrl != null) ? positionalUrl : profile.url;
      t.user = (user != null) ? user : profile.user;
      t.pass = (pass != null) ? pass : profile.pass;

      if (t.url == null)
        throw new RuntimeException("Target URL missing. Run 'device register' or pass URL.");
      if (t.user == null || t.pass == null)
        throw new RuntimeException("Credentials missing. Use -u/-p or 'device update'.");
      return t;
    }

    private String postSoap(String deviceAlias, String url, String xml, String action) {
      log.trace("[{}] [{}] POST {}: {}", deviceAlias, action, url, xml);
      int attempts = 0;
      try {
        while (true) {
          try {
            attempts++;
            log.debug("[{}] [{}] POST {} attempt {}/{}", deviceAlias, action, url, attempts, retries);

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
            log.warn("[{}] [{}] POST {} attempt {}/{} failed: {}. Retrying.... Enable trace for full stacktrace.",
                deviceAlias, action, url, attempts, retries, e.getMessage());
            log.trace("[{}] [{}] POST {} attempt {}/{} failed. Retrying...", deviceAlias, action, url, attempts,
                retries,
                e);
            Thread.sleep(500); // Small backoff
          }
        }
      } catch (InterruptedException e) {
        throw sneakyThrow(e);
      }
    }

    /**
     * Hardened Digest Math: Explicitly handles the Base64 decoding
     * to ensure the SHA-1 hash is calculated on raw bytes.
     */
    public static String calculateDigest(String nonceBase64, String created, String password) {
      try {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(Base64.getDecoder().decode(nonceBase64));
        md.update(created.getBytes(StandardCharsets.UTF_8));
        md.update(password.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(md.digest());
      } catch (Exception e) {
        throw new RuntimeException(e); // Or your sneakyThrow
      }
    }

    /**
     * Universal Envelope Builder: Now static so subcommands can call it directly.
     */
    public static String buildSoapEnvelope(String user, String pass, String body) {
      try {
        // Use a 16-byte random nonce as per WS-Security spec
        byte[] nonceBytes = new byte[16];
        new SecureRandom().nextBytes(nonceBytes);
        String nonce = Base64.getEncoder().encodeToString(nonceBytes);

        String created = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
        String digest = calculateDigest(nonce, created, pass);

        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">" +
            "<s:Header><Security s:mustUnderstand=\"1\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
            +
            "<UsernameToken><Username>" + user + "</Username>" +
            "<Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">"
            + digest + "</Password>" +
            "<Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">"
            + nonce + "</Nonce>" +
            "<Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
            + created + "</Created>" +
            "</UsernameToken></Security></s:Header>" +
            "<s:Body>" + body + "</s:Body></s:Envelope>";
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }

    private void sendProbes(InetAddress source, Set<String> discovered, boolean silent) {
      int windowMillis = (timeout * 1000) / retries;

      try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(source, 0))) {
        socket.setSoTimeout(windowMillis);

        String probeXml = buildProbeXml();
        byte[] data = probeXml.getBytes(StandardCharsets.UTF_8);
        DatagramPacket packet = new DatagramPacket(data, data.length,
            InetAddress.getByName("239.255.255.250"), 3702);

        for (int i = 0; i < retries; i++) {
          socket.send(packet);
          long windowEnd = System.currentTimeMillis() + windowMillis;

          while (System.currentTimeMillis() < windowEnd) {
            try {
              byte[] buf = new byte[8192];
              DatagramPacket reply = new DatagramPacket(buf, buf.length);
              socket.receive(reply);

              String xml = new String(reply.getData(), 0, reply.getLength(), StandardCharsets.UTF_8);
              String url = extractUrl(xml);

              if (url != null && discovered.add(url)) {
                if (!silent)
                  System.out.println(url);
                else
                  log.info("Found device: {}", url);
              }
            } catch (SocketTimeoutException e) {
              // EXPECTED FLOW: Discovery window closed or no more devices found.
              // We log the fact that we handled this for transparency.
              log.debug(
                  "SocketTimeoutException: {}. This is expected during discovery. Enable trace for full stacktrace.",
                  e.getMessage());
              log.trace("Full stacktrace for handled SocketTimeoutException:", e);
              break;
            }
          }
        }
      } catch (Exception e) {
        // UNKNOWN/CRITICAL: We don't log here to avoid the "Log and Throw"
        // anti-pattern.
        // We let the caller or the global handler deal with the failure.
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
  }

  public static class OnvifProfile {
    public String name, token, resolution;

    // Add this constructor to fix the compile error
    public OnvifProfile(String name, String token, String resolution) {
      this.name = name;
      this.token = token;
      this.resolution = resolution;
    }

    // Keep your default constructor if other logic (like a mapper) needs it
    public OnvifProfile() {
    }
  }

  static class DeviceProfile {
    public String alias, url, user, pass;

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
        if (Files.exists(CONFIG_PATH)) {
          log.debug("Loading configuration from: {}", CONFIG_PATH.toAbsolutePath());
          return new YAMLMapper().readValue(CONFIG_PATH.toFile(), Config.class);
        }
        log.debug("No config found at {}, starting fresh.", CONFIG_PATH);
        return new Config();
      } catch (Exception e) {
        log.debug("Failed to load config (using defaults): {}. Trace for details.", e.getMessage());
        log.trace("Config load error:", e);
        return new Config();
      }
    }

    void save() {
      try {
        Files.createDirectories(CONFIG_PATH.getParent());
        log.debug("Saving configuration to: {}", CONFIG_PATH.toAbsolutePath());
        new YAMLMapper().writerWithDefaultPrettyPrinter().writeValue(CONFIG_PATH.toFile(), this);
      } catch (Exception e) {
        throw sneakyThrow(e);
      }
    }
  }
}
