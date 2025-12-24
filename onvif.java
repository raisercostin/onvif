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

  @Command(name = "onvif", mixinStandardHelpOptions = true, version = "1.8.2", subcommands = {
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

    // --- DEVICE MANAGEMENT ---
    @Command(name = "device", description = "Manage saved device profiles.")
    public static class DeviceCmd {

      @ParentCommand
      MainCommand parent; // Access to global -u, -p, and URL via parent logic

      @Command(description = "Add or update a device profile.")
      public void add(
          @Parameters(index = "0", description = "Device alias (e.g., kitchen)") String name,
          @Option(names = "--url", required = true, description = "Device Service URL") String url) {
        // We pull user/pass from the global flags inherited by the parent
        if (parent.user == null || parent.pass == null) {
          throw new RuntimeException(
              "Missing credentials. Use: onvif -u <user> -p <pass> device add " + name + " --url <url>");
        }

        Config cfg = Config.load();
        cfg.devices.put(name, new DeviceProfile(url, parent.user, parent.pass));
        if (cfg.activeDevice == null)
          cfg.activeDevice = name;
        cfg.save();
        System.out.println("Device '" + name + "' saved successfully.");
      }

      @Command(description = "Set the active device.")
      public void use(@Parameters String name) {
        Config cfg = Config.load();
        if (!cfg.devices.containsKey(name))
          throw new RuntimeException("Device '" + name + "' not found.");
        cfg.activeDevice = name;
        cfg.save();
        System.out.println("Active device set to: " + name);
      }

      @Command(description = "List all saved devices.")
      public void list() {
        Config cfg = Config.load();
        cfg.devices.forEach((name, p) -> System.out.printf("%s %-15s -> %s (%s)%n",
            name.equals(cfg.activeDevice) ? "*" : " ", name, p.url, p.user));
      }
    }

    // --- CORE COMMANDS ---

    @Command(description = "Discover ONVIF devices.")
    public void discover() {
      log.info("Starting discovery...");
      Set<String> discovered = Collections.synchronizedSet(new HashSet<>());
      List<InetAddress> interfaces = getActiveIPv4Interfaces();
      ExecutorService executor = Executors.newFixedThreadPool(interfaces.size());
      try {
        List<CompletableFuture<Void>> futures = interfaces.stream()
            .map(addr -> CompletableFuture.runAsync(() -> {
              try {
                sendProbes(addr, discovered);
              } catch (Exception e) {
                log.debug("Interface failed: {}", addr);
              }
            }, executor)).collect(Collectors.toList());
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
      } finally {
        executor.shutdown();
      }
      log.info("Found {} devices.", discovered.size());
    }

    @Command(description = "Get all available RTSP Stream URIs.")
    public void stream(@Parameters(arity = "0..1", description = "Device Service URL") String urlParam) {
      Target t = resolveTarget(urlParam);
      try {
        String capSoap = buildSoapEnvelope(t.user, t.pass,
            "<GetCapabilities xmlns=\"http://www.onvif.org/ver10/device/wsdl\"><Category>Media</Category></GetCapabilities>");
        String capRes = postSoap(t.url, capSoap);
        String mediaUrl = extractTag(capRes, "tt:XAddr");
        String targetUrl = (mediaUrl != null) ? mediaUrl : t.url;

        String profilesSoap = buildSoapEnvelope(t.user, t.pass,
            "<GetProfiles xmlns=\"http://www.onvif.org/ver10/media/wsdl\"/>");
        String profRes = postSoap(targetUrl, profilesSoap);
        List<OnvifProfile> profiles = parseProfiles(profRes);

        for (OnvifProfile profile : profiles) {
          String streamSoap = buildSoapEnvelope(t.user, t.pass,
              "<GetStreamUri xmlns=\"http://www.onvif.org/ver10/media/wsdl\"><StreamSetup>" +
                  "<Stream xmlns=\"http://www.onvif.org/ver10/schema\">RTP-Unicast</Stream>" +
                  "<Transport xmlns=\"http://www.onvif.org/ver10/schema\"><Protocol>RTSP</Protocol></Transport>" +
                  "</StreamSetup><ProfileToken>" + profile.token + "</ProfileToken></GetStreamUri>");
          String streamRes = postSoap(targetUrl, streamSoap);
          String rtspUri = extractTag(streamRes, "tt:Uri");
          System.out.printf("Profile: %-15s | Token: %-10s | Res: %-10s | URI: %s%n", profile.name, profile.token,
              profile.resolution, rtspUri);
        }
      } catch (Exception e) {
        throw sneakyThrow(e);
      }
    }

    @Command(description = "Dump full camera profiles as JSON.")
    public void dump(@Parameters(arity = "0..1", description = "Device Service URL") String urlParam) {
      Target t = resolveTarget(urlParam);
      try {
        String soap = buildSoapEnvelope(t.user, t.pass,
            "<GetProfiles xmlns=\"http://www.onvif.org/ver10/media/wsdl\"/>");
        String xmlResponse = postSoap(t.url, soap);
        JsonNode profiles = new XmlMapper().readTree(xmlResponse.getBytes()).get("Body").get("GetProfilesResponse");
        System.out.println(new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(profiles));
      } catch (Exception e) {
        throw sneakyThrow(e);
      }
    }

    // --- LOGIC HELPERS ---

    private Target resolveTarget(String positionalUrl) {
      Config cfg = Config.load();
      String targetName = (deviceAlias != null) ? deviceAlias : cfg.activeDevice;
      DeviceProfile profile = cfg.devices.getOrDefault(targetName, new DeviceProfile());

      Target t = new Target();
      t.url = (positionalUrl != null) ? positionalUrl : profile.url;
      t.user = (user != null) ? user : profile.user;
      t.pass = (pass != null) ? pass : profile.pass;

      if (t.url == null)
        throw new RuntimeException("Target URL missing. Use 'onvif device use <name>' or pass a URL.");
      if (t.user == null || t.pass == null)
        throw new RuntimeException("Credentials missing. Use -u/-p or configure a device.");
      return t;
    }

    private List<OnvifProfile> parseProfiles(String xml) {
      log.debug("Parsing {}", xml);
      List<OnvifProfile> list = new ArrayList<>();
      Matcher m = Pattern.compile(
          "<trt:Profiles.*?token=\"(.*?)\">.*?<tt:Name>(.*?)</tt:Name>.*?<tt:Width>(\\d+)</tt:Width>.*?<tt:Height>(\\d+)</tt:Height>",
          Pattern.DOTALL).matcher(xml);
      while (m.find()) {
        OnvifProfile p = new OnvifProfile();
        p.token = m.group(1);
        p.name = m.group(2);
        p.resolution = m.group(3) + "x" + m.group(4);
        list.add(p);
      }
      if (list.isEmpty()) {
        Matcher m2 = Pattern.compile("token=\"([^\"]+)\"").matcher(xml);
        while (m2.find()) {
          OnvifProfile p = new OnvifProfile();
          p.token = m2.group(1);
          p.name = "Unknown";
          p.resolution = "N/A";
          list.add(p);
        }
      }
      return list;
    }

    private String extractTag(String xml, String tag) {
      Matcher m = Pattern.compile("<" + tag + ">(.*?)</" + tag + ">").matcher(xml);
      return m.find() ? m.group(1) : null;
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

    private String calculateDigest(String nonceBase64, String created, String password) throws Exception {
      byte[] nonce = Base64.getDecoder().decode(nonceBase64);
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      md.update(nonce);
      md.update(created.getBytes(StandardCharsets.UTF_8));
      md.update(password.getBytes(StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(md.digest());
    }

    private void sendProbes(InetAddress sourceIp, Set<String> discovered) throws Exception {
      String multicastIp = "239.255.255.250";
      int port = 3702;

      try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(sourceIp, 0))) {
        socket.setSoTimeout(500);

        String probeXml = buildProbeXml();
        byte[] data = probeXml.getBytes(StandardCharsets.UTF_8);
        DatagramPacket packet = new DatagramPacket(data, data.length, InetAddress.getByName(multicastIp), port);

        long globalEnd = System.currentTimeMillis() + (timeout * 1000L);

        for (int i = 0; i < retries; i++) {
          if (System.currentTimeMillis() >= globalEnd)
            break;

          log.debug("Probe #{} from {}", (i + 1), sourceIp.getHostAddress());
          socket.send(packet);

          long windowEnd = System.currentTimeMillis() + ((timeout * 1000L) / retries);
          byte[] buf = new byte[8192];

          while (System.currentTimeMillis() < windowEnd && System.currentTimeMillis() < globalEnd) {
            try {
              DatagramPacket reply = new DatagramPacket(buf, buf.length);
              socket.receive(reply);
              String xml = new String(reply.getData(), 0, reply.getLength(), StandardCharsets.UTF_8);
              String url = extractUrl(xml);

              if (url != null && discovered.add(url)) {
                log.info("Discovered: {} (Source IP: {})", url, reply.getAddress().getHostAddress());
                System.out.println(url);
              }
            } catch (SocketTimeoutException e) {
              log.trace("timeout", e);
            }
          }
        }
      }
    }

    private List<InetAddress> getActiveIPv4Interfaces() {
      try {
        return Collections.list(NetworkInterface.getNetworkInterfaces()).stream()
            .filter(ni -> {
              try {
                return ni.isUp() && !ni.isLoopback() && ni.supportsMulticast();
              } catch (SocketException e) {
                return false;
              }
            })
            .flatMap(ni -> ni.getInterfaceAddresses().stream())
            .map(InterfaceAddress::getAddress)
            .filter(addr -> addr instanceof Inet4Address)
            .collect(Collectors.toList());
      } catch (SocketException e) {
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
