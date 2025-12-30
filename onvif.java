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
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;
import picocli.CommandLine.ScopeType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.namekis.utils.RichCli;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
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
  private static final ObjectMapper JSON_MAPPER = new ObjectMapper()
      .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
  private static final XmlMapper XML_MAPPER = new XmlMapper();
  static {
    XML_MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
  }

  public static void main(String[] args) {
    RichCli.main(args, () -> new MainCommand());
  }

  @SuppressWarnings("unchecked")
  public static <E extends Throwable> RuntimeException sneakyThrow(Throwable e) throws E {
    throw (E) e;
  }

  @Command(name = "onvif", version = "0.9.0", subcommands = {
      MainCommand.DeviceCmd.class,
      MainCommand.PlayCmd.class,
      MainCommand.SnapshotCmd.class,
      MainCommand.RecordCmd.class,
      MainCommand.StreamCmd.class,
      MainCommand.DiscoverCmd.class,
      MainCommand.DescribeCmd.class,
      MainCommand.EventsCmd.class,
      CommandLine.HelpCommand.class
  })
  public static class MainCommand {
    final Config cfg = Config.load();

    static class StandardOptions extends RichCli.BaseOptions {
      // Inherits all standard options from BaseOptions
    }

    @ArgGroup(exclusive = false, heading = "Development options:%n", order = 100)
    StandardOptions standardOpts = new StandardOptions();

    static class GlobalOptions {
      @Option(names = { "-h", "--help" }, usageHelp = true, description = "Show this help message and exit.")
      boolean help;

      @Option(names = { "-V", "--version" }, versionHelp = true, description = "Print version information and exit.")
      boolean version;
    }

    @ArgGroup(exclusive = false, heading = "Global Options:%n", order = 10)
    GlobalOptions globals = new GlobalOptions();

    static class DeviceOptions {
      @Option(names = { "-t",
          "--timeout" }, description = "Network timeout in seconds (default: 5).")
      Integer timeout;

      @Option(names = { "-r",
          "--retries" }, description = "Number of UDP probe attempts per interface (default: 3).")
      Integer retries;

      @Option(names = {
          "--dry-run" }, description = "Log the command that would be executed without running it.")
      Boolean dryRun;

      @Option(names = { "-d",
          "--device" }, description = "Target device alias. Candidates: ${COMPLETION-CANDIDATES}", completionCandidates = DeviceAliasCandidates.class)
      String device;

      @Option(names = { "-u", "--user" }, description = "Override username")
      String user;

      @Option(names = { "-p", "--pass" }, description = "Override password")
      String pass;
    }

    @ArgGroup(exclusive = false, heading = "Device Options:%n", order = 50)
    DeviceOptions deviceOpts = new DeviceOptions();

    // Default accessors handling nulls
    int getEffectiveTimeout(DeviceOptions local) {
      if (local != null && local.timeout != null)
        return local.timeout;
      if (deviceOpts.timeout != null)
        return deviceOpts.timeout;
      return 5;
    }

    int getEffectiveRetries(DeviceOptions local) {
      if (local != null && local.retries != null)
        return local.retries;
      if (deviceOpts.retries != null)
        return deviceOpts.retries;
      return 3;
    }

    boolean getEffectiveDryRun(DeviceOptions local) {
      if (local != null && local.dryRun != null)
        return local.dryRun;
      if (deviceOpts.dryRun != null)
        return deviceOpts.dryRun;
      return false;
    }

    @Spec
    Model.CommandSpec spec;

    public MainCommand() {
      DeviceAliasCandidates.setConfig(cfg);
    }

    // --- DEVICE MANAGEMENT MODULE ---
    @Command(name = "device", description = "Manage ONVIF device inventory.")
    public static class DeviceCmd {

      @ParentCommand
      MainCommand parent;

      @ArgGroup(exclusive = false, heading = "Global Options:%n", order = 10)
      GlobalOptions globals = new GlobalOptions();

      @ArgGroup(exclusive = false, heading = "Device Options:%n", order = 50)
      DeviceOptions deviceOpts = new DeviceOptions();

      @ArgGroup(exclusive = false, heading = "Development options:%n", order = 100)
      StandardOptions standardOpts = new StandardOptions();

      @Command(description = "Manually add a device profile.")
      public void add(
          @Parameters(index = "0", description = "Device alias", completionCandidates = DeviceAliasCandidates.class) String name,
          @Option(names = "--url", required = true, description = "Service URL") String url,
          @ArgGroup(exclusive = false, heading = "Device Options:%n", order = 50) DeviceOptions locals) {
        // Logic: CLI flags take priority for registration credentials
        String user = locals.user != null ? locals.user : parent.deviceOpts.user;
        String pass = locals.pass != null ? locals.pass : parent.deviceOpts.pass;
        if (user == null || pass == null) {
          throw new RuntimeException(
              "Provide credentials: onvif -u <user> -p <pass> device add " + name + " --url <url>");
        }
        parent.cfg.devices.put(name, new DeviceProfile(url, user, pass));
        parent.cfg.save();
        System.out.println("Device '" + name + "' added manually.");
      }

      @Command(name = "register", description = "Scan and auto-register new devices.")
      public void register(
          @ArgGroup(exclusive = false, heading = "Device Options:%n", order = 50) DeviceOptions locals) {
        Set<String> discovered = parent.runDiscovery(true, locals);
        if (discovered.isEmpty())
          return;
        Console console = System.console();

        String user = locals.user != null ? locals.user : parent.deviceOpts.user;
        String pass = locals.pass != null ? locals.pass : parent.deviceOpts.pass;

        // Interactive TTY fallback for bulk registration
        if (user == null && pass == null && console != null) {
          System.out.println("\n--- Registration Credentials ---");
          System.out.println("The following credentials will be applied to ALL newly discovered devices.");
          user = console.readLine("Default Username [admin]: ");
          if (user == null || user.isEmpty())
            user = "admin";
          char[] passwordChars = console.readPassword("Default Password: ");
          pass = (passwordChars != null) ? new String(passwordChars) : "";
        }

        for (String url : discovered) {
          String alias = generateAlias(url);
          if (!parent.cfg.devices.containsKey(alias)) {
            parent.cfg.devices.put(alias, new DeviceProfile(url,
                user != null ? user : "admin",
                pass != null ? pass : "admin"));
            System.out.printf("Registered: %-12s -> %s%n", alias, url);
          }
        }
        parent.cfg.save();
      }

      @Command(description = "Update credentials or URL for an existing device.")
      public void update(
          @Parameters(description = "Device alias", completionCandidates = DeviceAliasCandidates.class) String name,
          @Option(names = "--url", description = "New service URL") String url,
          @ArgGroup(exclusive = false, heading = "Device Options:%n", order = 50) DeviceOptions locals) {
        DeviceProfile p = parent.cfg.devices.get(name);
        if (p == null)
          throw new RuntimeException("Device '" + name + "' not found.");

        String user = locals.user != null ? locals.user : parent.deviceOpts.user;
        String pass = locals.pass != null ? locals.pass : parent.deviceOpts.pass;

        if (url != null)
          p.url = url; // Update URL if provided
        if (user != null)
          p.user = user;
        if (pass != null)
          p.pass = pass;

        parent.cfg.save();
        System.out.println("Device '" + name + "' updated.");
      }

      @Command(description = "List devices with optional liveness check and network discovery.")
      public void list(
          @Option(names = { "--all", "-a" }, description = "Show registered and scan for new") boolean all,
          @Option(names = {
              "--unregistered" }, description = "Show only discovered but not saved") boolean unregistered,
          @Option(names = { "--check", "-c" }, description = "Perform liveness ping") boolean check,
          @ArgGroup(exclusive = false, heading = "Device Options:%n", order = 50) DeviceOptions locals) {
        Set<String> initial = new HashSet<>();

        if (all || unregistered) {
          log.info("Scanning network...");
          initial = parent.runDiscovery(true, locals);
        }
        Set<String> onNetwork = initial;

        // Header - Hidden if --quiet is used
        if (!standardOpts.isQuiet() && !parent.standardOpts.isQuiet()) {
          System.out.printf("%-2s %-15s %-45s %-10s %-30s%n", "", "ALIAS", "URL", "USER", check ? "STATUS" : "");
          System.out.println("-".repeat(90));
        }

        // 1. Process Registered Devices
        if (!unregistered) {
          parent.cfg.devices.forEach((id, p) -> {
            String marker = id.equals(parent.cfg.activeDevice) ? "*" : " ";
            String status = check ? checkStatus(p.url, p.user, p.pass, locals) : "NOT CHECKED";
            System.out.printf("%s %-20s %-40s %-10s %-30s%n",
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
      public void use(
          @Parameters(index = "0", description = "Device alias", paramLabel = "device", completionCandidates = DeviceAliasCandidates.class) String name) {
        if (!parent.cfg.devices.containsKey(name))
          throw new RuntimeException("Unknown alias: " + name);
        parent.cfg.activeDevice = name;
        parent.cfg.save();
        System.out.println("Active device: " + name);
      }

      // --- PRIVATE HELPERS ---
      private String checkStatus(String url, String user, String pass, DeviceOptions local) {
        URI uri = URI.create(url);
        String host = uri.getHost();
        int port = uri.getPort() != -1 ? uri.getPort() : 80;

        // --- PHASE 1: L4 TCP CHECK (Reachability) ---
        log.trace("First test socket to avoid the overhead of building SOAP if the wire is dead.");
        try (Socket socket = new Socket()) {
          socket.connect(new InetSocketAddress(host, port), parent.getEffectiveTimeout(local) * 1000);
        } catch (SocketTimeoutException e) {
          parent.standardOpts.debug(log, "L4 TCP connection timed out to " + host + ":" + port, e);
          return "❌ TIMEOUT. WRONG IP?";
        } catch (ConnectException e) {
          if (e.getMessage().contains("Connection refused: getsockopt")) {
            parent.standardOpts.debug(log, "L4 TCP connection refused to " + host + ":" + port, e);
            return "❌ REFUSED. WRONG PORT?";
          }
          parent.standardOpts.debug(log, "L4 TCP connection refused to " + host + ":" + port, e);
          return "❌ REFUSED " + e.getMessage();
        } catch (Exception e) {
          parent.standardOpts.debug(log, "L4 TCP connection failed to " + host + ":" + port, e);
          return "❌ OFFLINE" + e.getMessage();
        }

        // --- PHASE 2: L7 SOAP & AUTH CHECK (Identity) ---
        StringBuilder status = new StringBuilder();
        try {
          // Minimal ONVIF command to verify credentials and service health
          String body = "<GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>";
          String soap = buildSoapEnvelope(user, pass, body);

          HttpClient client = HttpClient.newBuilder()
              .connectTimeout(Duration.ofSeconds(parent.getEffectiveTimeout(local)))
              .build();

          HttpRequest request = HttpRequest.newBuilder()
              .uri(uri)
              .header("Content-Type", "application/soap+xml; charset=utf-8")
              .POST(HttpRequest.BodyPublishers.ofString(soap))
              .build();

          HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

          if (response.statusCode() == 200) {
            status.append("✅ AUTHORIZED");
          } else if (response.statusCode() == 401 || response.body().contains("Unauthorized")
              || response.body().contains("NotAuthorized")) {
            // Protocol-level Auth rejection (401 or SOAP Fault containing "Unauthorized")
            return "🔐 AUTH REQ " + response.statusCode();
          } else {
            return "⚠️ HTTP " + response.statusCode() + " [" + response.body() + "]";
          }
        } catch (java.net.http.HttpConnectTimeoutException e) {
          parent.standardOpts.info(log, "L7 Protocol timeout for " + host, e);
          return "❌ TIMEOUT";
        } catch (Exception e) {
          // Catch-all for parser errors, EOF, or SSL issues
          parent.standardOpts.info(log, "L7 Auth check failed for " + user + "@" + host, e);
          return "❓ ERROR";
        }

        // --- PHASE 3: EVENTING CHECK ---
        try {
          DeviceProfile t = new DeviceProfile(url, user, pass);
          t.alias = "check"; // dummy alias
          String capRes = parent.postSoap(t, t.url, buildSoapEnvelope(t.user, t.pass,
              "<GetCapabilities xmlns=\"http://www.onvif.org/ver10/device/wsdl\"><Category>Events</Category></GetCapabilities>"),
              "GetCapabilities", null, null, null);
          SoapEnvelope capEnv = parent.xmlToEnvelope(capRes);
          if (capEnv.getEventsXAddr() != null && !capEnv.getEventsXAddr().isBlank()) {
            status.append(" | ✅ EVENTS");
          } else {
            status.append(" | ❌ EVENTS");
          }
        } catch (Exception e) {
          status.append(" | ❌ EVENTS");
        }
        return status.toString();
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

    // --- MEDIA UTILS ---
    private String getBestStreamUri(DeviceProfile t, String profileName, DeviceOptions local) {
      try {
        // 1. GetProfiles to find the token
        String profRes = postSoap(t, t.url,
            buildSoapEnvelope(t.user, t.pass, "<GetProfiles xmlns=\"http://www.onvif.org/ver10/media/wsdl\"/>"),
            "GetProfiles", null, null, local);
        List<OnvifProfile> profiles = parseProfiles(profRes);

        if (profiles.isEmpty())
          throw new RuntimeException("No profiles found on device.");

        // Select profile: specific name or first available
        OnvifProfile selected = profiles.stream()
            .filter(p -> profileName != null && p.name.equals(profileName))
            .findFirst()
            .orElse(profiles.get(0));

        log.info("Using profile: {} (Token: {})", selected.name, selected.token);

        // 2. GetStreamUri for the token
        String streamSoap = buildSoapEnvelope(t.user, t.pass,
            "<GetStreamUri xmlns=\"http://www.onvif.org/ver10/media/wsdl\"><StreamSetup>" +
                "<Stream xmlns=\"http://www.onvif.org/ver10/schema\">RTP-Unicast</Stream>" +
                "<Transport xmlns=\"http://www.onvif.org/ver10/schema\"><Protocol>RTSP</Protocol></Transport></StreamSetup>"
                +
                "<ProfileToken>" + selected.token + "</ProfileToken></GetStreamUri>");

        String streamRes = postSoap(t, t.url, streamSoap, "GetStreamUri", null, null, local);
        String uri = extractTag(streamRes, "Uri");
        if (uri == null)
          uri = extractTag(streamRes, "tt:Uri");

        if (uri == null || uri.isBlank())
          throw new RuntimeException("Failed to retrieve RTSP URI for profile " + selected.name);

        // Inject credentials into URI
        // Format: rtsp://user:pass@host:port/path
        if (uri.startsWith("rtsp://")) {
          // Check if URI already has auth
          String noScheme = uri.substring(7);
          if (!noScheme.contains("@")) {
            return "rtsp://" + t.user + ":" + t.pass + "@" + noScheme;
          }
        }
        return uri;

      } catch (Exception e) {
        throw sneakyThrow(e);
      }
    }

    @Command(name = "play", aliases = {
        "view" }, description = "Play the live stream using VLC.")
    public static class PlayCmd implements Runnable {
      @ParentCommand
      MainCommand parent;

      @ArgGroup(exclusive = false, heading = "Global Options:%n", order = 10)
      GlobalOptions globals = new GlobalOptions();

      @ArgGroup(exclusive = false, heading = "Device Options:%n", order = 50)
      DeviceOptions deviceOpts = new DeviceOptions();

      @ArgGroup(exclusive = false, heading = "Development options:%n", order = 100)
      StandardOptions standardOpts = new StandardOptions();

      @Parameters(index = "0", arity = "0..1", description = "Device alias")
      String device;

      @Option(names = "--profile", description = "Specific profile name to use")
      String profile;

      @Option(names = "--allow-pass", description = "Show full password in logs/command output")
      boolean allowPass;

      @Override
      public void run() {
        DeviceProfile t = parent.resolveTarget(device, deviceOpts);
        String uri = parent.getBestStreamUri(t, profile, deviceOpts);

        // VLC command: vlc <uri>
        List<String> cmd = new ArrayList<>();
        // On Windows it might just be 'vlc', on others maybe 'cvlc' or 'vlc'
        // We assume 'vlc' is in PATH.
        cmd.add("vlc");
        cmd.add(uri);

        exec(cmd, allowPass, parent.getEffectiveDryRun(deviceOpts));
      }
    }

    @Command(name = "snapshot", description = "Take a JPEG snapshot using ffmpeg.")
    public static class SnapshotCmd implements Runnable {
      @ParentCommand
      MainCommand parent;

      @ArgGroup(exclusive = false, heading = "Global Options:%n", order = 10)
      GlobalOptions globals = new GlobalOptions();

      @ArgGroup(exclusive = false, heading = "Device Options:%n", order = 50)
      DeviceOptions deviceOpts = new DeviceOptions();

      @ArgGroup(exclusive = false, heading = "Development options:%n", order = 100)
      StandardOptions standardOpts = new StandardOptions();

      @Parameters(index = "0", arity = "0..1", description = "Device alias")
      String device;

      @Option(names = "--out", description = "Output filename (default: <alias>-<timestamp>.jpg)")
      String outFile;

      @Option(names = "--allow-pass", description = "Show full password in logs/command output")
      boolean allowPass;

      @Override
      public void run() {
        DeviceProfile t = parent.resolveTarget(device, deviceOpts);
        String uri = parent.getBestStreamUri(t, null, deviceOpts);

        if (outFile == null) {
          outFile = t.alias + "-" + Instant.now().toString().replaceAll("[:.]", "-") + ".jpg";
        }

        // ffmpeg -y -i <uri> -vframes 1 <outFile>
        List<String> cmd = new ArrayList<>();
        cmd.add("ffmpeg");
        cmd.add("-y");
        cmd.add("-i");
        cmd.add(uri);
        cmd.add("-vframes");
        cmd.add("1");
        cmd.add(outFile);

        exec(cmd, allowPass, parent.getEffectiveDryRun(deviceOpts));
      }
    }

    @Command(name = "record", description = "Record the stream to a file using ffmpeg.")
    public static class RecordCmd implements Runnable {
      @ParentCommand
      MainCommand parent;

      @ArgGroup(exclusive = false, heading = "Global Options:%n", order = 10)
      GlobalOptions globals = new GlobalOptions();

      @ArgGroup(exclusive = false, heading = "Device Options:%n", order = 50)
      DeviceOptions deviceOpts = new DeviceOptions();

      @ArgGroup(exclusive = false, heading = "Development options:%n", order = 100)
      StandardOptions standardOpts = new StandardOptions();

      @Parameters(index = "0", arity = "0..1", description = "Device alias")
      String device;

      @Option(names = "--out", description = "Output filename pattern (default: <alias>-capture.mkv)")
      String outFile;

      @Option(names = "--segment", description = "Enable segmented recording (every 1 hour)")
      boolean segment;

      @Option(names = "--allow-pass", description = "Show full password in logs/command output")
      boolean allowPass;

      @Override
      public void run() {
        DeviceProfile t = parent.resolveTarget(device, deviceOpts);
        String uri = parent.getBestStreamUri(t, null, deviceOpts);

        if (outFile == null) {
          outFile = t.alias + "-capture.mkv";
        }

        List<String> cmd = new ArrayList<>();
        cmd.add("ffmpeg");
        // Improve robustnes over tcp
        cmd.add("-rtsp_transport");
        cmd.add("tcp");

        cmd.add("-i");
        cmd.add(uri);

        cmd.add("-map");
        cmd.add("0");

        cmd.add("-c");
        cmd.add("copy"); // Copy codec (no re-encode)

        if (segment) {
          // -f segment -segment_time 3600 -segment_format matroska -segment_wrap 240
          // -reset_timestamps 1 "capture-%03d.mkv"
          cmd.add("-f");
          cmd.add("segment");
          cmd.add("-segment_time");
          cmd.add("3600");
          cmd.add("-segment_format");
          cmd.add("matroska");
          // Reset timestamps to avoid sync issues in segments
          cmd.add("-reset_timestamps");
          cmd.add("1");
        }

        cmd.add(outFile);

        exec(cmd, allowPass, parent.getEffectiveDryRun(deviceOpts));
      }
    }

    // --- CORE COMMANDS ---
    @Command(name = "discover", description = "Discover ONVIF devices.")
    public static class DiscoverCmd implements Runnable {
      @ParentCommand
      MainCommand parent;

      @ArgGroup(exclusive = false, heading = "Global Options:%n", order = 10)
      GlobalOptions globals = new GlobalOptions();

      @ArgGroup(exclusive = false, heading = "Device Options:%n", order = 50)
      DeviceOptions deviceOpts = new DeviceOptions();

      @ArgGroup(exclusive = false, heading = "Development options:%n", order = 100)
      StandardOptions standardOpts = new StandardOptions();

      @Override
      public void run() {
        parent.runDiscovery(false, deviceOpts);
      }
    }

    public Set<String> runDiscovery(boolean silent, DeviceOptions local) {
      Set<String> knownUrls = cfg.devices.values().stream()
          .map(p -> p.url)
          .filter(Objects::nonNull)
          .collect(Collectors.toSet());
      Set<String> initial = Collections.synchronizedSet(new HashSet<>(knownUrls));
      Set<String> discovered = Collections.synchronizedSet(new HashSet<>());
      Set<String> discoveredNew = Collections.synchronizedSet(new HashSet<>());
      // List<String> newUrls = discovered.stream()
      // .filter(url -> !knownUrls.contains(url))
      // .collect(Collectors.toList());

      if (!silent)
        log.info("Starting discovery...");
      List<InetAddress> interfaces = getActiveIPv4Interfaces();
      ExecutorService executor = Executors.newFixedThreadPool(interfaces.size());
      try {
        List<CompletableFuture<Void>> futures = interfaces.stream()
            .map(addr -> CompletableFuture.runAsync(() -> {
              sendProbes(addr, initial, discovered, discoveredNew, silent, local);
            }, executor)).collect(Collectors.toList());
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
      } finally {
        executor.shutdown();
      }
      log.info("Found {} new devices, confirmed {} devices, configured {} devices.", discoveredNew.size(),
          discovered.size(), initial.size());
      return discoveredNew;
    }

    @Command(name = "stream", description = "Get all available RTSP Stream URIs.")
    public static class StreamCmd implements Runnable {
      @ParentCommand
      MainCommand parent;

      @ArgGroup(exclusive = false, heading = "Global Options:%n", order = 10)
      GlobalOptions globals = new GlobalOptions();

      @ArgGroup(exclusive = false, heading = "Device Options:%n", order = 50)
      DeviceOptions deviceOpts = new DeviceOptions();

      @ArgGroup(exclusive = false, heading = "Development options:%n", order = 100)
      StandardOptions standardOpts = new StandardOptions();

      @Parameters(index = "0", arity = "0..1", description = "Device alias or URL", completionCandidates = DeviceAliasCandidates.class)
      String targetParam;

      @Override
      public void run() {
        DeviceProfile t = parent.resolveTarget(targetParam, deviceOpts);
        try {
          String capRes = parent.postSoap(t, t.url, buildSoapEnvelope(t.user, t.pass,
              "<GetCapabilities xmlns=\"http://www.onvif.org/ver10/device/wsdl\"><Category>Media</Category></GetCapabilities>"),
              "GetCapabilities", null, null, deviceOpts);

          // Fallback-friendly extraction
          String mediaUrl = parent.extractTag(capRes, "XAddr");
          if (mediaUrl == null)
            mediaUrl = parent.extractTag(capRes, "tt:XAddr");

          String targetUrl = (mediaUrl != null) ? mediaUrl : t.url;

          String profRes = parent.postSoap(t, targetUrl,
              buildSoapEnvelope(t.user, t.pass, "<GetProfiles xmlns=\"http://www.onvif.org/ver10/media/wsdl\"/>"),
              "GetProfiles", null, null, deviceOpts);

          List<OnvifProfile> profiles = parent.parseProfiles(profRes);

          if (profiles.isEmpty()) {
            System.err.println("No media profiles found. Raw XML length: " + profRes.length());
            // Log the first 500 chars of the response to help debug if it fails again
            parent.standardOpts.info(log,
                "Raw Response Preview: " + profRes.substring(0, Math.min(500, profRes.length())), null);
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

              String streamRes = parent.postSoap(t, targetUrl, streamSoap, "GetStreamUri", null, null, deviceOpts);
              String uri = parent.extractTag(streamRes, "Uri");
              if (uri == null)
                uri = parent.extractTag(streamRes, "tt:Uri");

              if (uri != null && !uri.isBlank()) {
                System.out.printf("Profile: %-15s | Token: %-10s | Res: %-10s | URI: %s%n",
                    profile.name, profile.token, profile.resolution, uri);
              } else {
                parent.standardOpts.info(log,
                    "Profile " + profile.name + " (Token: " + profile.token + ") returned empty URI.",
                    null);
              }
            } catch (Exception e) {
              // Log failure to info without swallowing
              parent.standardOpts.info(log, "Profile " + profile.name + " (Token: " + profile.token + ") failed.", e);
            }
          }
        } catch (Exception e) {
          throw sneakyThrow(e);
        }
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

    @Command(name = "describe", aliases = {
        "dump" }, description = "Describe camera details as JSON.", mixinStandardHelpOptions = true)
    public static class DescribeCmd implements Runnable {
      @ParentCommand
      MainCommand parent;

      @ArgGroup(exclusive = false, heading = "Global Options:%n", order = 10)
      GlobalOptions globals = new GlobalOptions();

      @ArgGroup(exclusive = false, heading = "Device Options:%n", order = 50)
      DeviceOptions deviceOpts = new DeviceOptions();

      @ArgGroup(exclusive = false, heading = "Development options:%n", order = 100)
      StandardOptions standardOpts = new StandardOptions();

      @Parameters(index = "0", arity = "0..1", description = "Device alias or URL", completionCandidates = DeviceAliasCandidates.class)
      String targetParam;

      @Option(names = "--all", description = "Include all sections.")
      boolean all;

      @Option(names = "--profiles", description = "Include GetProfiles output.", negatable = true)
      Boolean profiles;

      @Option(names = "--capabilities", description = "Include GetCapabilities output.", negatable = true)
      Boolean capabilities;

      @Option(names = "--device-info", description = "Include GetDeviceInformation output.", negatable = true)
      Boolean deviceInfo;

      @Option(names = "--system-time", description = "Include GetSystemDateAndTime output.", negatable = true)
      Boolean systemTime;

      @Option(names = "--services", description = "Include GetServices output.", negatable = true)
      Boolean services;

      @Option(names = "--event-properties", description = "Include GetEventProperties output.", negatable = true)
      Boolean eventProperties;

      @Override
      public void run() {
        DeviceProfile t = parent.resolveTarget(targetParam, deviceOpts);
        try {
          ObjectNode out = JSON_MAPPER.createObjectNode();
          boolean anyFlagSet = profiles != null || capabilities != null || deviceInfo != null || systemTime != null
              || services != null || eventProperties != null;
          boolean anyNegative = (profiles != null && !profiles) || (capabilities != null && !capabilities)
              || (deviceInfo != null && !deviceInfo) || (systemTime != null && !systemTime)
              || (services != null && !services) || (eventProperties != null && !eventProperties);
          boolean baselineAll = all || !anyFlagSet || anyNegative;

          if (baselineAll ? profiles != Boolean.FALSE : profiles == Boolean.TRUE) {
            String profilesXml = parent.postSoap(t, t.url,
                buildSoapEnvelope(t.user, t.pass, "<GetProfiles xmlns=\"http://www.onvif.org/ver10/media/wsdl\"/>"),
                "GetProfiles", null, null, deviceOpts);
            JsonNode profilesNode = XML_MAPPER.readTree(profilesXml.getBytes()).get("Body").get("GetProfilesResponse");
            out.set("profiles", profilesNode);
          }

          if (baselineAll ? capabilities != Boolean.FALSE : capabilities == Boolean.TRUE) {
            String capXml = parent.postSoap(t, t.url, buildSoapEnvelope(t.user, t.pass,
                "<GetCapabilities xmlns=\"http://www.onvif.org/ver10/device/wsdl\"><Category>All</Category></GetCapabilities>"),
                "GetCapabilities", null, null, deviceOpts);
            JsonNode cap = XML_MAPPER.readTree(capXml.getBytes()).get("Body").get("GetCapabilitiesResponse");
            out.set("capabilities", cap);
          }

          if (baselineAll ? deviceInfo != Boolean.FALSE : deviceInfo == Boolean.TRUE) {
            String infoXml = parent.postSoap(t, t.url, buildSoapEnvelope(t.user, t.pass,
                "<GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>"),
                "GetDeviceInformation", null, null, deviceOpts);
            JsonNode info = XML_MAPPER.readTree(infoXml.getBytes()).get("Body").get("GetDeviceInformationResponse");
            out.set("deviceInfo", info);
          }

          if (baselineAll ? systemTime != Boolean.FALSE : systemTime == Boolean.TRUE) {
            String timeXml = parent.postSoap(t, t.url, buildSoapEnvelope(t.user, t.pass,
                "<GetSystemDateAndTime xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>"),
                "GetSystemDateAndTime", null, null, deviceOpts);
            JsonNode time = XML_MAPPER.readTree(timeXml.getBytes()).get("Body").get("GetSystemDateAndTimeResponse");
            out.set("systemTime", time);
          }

          if (baselineAll ? services != Boolean.FALSE : services == Boolean.TRUE) {
            String servicesXml = parent.postSoap(t, t.url, buildSoapEnvelope(t.user, t.pass,
                "<GetServices xmlns=\"http://www.onvif.org/ver10/device/wsdl\"><IncludeCapability>true</IncludeCapability></GetServices>"),
                "GetServices", null, null, deviceOpts);
            JsonNode servicesNode = XML_MAPPER.readTree(servicesXml.getBytes()).get("Body").get("GetServicesResponse");
            out.set("services", servicesNode);
          }

          if (baselineAll ? eventProperties != Boolean.FALSE : eventProperties == Boolean.TRUE) {
            String eventsXml = parent.postSoap(t, t.url, buildSoapEnvelope(t.user, t.pass,
                "<GetEventProperties xmlns=\"http://www.onvif.org/ver10/events/wsdl\"/>"),
                "GetEventProperties", null, null, deviceOpts);
            JsonNode eventsNode = XML_MAPPER.readTree(eventsXml.getBytes()).get("Body")
                .get("GetEventPropertiesResponse");
            out.set("eventProperties", eventsNode);
          }

          System.out.println(JSON_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(out));
        } catch (Exception e) {
          throw sneakyThrow(e);
        }
      }
    }

    @Command(name = "events", description = "Stream ONVIF events as JSON.")
    public static class EventsCmd implements Runnable {
      @ParentCommand
      MainCommand parent;

      @ArgGroup(exclusive = false, heading = "Global Options:%n", order = 10)
      GlobalOptions globals = new GlobalOptions();

      @ArgGroup(exclusive = false, heading = "Device Options:%n", order = 50)
      DeviceOptions deviceOpts = new DeviceOptions();

      @ArgGroup(exclusive = false, heading = "Development options:%n", order = 100)
      StandardOptions standardOpts = new StandardOptions();

      @Parameters(index = "0", arity = "0..1", description = "Device alias or URL", completionCandidates = DeviceAliasCandidates.class)
      String targetParam;

      @Option(names = "--pull-timeout", defaultValue = "10", description = "PullMessages timeout in seconds. Devices may close the connection if no messages are available within this time and might anyway max it out to 10s.")
      int pullTimeout;

      @Option(names = "--limit", defaultValue = "50", description = "Message limit per PullMessages call.")
      int messageLimit;

      @Option(names = "--once", description = "Exit after a single PullMessages call.")
      boolean once;

      @Override
      public void run() {
        DeviceProfile t = parent.resolveTarget(targetParam, deviceOpts);
        try {
          if (pullTimeout > 10) {
            log.warn("PullMessages timeout {}s exceeds 10s; some devices close early (EOF).", pullTimeout);
          }
          String capRes = parent.postSoap(t, t.url, buildSoapEnvelope(t.user, t.pass,
              "<GetCapabilities xmlns=\"http://www.onvif.org/ver10/device/wsdl\"><Category>All</Category></GetCapabilities>"),
              "GetCapabilities", null, null, deviceOpts);
          SoapEnvelope capEnv = parent.xmlToEnvelope(capRes);
          String eventsUrl = capEnv.getEventsXAddr();
          if (eventsUrl == null || eventsUrl.isBlank())
            throw new RuntimeException("No Events XAddr from GetCapabilities.");
          if (!capEnv.isPullPointSupported())
            throw new RuntimeException("Device does not support PullPoint subscriptions.");

          log.info("Subscribing to: {}", eventsUrl);
          String subSoap = buildSoapEnvelope(t.user, t.pass,
              "<CreatePullPointSubscription xmlns=\"http://www.onvif.org/ver10/events/wsdl\"/>");
          String subRes = parent.postSoap(t, eventsUrl, subSoap, "CreatePullPointSubscription", null, null, deviceOpts);
          SoapEnvelope subEnv = parent.xmlToEnvelope(subRes);
          String subAddr = subEnv.getSubscriptionAddress();
          if (subAddr == null)
            throw new RuntimeException("Subscription failed. No address returned.");

          log.info("Subscription created: {}", subAddr);

          while (true) {
            try {
              String pullSoap = buildSoapEnvelope(t.user, t.pass,
                  "<PullMessages xmlns=\"http://www.onvif.org/ver10/events/wsdl\">" +
                      "<Timeout>PT" + pullTimeout + "S</Timeout>" +
                      "<MessageLimit>" + messageLimit + "</MessageLimit></PullMessages>");

              String pullRes = parent.postSoap(t, subAddr, pullSoap, "PullMessages", null, null, deviceOpts);
              SoapEnvelope pullEnv = parent.xmlToEnvelope(pullRes);

              PullMessagesResponse pmRes = pullEnv.getPullMessagesResponse();
              JsonNode msgs = pmRes != null ? pmRes.NotificationMessage : null;
              if (msgs != null && msgs.isArray()) {
                for (JsonNode msg : msgs) {
                  System.out.println(JSON_MAPPER.writeValueAsString(msg));
                }
              } else if (msgs != null && !msgs.isNull()) {
                System.out.println(JSON_MAPPER.writeValueAsString(msgs));
              }

              if (once)
                break;
            } catch (Exception e) {
              if (e.getMessage().contains("EOF") || e.getMessage().contains("Stream closed")) {
                log.warn("Connection lost, retrying pull... ({})", e.getMessage());
                continue;
              }
              throw e;
            }
          }
        } catch (Exception e) {
          throw sneakyThrow(e);
        }
      }
    }

    // --- INTERNAL HELPERS ---
    private DeviceProfile resolveTarget(String positionalValue) {
      return resolveTarget(positionalValue, null);
    }

    private DeviceProfile resolveTarget(String positionalValue, DeviceOptions local) {
      String positionalAlias = (positionalValue != null && cfg.devices.containsKey(positionalValue))
          ? positionalValue
          : null;
      String positionalUrl = null;
      if (positionalValue != null && positionalAlias == null) {
        try {
          URI uri = URI.create(positionalValue);
          if (uri.getScheme() == null || uri.getHost() == null)
            throw new IllegalArgumentException("Missing scheme or host");
          positionalUrl = positionalValue;
        } catch (IllegalArgumentException e) {
          throw new RuntimeException("Unknown device alias or invalid URL: " + positionalValue);
        }
      }

      String deviceOverride = (local != null && local.device != null) ? local.device : deviceOpts.device;
      String targetName = (deviceOverride != null) ? deviceOverride
          : (positionalAlias != null ? positionalAlias : cfg.activeDevice);
      boolean hasAlias = targetName != null && !targetName.isBlank();

      if (hasAlias && !cfg.devices.containsKey(targetName))
        throw new RuntimeException("Unknown alias: " + targetName + ". Run 'device list' or 'device register'.");
      if (!hasAlias && positionalValue == null)
        throw new RuntimeException("No device selected. Run 'device use <alias>' or pass URL.");

      DeviceProfile profile = hasAlias ? cfg.devices.get(targetName) : new DeviceProfile();
      DeviceProfile t = new DeviceProfile();
      t.alias = hasAlias ? targetName : "direct";
      t.url = (positionalUrl != null) ? positionalUrl : profile.url;

      String userOverride = (local != null && local.user != null) ? local.user : deviceOpts.user;
      String passOverride = (local != null && local.pass != null) ? local.pass : deviceOpts.pass;

      t.user = (userOverride != null) ? userOverride : profile.user;
      t.pass = (passOverride != null) ? passOverride : profile.pass;

      if (t.url == null)
        throw new RuntimeException("Target URL missing. Run 'device register' or pass URL.");
      if (t.user == null || t.pass == null)
        throw new RuntimeException("Credentials missing. Use -u/-p or 'device update'.");
      return t;
    }

    private SoapEnvelope xmlToEnvelope(String xml) {
      try {
        JsonNode raw = XML_MAPPER.readTree(xml.getBytes());
        JsonNode normalized = normalizeJson(raw);
        JsonNode envelopeNode = normalized;
        if (normalized.isObject() && normalized.has("Envelope"))
          envelopeNode = normalized.get("Envelope");
        return JSON_MAPPER.treeToValue(envelopeNode, SoapEnvelope.class);
      } catch (Exception e) {
        throw sneakyThrow(e);
      }
    }

    private JsonNode normalizeJson(JsonNode node) {
      if (node == null)
        return NullNode.instance;
      if (node.isObject()) {
        ObjectNode out = JSON_MAPPER.createObjectNode();
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
          Map.Entry<String, JsonNode> entry = fields.next();
          String key = stripPrefix(entry.getKey());
          JsonNode value = normalizeJson(entry.getValue());
          if (out.has(key)) {
            JsonNode existing = out.get(key);
            ArrayNode arr;
            if (existing.isArray()) {
              arr = (ArrayNode) existing;
            } else {
              arr = JSON_MAPPER.createArrayNode();
              arr.add(existing);
              out.set(key, arr);
            }
            if (value.isArray()) {
              arr.addAll((ArrayNode) value);
            } else {
              arr.add(value);
            }
          } else {
            out.set(key, value);
          }
        }
        return out;
      }
      if (node.isArray()) {
        ArrayNode arr = JSON_MAPPER.createArrayNode();
        for (JsonNode item : node) {
          arr.add(normalizeJson(item));
        }
        return arr;
      }
      return node;
    }

    private String stripPrefix(String name) {
      int idx = name.indexOf(':');
      return idx >= 0 ? name.substring(idx + 1) : name;
    }

    private String extractTopic(JsonNode topic) {
      if (topic == null)
        return null;
      if (topic.isTextual())
        return topic.asText();
      JsonNode content = topic.get("content");
      if (content != null) {
        if (content.isTextual())
          return content.asText();
        if (content.isArray() && content.size() > 0 && content.get(0).isTextual())
          return content.get(0).asText();
      }
      return topic.toString().replace("\"", "");
    }

    private java.util.List<NotificationMessage> normalizeMessages(JsonNode node) {
      if (node == null || node.isNull())
        return java.util.Collections.emptyList();
      if (node.isArray()) {
        java.util.List<NotificationMessage> list = new java.util.ArrayList<>();
        for (JsonNode item : node) {
          list.add(JSON_MAPPER.convertValue(item, NotificationMessage.class));
        }
        return list;
      }
      return java.util.Collections.singletonList(JSON_MAPPER.convertValue(node, NotificationMessage.class));
    }

    private String postSoap(DeviceProfile t, String url, String xml, String action) {
      return postSoap(t, url, xml, action, null, null, null);
    }

    private String postSoap(DeviceProfile t, String url, String xml, String action, String soapAction) {
      return postSoap(t, url, xml, action, soapAction, null, null);
    }

    private String postSoap(DeviceProfile t, String url, String xml, String action, String soapAction,
        String contentTypeOverride, DeviceOptions local) {
      log.trace("[{}] [{}] POST {}: {}", t.alias, action, url, xml);
      int attempts = 0;
      int maxRetries = getEffectiveRetries(local);
      try {
        while (true) {
          try {
            attempts++;

            HttpClient client = HttpClient.newBuilder()
                .connectTimeout(java.time.Duration.ofSeconds(getEffectiveTimeout(local)))
                .version(HttpClient.Version.HTTP_1_1)
                .build();
            String contentType = contentTypeOverride != null ? contentTypeOverride
                : "application/soap+xml; charset=utf-8";
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .POST(HttpRequest.BodyPublishers.ofString(xml));
            builder.header("User-Agent", "Mozilla/5.0 (Linux)");
            if (soapAction != null) {
              if (contentTypeOverride == null) {
                contentType = contentType + "; action=\"" + soapAction + "\"";
              }
              builder.header("SOAPAction", soapAction);
            }

            HttpRequest request = builder.header("Content-Type", contentType).build();

            log.debug("[{}] [{}] POST {} attempt {}/{}", t.alias, action, url, attempts, maxRetries);
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
              String body = response.body();
              // If it's a 401 Unauthorized, don't bother retrying
              if (response.statusCode() == 401)
                throw new RuntimeException("Authentication failed (401): [" + body + "]");
              throw new RuntimeException("HTTP " + response.statusCode() + ": [" + body + "]");
            }
            log.trace("[{}] [{}] POST {} response: {}", t.alias, action, url, response.body());
            return response.body();
          } catch (Exception e) {
            if (action != null && action.startsWith("PullMessages") && isNoBytesException(e))
              throw sneakyThrow(e);
            if (attempts >= maxRetries)
              throw sneakyThrow(e); // Last attempt failed, propagate
            String errorMsg = e.getMessage() != null ? e.getMessage() : e.toString();
            log.warn("[{}] [{}] POST {} attempt {}/{} failed: {}. Retrying.... Enable trace for full stacktrace.",
                t.alias, action, url, attempts, maxRetries, errorMsg);
            log.trace("[{}] [{}] POST {} attempt {}/{} failed. Retrying...", t.alias, action, url, attempts,
                maxRetries,
                e);
            Thread.sleep(500); // Small backoff
          }
        }
      } catch (InterruptedException e) {
        throw sneakyThrow(e);
      }
    }

    private boolean isNoBytesException(Throwable e) {
      Throwable cause = (e instanceof RuntimeException && e.getCause() != null) ? e.getCause() : e;
      return cause instanceof IOException && cause.getMessage() != null
          && cause.getMessage().contains("HTTP/1.1 header parser received no bytes");
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

    public static String buildSoapEnvelope(String user, String pass, String body, String wsaAction, String wsaTo) {
      try {
        // Use a 16-byte random nonce as per WS-Security spec
        byte[] nonceBytes = new byte[16];
        new SecureRandom().nextBytes(nonceBytes);
        String nonce = Base64.getEncoder().encodeToString(nonceBytes);

        String created = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
        String digest = calculateDigest(nonce, created, pass);
        String messageId = "uuid:" + UUID.randomUUID();

        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">" +
            "<s:Header>" +
            "<Security s:mustUnderstand=\"1\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
            +
            "<UsernameToken><Username>" + user + "</Username>" +
            "<Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">"
            + digest + "</Password>" +
            "<Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">"
            + nonce + "</Nonce>" +
            "<Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
            + created + "</Created>" +
            "</UsernameToken></Security>" +
            "<wsa:Action xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">" + wsaAction
            + "</wsa:Action>" +
            "<wsa:MessageID xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">" + messageId
            + "</wsa:MessageID>" +
            "<wsa:To xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">" + wsaTo + "</wsa:To>" +
            "</s:Header>" +
            "<s:Body>" + body + "</s:Body></s:Envelope>";
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }

    private void sendProbes(InetAddress source, Set<String> initial, Set<String> discovered, Set<String> discoveredNew,
        boolean silent, DeviceOptions local) {
      int effTimeout = getEffectiveTimeout(local);
      int effRetries = getEffectiveRetries(local);
      int windowMillis = (effTimeout * 1000) / effRetries;

      try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(source, 0))) {
        socket.setSoTimeout(windowMillis);

        String probeXml = buildProbeXml();
        byte[] data = probeXml.getBytes(StandardCharsets.UTF_8);
        DatagramPacket packet = new DatagramPacket(data, data.length,
            InetAddress.getByName("239.255.255.250"), 3702);

        for (int i = 0; i < effRetries; i++) {
          log.debug("Sending probe from {} (attempt {}/{})", source.getHostAddress(), i + 1, effRetries);
          socket.send(packet);
          long windowEnd = System.currentTimeMillis() + windowMillis;

          while (System.currentTimeMillis() < windowEnd) {
            try {
              byte[] buf = new byte[8192];
              DatagramPacket reply = new DatagramPacket(buf, buf.length);
              socket.receive(reply);

              String xml = new String(reply.getData(), 0, reply.getLength(), StandardCharsets.UTF_8);
              String url = extractUrl(xml);

              if (url != null)
                if (!discovered.add(url))
                  log.debug("Duplicate device ignored: {}", url);
                else if (initial.contains(url))
                  log.info("Found configured device: {}", url);
                else if (discoveredNew.add(url))
                  if (!silent)
                    System.out.println(url);
                  else
                    log.info("Found device: {}", url);
                else
                  log.debug("Duplicate new device ignored: {}", url);
              else
                log.info("Received reply without URL: {}", xml);
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

  static class DeviceAliasCandidates implements Iterable<String> {
    private static volatile Config cachedConfig;

    @Spec
    Model.CommandSpec spec;

    static void setConfig(Config cfg) {
      cachedConfig = cfg;
    }

    @Override
    public Iterator<String> iterator() {
      if (spec != null) {
        Object root = spec.commandLine().getCommandSpec().root().userObject();
        if (root instanceof MainCommand) {
          return ((MainCommand) root).cfg.devices.keySet().iterator();
        }
      }
      if (cachedConfig != null) {
        return cachedConfig.devices.keySet().iterator();
      }
      return Collections.emptyIterator();
    }
  }

  static class SoapEnvelope {
    public SoapBody Body;

    String getEventsXAddr() {
      if (Body == null || Body.GetCapabilitiesResponse == null || Body.GetCapabilitiesResponse.Capabilities == null)
        return null;
      if (Body.GetCapabilitiesResponse.Capabilities.Events == null)
        return null;
      return Body.GetCapabilitiesResponse.Capabilities.Events.XAddr;
    }

    boolean isPullPointSupported() {
      if (Body == null || Body.GetCapabilitiesResponse == null || Body.GetCapabilitiesResponse.Capabilities == null)
        return false;
      EventsCap events = Body.GetCapabilitiesResponse.Capabilities.Events;
      if (events == null || events.WSPullPointSupport == null)
        return false;
      return Boolean.parseBoolean(events.WSPullPointSupport);
    }

    String getSubscriptionAddress() {
      if (Body == null || Body.CreatePullPointSubscriptionResponse == null)
        return null;
      if (Body.CreatePullPointSubscriptionResponse.SubscriptionReference == null)
        return null;
      return Body.CreatePullPointSubscriptionResponse.SubscriptionReference.Address;
    }

    PullMessagesResponse getPullMessagesResponse() {
      return Body != null ? Body.PullMessagesResponse : null;
    }
  }

  static class SoapBody {
    public GetCapabilitiesResponse GetCapabilitiesResponse;
    public CreatePullPointSubscriptionResponse CreatePullPointSubscriptionResponse;
    public PullMessagesResponse PullMessagesResponse;
  }

  static class GetCapabilitiesResponse {
    public Capabilities Capabilities;
  }

  static class Capabilities {
    public EventsCap Events;
  }

  static class EventsCap {
    public String XAddr;
    public String WSPullPointSupport;
  }

  static class CreatePullPointSubscriptionResponse {
    public SubscriptionReference SubscriptionReference;
  }

  static class SubscriptionReference {
    public String Address;
  }

  static class PullMessagesResponse {
    public JsonNode NotificationMessage;
  }

  static class NotificationMessage {
    public JsonNode Topic;
    public JsonNode Message;
  }

  // --- PROCESS EXECUTOR HELPER ---
  public static void exec(List<String> cmd, boolean allowPass, boolean dryRun) {
    if (!allowPass) {
      List<String> masked = new ArrayList<>();
      for (String arg : cmd) {
        if (arg.startsWith("rtsp://")) {
          // Mask password: rtsp://user:pass@host -> rtsp://user:****@host
          masked.add(arg.replaceAll("(?<=//)([^:@]+):([^@]+)@", "$1:****@"));
        } else {
          masked.add(arg);
        }
      }
      log.info("Executing: {}", String.join(" ", masked));
    } else {
      log.info("Executing: {}", String.join(" ", cmd));
    }

    if (dryRun)
      return;

    try {
      new org.zeroturnaround.exec.ProcessExecutor()
          .command(cmd)
          .redirectOutput(System.out)
          .redirectError(System.err)
          .destroyOnExit() // Ensure process is killed on JVM exit (Ctrl+C)
          .execute();
    } catch (Exception e) {
      throw new RuntimeException("Execution failed: " + e.getMessage(), e);
    }
  }
}