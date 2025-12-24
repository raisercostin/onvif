///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.7.5
//DEPS org.slf4j:slf4j-api:2.0.9
//DEPS ch.qos.logback:logback-classic:1.4.11
//DEPS com.fasterxml.jackson.dataformat:jackson-dataformat-xml:2.15.2
//DEPS com.fasterxml.jackson.core:jackson-databind:2.15.2
//SOURCES com/namekis/utils/RichLogback.java

import picocli.CommandLine;
import picocli.CommandLine.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.namekis.utils.RichLogback;

import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;
import java.util.stream.Collectors;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;

public class onvif {
  private static final Logger log = LoggerFactory.getLogger("onvif");

  public static void main(String[] args) {
    RichLogback.configureLogbackByVerbosity(args);
    int exitCode = new CommandLine(new MainCommand()).execute(args);
    System.exit(exitCode);
  }

  @SuppressWarnings("unchecked")
  public static <E extends Throwable> RuntimeException sneakyThrow(Throwable e) throws E {
    throw (E) e;
  }

  @Command(name = "onvif", mixinStandardHelpOptions = true, version = "0.1.0")
  public static class MainCommand extends RichLogback.BaseOptions implements Runnable {

    @Option(names = { "-t", "--timeout" }, defaultValue = "5")
    private int timeout;

    @Option(names = { "-r", "--retries" }, defaultValue = "3")
    private int retries;

    @Spec
    Model.CommandSpec spec;

    @Override
    public void run() {
      discover();
    }

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

    @Command(description = "Get all available RTSP Stream URIs with full profile details.")
    public void stream(
        @Parameters(description = "Device Service URL") String url,
        @Option(names = { "-u", "--user" }, required = true) String user,
        @Option(names = { "-p", "--pass" }, required = true) String pass) {
      try {
        // 1. Aflăm Media Service XAddr (GetCapabilities)
        String capSoap = buildSoapEnvelope(user, pass,
            "<GetCapabilities xmlns=\"http://www.onvif.org/ver10/device/wsdl\"><Category>Media</Category></GetCapabilities>");
        String capRes = postSoap(url, capSoap);
        String mediaUrl = extractTag(capRes, "tt:XAddr");
        String targetUrl = (mediaUrl != null) ? mediaUrl : url;

        log.debug("Using Media Service URL: {}", targetUrl);

        // 2. Extragem toate Profilele
        String profilesSoap = buildSoapEnvelope(user, pass,
            "<GetProfiles xmlns=\"http://www.onvif.org/ver10/media/wsdl\"/>");
        String profRes = postSoap(targetUrl, profilesSoap);

        // Parsăm profilele și detaliile lor (Nume, Rezoluție, Token)
        List<OnvifProfile> profiles = parseProfiles(profRes);

        if (profiles.isEmpty()) {
          System.err.println("No media profiles found for this device.");
          return;
        }

        // 3. Pentru fiecare profil, cerem URI-ul de stream
        for (OnvifProfile profile : profiles) {
          String streamSoap = buildSoapEnvelope(user, pass,
              "<GetStreamUri xmlns=\"http://www.onvif.org/ver10/media/wsdl\">" +
                  "<StreamSetup><Stream xmlns=\"http://www.onvif.org/ver10/schema\">RTP-Unicast</Stream>" +
                  "<Transport xmlns=\"http://www.onvif.org/ver10/schema\"><Protocol>RTSP</Protocol></Transport></StreamSetup>"
                  +
                  "<ProfileToken>" + profile.token + "</ProfileToken></GetStreamUri>");

          String streamRes = postSoap(targetUrl, streamSoap);
          String rtspUri = extractTag(streamRes, "tt:Uri");

          // Afișăm detaliile complete
          System.out.printf("Profile: %-15s | Token: %-10s | Res: %-10s | URI: %s%n",
              profile.name, profile.token, profile.resolution, rtspUri);
        }
      } catch (Exception e) {
        throw sneakyThrow(e);
      }
    }

    // Inside your MainCommand class:
    @Command(description = "Dump full camera profiles as JSON.")
    public void dump(
        @Parameters(description = "Device Service URL") String url, @Option(names = { "-u", "--user" }) String user,
        @Option(names = { "-p", "--pass" }) String pass) {
      try {
        String soap = buildSoapEnvelope(user, pass, "<GetProfiles xmlns=\"http://www.onvif.org/ver10/media/wsdl\"/>");
        String xmlResponse = postSoap(url, soap);

        XmlMapper xmlMapper = new XmlMapper();
        JsonNode node = xmlMapper.readTree(xmlResponse.getBytes());

        // Extract just the Profiles part of the SOAP Body
        JsonNode profiles = node.get("Body").get("GetProfilesResponse");

        ObjectMapper jsonMapper = new ObjectMapper();
        System.out.println(jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(profiles));
      } catch (Exception e) {
        throw sneakyThrow(e);
      }
    }

    // Helper class pentru a stoca detaliile profilului
    static class OnvifProfile {
      String token, name, resolution;
    }

    private List<OnvifProfile> parseProfiles(String xml) {
      log.debug("Parsing {}", xml);
      List<OnvifProfile> list = new ArrayList<>();
      // Regex mai robust pentru a prinde profilele și rezoluțiile
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
      // Fallback dacă rezoluția nu e în XML-ul simplificat
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

    private String postSoap(String url, String xml) throws Exception {
      log.debug("POST to {}: {}", url, xml);
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
        throw new RuntimeException("HTTP Error " + response.statusCode() + ": " + response.body());
      }
      return response.body();
    }

    private String fetchOnvifStreamUri(String url, String user, String pass) throws Exception {
      // Step 1: Request Media Profiles
      String profilesSoap = buildSoapEnvelope(user, pass,
          "<GetProfiles xmlns=\"http://www.onvif.org/ver10/media/wsdl\"/>");

      String response = postSoap(url, profilesSoap);

      // Step 2: Extract the first ProfileToken (usually 'main', 'Profile_1', etc.)
      Matcher m = Pattern.compile("token=\"([^\"]+)\"").matcher(response);
      if (!m.find())
        throw new RuntimeException("No profiles found in camera response.");
      String token = m.group(1);
      log.debug("Using profile token: {}", token);

      // Step 3: Request Stream URI for that token
      String streamSoap = buildSoapEnvelope(user, pass,
          "<GetStreamUri xmlns=\"http://www.onvif.org/ver10/media/wsdl\">" +
              "<StreamSetup><Stream xmlns=\"http://www.onvif.org/ver10/schema\">RTP-Unicast</Stream>" +
              "<Transport xmlns=\"http://www.onvif.org/ver10/schema\"><Protocol>RTSP</Protocol></Transport></StreamSetup>"
              +
              "<ProfileToken>" + token + "</ProfileToken></GetStreamUri>");

      String streamResponse = postSoap(url, streamSoap);
      Matcher uriMatcher = Pattern.compile("<tt:Uri>(.*?)</tt:Uri>").matcher(streamResponse);
      if (!uriMatcher.find())
        throw new RuntimeException("Could not extract Stream URI from response.");

      return uriMatcher.group(1);
    }

    private String buildSoapEnvelope(String user, String pass, String body) throws Exception {
      String nonce = Base64.getEncoder().encodeToString(UUID.randomUUID().toString().getBytes());
      String created = Instant.now().toString();
      String digest = calculateDigest(nonce, created, pass);

      return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
          "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
          +
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
    }

    private String calculateDigest(String nonceBase64, String created, String password) throws Exception {
      byte[] nonce = Base64.getDecoder().decode(nonceBase64);
      byte[] createdBytes = created.getBytes(StandardCharsets.UTF_8);
      byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);

      MessageDigest md = MessageDigest.getInstance("SHA-1");
      md.update(nonce);
      md.update(createdBytes);
      md.update(passwordBytes);
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
              // Loop check
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
        throw sneakyThrow(e); // Terminating sneaky throw
      }
    }

    private String buildProbeXml() {
      return "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
          "<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\" " +
          "xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" " +
          "xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\">" +
          "<e:Header><w:MessageID>uuid:" + UUID.randomUUID() + "</w:MessageID>" +
          "<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>" +
          "<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>" +
          "<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>";
    }

    private String extractUrl(String xml) {
      Matcher m = Pattern.compile("(http://[0-9\\.:]+/onvif/[a-zA-Z0-9_]+)").matcher(xml);
      return m.find() ? m.group(1) : null;
    }
  }
}
