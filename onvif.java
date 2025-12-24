///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.7.5
//DEPS org.slf4j:slf4j-api:2.0.9
//DEPS ch.qos.logback:logback-classic:1.4.11
//SOURCES com/namekis/utils/RichLogback.java

import picocli.CommandLine;
import picocli.CommandLine.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.namekis.utils.RichLogback;

import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;
import java.util.stream.Collectors;

public class onvif {
  private static final Logger log = LoggerFactory.getLogger("onvif");

  public static void main(String[] args) {
    RichLogback.configureLogbackByVerbosity(args);
    int exitCode = new CommandLine(new MainCommand()).execute(args);
    System.exit(exitCode);
  }

  /**
   * Terminating sneaky throw. Use as: throw sneakyThrow(e);
   */
  @SuppressWarnings("unchecked")
  public static <E extends Throwable> RuntimeException sneakyThrow(Throwable e) throws E {
    throw (E) e;
  }

  @Command(name = "onvif", mixinStandardHelpOptions = true, version = "1.4.0")
  public static class MainCommand extends RichLogback.BaseOptions implements Runnable {

    @Option(names = { "-t", "--timeout" }, description = "Total seconds to listen", defaultValue = "5")
    private int timeout;

    @Option(names = { "-r", "--retries" }, description = "Probes per interface", defaultValue = "3")
    private int retries;

    @Spec
    Model.CommandSpec spec;

    @Override
    public void run() {
      discover();
    }

    @Command(description = "Discover ONVIF devices via WS-Discovery.")
    public void discover() {
      log.info("Starting discovery (Timeout: {}s, Retries: {})...", timeout, retries);

      Set<String> discovered = Collections.synchronizedSet(new HashSet<>());
      List<InetAddress> interfaces = getActiveIPv4Interfaces();

      log.info("Probing via: {}",
          interfaces.stream().map(InetAddress::getHostAddress).collect(Collectors.joining(", ")));

      ExecutorService executor = Executors.newFixedThreadPool(interfaces.size());
      try {
        List<CompletableFuture<Void>> futures = interfaces.stream()
            .map(addr -> CompletableFuture.runAsync(() -> {
              try {
                sendProbes(addr, discovered);
              } catch (Exception e) {
                log.debug("Interface {} failed, but moving on...", addr);
                // We don't throw here to avoid killing other interface probes
              }
            }, executor))
            .collect(Collectors.toList());

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

      } catch (Exception e) {
        log.error("Global discovery failure");
        throw sneakyThrow(e); // Terminating sneaky throw
      } finally {
        executor.shutdown();
      }

      log.info("Discovery finished. Found {} unique devices.", discovered.size());
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
