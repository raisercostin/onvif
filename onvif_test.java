///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS org.junit.jupiter:junit-jupiter:5.11.3
//DEPS org.assertj:assertj-core:3.26.3
//DEPS org.junit.jupiter:junit-jupiter-engine:5.11.3
//DEPS org.junit.platform:junit-platform-launcher:1.11.3
//DEPS org.junit.platform:junit-platform-console:1.11.3
//SOURCES onvif.java

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.List;
import java.util.stream.Collectors;

import picocli.CommandLine;
import org.junit.jupiter.api.Test;

import com.namekis.utils.RichCli;

public class onvif_test {
  public static void main(String... allArgs) {
    RichCli.main(allArgs, args -> {
      java.util.List<String> fullArgs = new java.util.ArrayList<>(java.util.List.of(args));
      if (args.length == 0) {
        fullArgs.add("execute");
        fullArgs.add("--scan-class-path");
      }
      fullArgs.add(System.getProperty("java.class.path"));
      fullArgs.add("--disable-banner");
      org.junit.platform.console.ConsoleLauncher.main(fullArgs.toArray(String[]::new));
    });
  }

  public static class SoapEnvelopeTests {
    @Test
    void calculateDigestUsesDecodedNonce() {
      String digest = onvif.MainCommand.calculateDigest("YWJj", "2025-01-01T00:00:00Z", "secret");
      assertThat(digest).isEqualTo("FCPfOPRH4WNNQI8woihtHqioTzA=");
    }

    @Test
    void buildSoapEnvelopeContainsBodyAndUsername() {
      String body = "<GetCapabilities/>";
      String xml = onvif.MainCommand.buildSoapEnvelope("admin", "pass", body);
      assertThat(xml).contains(body);
      assertThat(xml).contains("<Username>admin</Username>");
      assertThat(xml).contains("PasswordDigest");
      assertThat(xml).contains("<s:Envelope");
      assertThat(xml).contains("<s:Body>");
    }
  }

  static class CommandResult {
    final int exitCode;
    final String output;

    CommandResult(int exitCode, String output) {
      this.exitCode = exitCode;
      this.output = output;
    }
  }

  static CommandResult runCommand(String... args) {
    ByteArrayOutputStream outBuffer = new ByteArrayOutputStream();
    ByteArrayOutputStream errBuffer = new ByteArrayOutputStream();
    PrintStream originalOut = System.out;
    PrintStream originalErr = System.err;
    try {
      System.setOut(new PrintStream(outBuffer));
      System.setErr(new PrintStream(errBuffer));
      int exitCode = new CommandLine(new onvif.MainCommand()).execute(args);
      String output = outBuffer.toString() + errBuffer.toString();
      return new CommandResult(exitCode, output);
    } finally {
      System.setOut(originalOut);
      System.setErr(originalErr);
    }
  }

  public static class CommandTests {
    @Test
    void deviceListShowsHeader() {
      CommandResult result = runCommand("device", "list");
      assertThat(result.exitCode).isEqualTo(0);
      assertThat(result.output).contains("ALIAS");
      assertThat(result.output).contains("URL");
    }

    @Test
    void deviceUseSetsActiveAlias() {
      CommandResult result = runCommand("device", "use", "cam-21");
      assertThat(result.exitCode).isEqualTo(0);
      assertThat(result.output).contains("Active device: cam-21");
    }

    @Test
    void streamByDeviceAliasPrintsProfiles() {
      CommandResult result = runCommand("stream", "-d", "cam-21");
      System.out.println(result.output); // Debug help
      assertThat(result.exitCode).isEqualTo(0);
      assertThat(result.output).contains("Profile:");
      assertThat(result.output).contains("rtsp://");
    }

    @Test
    void describeByDeviceAliasPrintsProfiles() {
      CommandResult result = runCommand("describe", "-d", "cam-21");
      assertThat(result.exitCode).isEqualTo(0);
      assertThat(result.output).contains("PTZConfiguration");
      assertThat(result.output).contains("mainStream");
    }
  }

  public static class MediaCommandTests {
    // Requires onvif.java to have a 'mock' device or we rely on 'cam-21' being
    // present in the user's config
    // We'll use 'cam-21' since it's in the committed config and proven by existing
    // tests.

    @Test
    void playCommandGeneratesVlcLog() {
      // Dry-run should log the command but not execute it.
      CommandResult result = runCommand("play", "cam-21", "--dry-run");
      System.out.println("play output: " + result.output);
      // Expect 0 exit code if command is implemented
      assertThat(result.exitCode).as("Check play command exists. Output: " + result.output).isEqualTo(0);
      // Expect log with masked password
      assertThat(result.output).contains("Executing: vlc rtsp://costin:****@192.168.1.21");
    }

    @Test
    void playCommandUnmaskedWithAllowPass() {
      CommandResult result = runCommand("play", "cam-21", "--dry-run", "--allow-pass");
      assertThat(result.exitCode).isEqualTo(0);
      // Expect log with visible password (dummy credentials from config)
      // Note: We don't know the exact password in the test env easily without reading
      // config,
      // but we know it should NOT be ****
      assertThat(result.output).contains("vlc rtsp://costin:");
      assertThat(result.output).doesNotContain("****");
    }

    @Test
    void snapshotCommandGeneratesFfmpegLog() {
      CommandResult result = runCommand("snapshot", "cam-21", "--dry-run");
      assertThat(result.exitCode).isEqualTo(0);
      assertThat(result.output).contains("Executing: ffmpeg -y -i rtsp://costin:****@192.168.1.21");
      assertThat(result.output).contains("-vframes 1");
      assertThat(result.output).contains(".jpg"); // Default extension
    }

    @Test
    void recordCommandGeneratesFfmpegLog() {
      CommandResult result = runCommand("record", "cam-21", "--dry-run");
      assertThat(result.exitCode).isEqualTo(0);
      assertThat(result.output).contains("Executing: ffmpeg -rtsp_transport tcp -i rtsp://costin:****@192.168.1.21");
      assertThat(result.output).contains("-c copy");
    }

    @Test
    void recordHelpOutputOrder() {
      // Use --no-color to avoid ANSI codes in output
      CommandResult result = runCommand("record", "-h", "--no-color");
      assertThat(result.exitCode).isEqualTo(0);

      List<String> lines = result.output.lines().collect(Collectors.toList());

      int segmentIndex = -1;
      int globalsIndex = -1;
      int debugIndex = -1;

      for (int i = 0; i < lines.size(); i++) {
        String line = lines.get(i);
        if (line.contains("--segment"))
          segmentIndex = i;
        if (line.contains("Global Options:"))
          globalsIndex = i;
        if (line.contains("--debug"))
          debugIndex = i;
      }

      // Verify ordering: Specifics -> Globals -> Standard
      assertThat(segmentIndex).as("--segment should be present").isGreaterThan(-1);
      assertThat(globalsIndex).as("Global Options should be present").isGreaterThan(-1);
      assertThat(debugIndex).as("--debug should be present").isGreaterThan(-1);

      assertThat(segmentIndex).as("Specifics should come before Global Options").isLessThan(globalsIndex);
      assertThat(globalsIndex).as("Global Options should come before Standard Options (Debug)").isLessThan(debugIndex);
    }
  }
}
