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

import picocli.CommandLine;
import org.junit.jupiter.api.Test;

import com.namekis.utils.RichLogback;

public class onvif_test {
  public static void main(String... allArgs) {
    RichLogback.main(allArgs, args -> {
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
      System.out.println(result.output);
      assertThat(result.exitCode).isEqualTo(0);
      assertThat(result.output).contains("Profile:");
      assertThat(result.output).contains("rtsp://");
    }

    @Test
    void dumpByDeviceAliasPrintsProfiles() {
      CommandResult result = runCommand("dump", "-d", "cam-21");
      assertThat(result.exitCode).isEqualTo(0);
      assertThat(result.output).contains("PTZConfiguration");
      assertThat(result.output).contains("mainStream");
    }
  }
}
