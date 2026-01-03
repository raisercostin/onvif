///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS org.junit.jupiter:junit-jupiter:5.11.3
//DEPS org.assertj:assertj-core:3.26.3
//DEPS org.junit.jupiter:junit-jupiter-engine:5.11.3
//DEPS org.junit.platform:junit-platform-launcher:1.11.3
//DEPS org.junit.platform:junit-platform-console:1.11.3
//SOURCES iot.java

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.List;
import java.util.stream.Collectors;

import picocli.CommandLine;
import org.junit.jupiter.api.Test;

import com.namekis.utils.RichCli;

public class iot_test {
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
      int exitCode = new CommandLine(new iot()).execute(args);
      String output = outBuffer.toString() + errBuffer.toString();
      return new CommandResult(exitCode, output);
    } finally {
      System.setOut(originalOut);
      System.setErr(originalErr);
    }
  }

  public static class ProbeTests {
    @Test
    void listProbes() {
      CommandResult result = runCommand("probes");
      assertThat(result.exitCode).isEqualTo(0);
      assertThat(result.output).contains("onvif");
      assertThat(result.output).contains("innova");
      assertThat(result.output).contains("modbus");
    }

    @Test
    void deviceList() {
      CommandResult result = runCommand("device", "list");
      assertThat(result.exitCode).isEqualTo(0);
      // Can be empty or show header
      if (result.output.contains("No devices registered")) {
          assertThat(result.output).contains("No devices registered");
      } else {
          assertThat(result.output).contains("ALIAS");
      }
    }

    @Test
    void modbusActions() {
      CommandResult result = runCommand("actions", "modbus");
      assertThat(result.exitCode).isEqualTo(0);
      assertThat(result.output).contains("poll");
      assertThat(result.output).contains("write");
      assertThat(result.output).contains("--address");
    }

    @Test
    void callHelp() {
      CommandResult result = runCommand("call", "--help");
      assertThat(result.exitCode).isEqualTo(0);
      assertThat(result.output).contains("-P");
    }

    @Test
    void callOnvifPtzStub() {
       // We need a device to call action on. 
       // Let's add a dummy device first.
       runCommand("device", "add", "dummy", "--type", "onvif", "--url", "http://localhost", "-u", "a", "-p", "a");
       CommandResult result = runCommand("call", "dummy", "ptz", "-Px=0.5");
       assertThat(result.exitCode).isEqualTo(0);
       assertThat(result.output).contains("PTZ command received");
    }

    @Test
    void discoverHelpHasModbusPorts() {
      CommandResult result = runCommand("discover", "--help");
      assertThat(result.exitCode).isEqualTo(0);
      assertThat(result.output).contains("--modbus.ports");
    }

    @Test
    void deviceListAll() {
      CommandResult result = runCommand("device", "list", "--all");
      if (result.exitCode != 0) {
          System.out.println("Command output:\n" + result.output);
      }
      assertThat(result.exitCode).isEqualTo(0);
    }

    @Test
    void deviceAutoregisterHelp() {
       CommandResult result = runCommand("device", "autoregister", "--help");
       assertThat(result.exitCode).isEqualTo(0);
    }
  }
}
