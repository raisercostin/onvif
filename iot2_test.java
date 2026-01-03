///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS org.junit.jupiter:junit-jupiter:5.11.3
//DEPS org.assertj:assertj-core:3.26.3
//DEPS org.junit.jupiter:junit-jupiter-engine:5.11.3
//DEPS org.junit.platform:junit-platform-launcher:1.11.3
//DEPS org.junit.platform:junit-platform-console:1.11.3
//SOURCES iot2.java

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import picocli.CommandLine;
import org.junit.jupiter.api.Test;

import com.namekis.utils.RichCli;

public class iot2_test {
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
            int exitCode = new CommandLine(new iot2()).execute(args);
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
        void listOnvifActions() {
            CommandResult result = runCommand("probe", "onvif", "actions");
            assertThat(result.exitCode).isEqualTo(0);
            assertThat(result.output).contains("ptz");
            assertThat(result.output).contains("stream");
        }

        @Test
        void rawPassThroughSupportsOnvifDeviceList() {
            CommandResult result = runCommand("probe", "onvif", "raw", "device", "list");
            assertThat(result.exitCode).isEqualTo(0);
            assertThat(result.output).contains("ALIAS");
        }

        @Test
        void listInnovaActions() {
            CommandResult result = runCommand("probe", "innova", "actions");
            assertThat(result.exitCode).isEqualTo(0);
            assertThat(result.output).contains("status");
            assertThat(result.output).contains("set");
        }

        @Test
        void rawPassThroughSupportsInnovaDeviceList() {
            CommandResult result = runCommand("probe", "innova", "raw", "device", "list");
            assertThat(result.exitCode).isEqualTo(0);
            assertThat(result.output).satisfiesAnyOf(
                s -> assertThat(s).contains("No devices registered."),
                s -> assertThat(s).contains("ALIAS")
            );
        }
    }

    public static class IntegrationTests {
        @Test
        void onvifDescribeByAlias() {
            CommandResult result = runCommand("probe", "onvif", "describe", "cam-21");
            assertThat(result.exitCode).isEqualTo(0);
            assertThat(result.output).contains("PTZConfiguration");
            assertThat(result.output).contains("mainStream");
        }

        @Test
        void modbusDescribeTcpShowsFingerprintOrFailure() {
            CommandResult result = runCommand("probe", "modbus", "describe", "-tcp", "127.0.0.1");
            assertThat(result.exitCode).isEqualTo(1);
            assertThat(result.output).satisfiesAnyOf(
                s -> assertThat(s).contains("Device Fingerprint"),
                s -> assertThat(s).contains("Connection refused"),
                s -> assertThat(s).contains("Connection failed")
            );
        }

        @Test
        void modbusProbeTargetsAreChecked() {
            CommandResult result = runCommand("probe", "modbus", "probe", "-tcp", "127.0.0.1");
            assertThat(result.exitCode).isEqualTo(1);
            assertThat(result.output).satisfiesAnyOf(
                s -> assertThat(s).contains("Device Fingerprint"),
                s -> assertThat(s).contains("Connection refused"),
                s -> assertThat(s).contains("Connection failed")
            );
        }

        @Test
        void modbusProbeWithPortRunsDiscovery() {
            CommandResult result = runCommand("probe", "modbus", "probe", "--modbus.ports=8899,502");
            assertThat(result.exitCode).satisfiesAnyOf(
                code -> assertThat(code).isEqualTo(0),
                code -> assertThat(code).isEqualTo(1)
            );
            assertThat(result.output).satisfiesAnyOf(
                s -> assertThat(s).contains("Scanning"),
                s -> assertThat(s).contains("Could not detect local subnet"),
                s -> assertThat(s).contains("No devices found")
            );
        }

        @Test
        void probeAllUsesPrefixedModbusArgs() {
            CommandResult result = runCommand("probe", "--modbus.ports=8899");
            assertThat(result.exitCode).satisfiesAnyOf(
                code -> assertThat(code).isEqualTo(0),
                code -> assertThat(code).isEqualTo(1)
            );
            assertThat(result.output).satisfiesAnyOf(
                s -> assertThat(s).contains("Scanning"),
                s -> assertThat(s).contains("Starting discovery"),
                s -> assertThat(s).contains("Could not detect local subnet")
            );
        }
    }
}
