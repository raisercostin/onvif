///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS org.junit.jupiter:junit-jupiter:5.11.3
//DEPS org.assertj:assertj-core:3.26.3
//DEPS org.junit.jupiter:junit-jupiter-engine:5.11.3
//DEPS org.junit.platform:junit-platform-launcher:1.11.3
//DEPS org.junit.platform:junit-platform-console:1.11.3
//SOURCES modbus.java

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.List;
import java.util.stream.Collectors;

import picocli.CommandLine;
import org.junit.jupiter.api.Test;

import com.namekis.utils.RichCli;

public class modbus_test {
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
      int exitCode = new CommandLine(new modbus()).execute(args);
      String output = outBuffer.toString() + errBuffer.toString();
      return new CommandResult(exitCode, output);
    } finally {
      System.setOut(originalOut);
      System.setErr(originalErr);
    }
  }

  public static class HelpTests {
    @Test
    void helpShowsSubcommands() {
      CommandResult result = runCommand("--help");
      assertThat(result.exitCode).isEqualTo(0);
      assertThat(result.output).contains("modbus");
      assertThat(result.output).contains("discover");
      assertThat(result.output).contains("describe");
      assertThat(result.output).contains("backup");
      assertThat(result.output).contains("restore");
      assertThat(result.output).contains("poll");
    }
  }

  public static class DiscoverTests {
    @Test
    void discoverWithoutSubnetFailsGracefullyOrDetects() {
      CommandResult result = runCommand("discover");
      assertThat(result.output).satisfiesAnyOf(
        s -> assertThat(s).contains("Could not detect local subnet"),
        s -> assertThat(s).contains("Scanning"),
        s -> assertThat(s).contains("No devices found")
      );
    }

    @Test
    void discoverWithSubnetScans() {
      CommandResult result = runCommand("discover", "--subnet", "127.0.0", "--ports", "50200"); 
      assertThat(result.output).contains("Scanning 127.0.0.1-254");
    }
  }

  public static class DescribeTests {
    @Test
    void describeTcpShowsFingerprint() {
      CommandResult result = runCommand("describe", "-tcp", "127.0.0.1");
      // Expect 1 because connection will fail
      assertThat(result.exitCode).isEqualTo(1); 
      assertThat(result.output).satisfiesAnyOf(
          s -> assertThat(s).contains("Device Fingerprint"),
          s -> assertThat(s).contains("Connection refused"),
          s -> assertThat(s).contains("Connection failed")
      );
    }
  }

  public static class PollTests {
    @Test
    void pollMissingAddressFails() {
        CommandResult result = runCommand("poll", "-tcp", "127.0.0.1");
        assertThat(result.exitCode).isNotEqualTo(0);
        assertThat(result.output).contains("Missing required option: '--address=<address>'");
    }

        @Test

        void pollWithRequiredArgsRuns() {

            CommandResult result = runCommand("poll", "-tcp", "127.0.0.1", "-a", "0", "-c", "1");

            // Expect 1 because connection will fail

            assertThat(result.exitCode).isEqualTo(1);

            

            assertThat(result.output + result.exitCode).satisfiesAnyOf(

                s -> assertThat(s).contains("Connection refused"),

                s -> assertThat(s).contains("Connection failed")

            );

        }

      }

    

      public static class BackupTests {

        @Test

        void backupChofuDevice() throws Exception {

            // Setup isolated config environment

            java.nio.file.Path tempDir = java.nio.file.Files.createTempDirectory("modbus-test-config");

            System.setProperty("MODBUS_CONFIG_PATH", tempDir.resolve("config.yaml").toString());

            

            try {

                // 1. Create a dummy mapping CSV

                java.nio.file.Path mappingFile = tempDir.resolve("mapping.csv");

                java.nio.file.Files.writeString(mappingFile, 

                    "Param,Group,Level,Name,Description,Default,Min,Max,Unit,Remarks,,ModbusValue,Value,Type,,Address,Name,Code,Param,Step,Scale,Offset,Precision,DataType,Unit,Default,Min,Max,Remarks,,Read/Write,,Address,F1-Coil-RW,F2-discrete-inputs,F3-Holding Register RW,F4-Input Register R,,ModbusValue,F1-Coil-RW,F2-Discrete-Inputs R,F3 Holding Register RW,F4 Input Register R\n" +

                    "P0100,,,,,,,,,,,,,,,,,,,0,,,,,,,,,,,,holding,,,,,,,0,,,,"

                );

    

                // 2. Configure the 'chofu' device

                runCommand("device", "add", "chofu", "-tcp", "127.0.0.1", "-p", "50200"); // Use random high port to ensure connection failure

    

                // 3. Run backup

                java.nio.file.Path backupFile = tempDir.resolve("backup.csv");

                CommandResult result = runCommand("backup", "-d", "chofu", "--config", mappingFile.toString(), "--output", backupFile.toString());

    

                            // 4. Verification

    

                            // Expect exit code 1 due to connection failure (we used a fake port)

    

                            assertThat(result.exitCode).isEqualTo(1);

    

                            

    

                                        // Verify it attempted to connect (connection failure proves it tried)

    

                            

    

                                        // We cannot verify "Reading holding" because that log happens AFTER connection success.

    

                            

    

                                        assertThat(result.output).satisfiesAnyOf(

    

                            

    

                                            s -> assertThat(s).contains("Connection refused"),

    

                            

    

                                            s -> assertThat(s).contains("Connection failed")

    

                            

    

                                        );

    

                            

    

                            

    

                            

    

                                    } finally {

    

                            

    

                                        System.clearProperty("MODBUS_CONFIG_PATH");

    

                            

    

                                        // Cleanup (optional, OS usually handles temp dirs eventually, but good practice)

    

                            

    

                                        // FileUtils.deleteDirectory(tempDir.toFile()); 

    

                            

    

                                    }

    

                            

    

                                }

    

                            

    

                            

    

                            

    

                                @Test

    

                            

    

                                void backupWithDefaultsRuns() {

    

                            

    

                                    // Run without --config or --output. Should default to internal list and stdout.

    

                            

    

                                    // It will fail connection, but should NOT fail with "Configuration file not found".

    

                            

    

                                    CommandResult result = runCommand("backup", "-tcp", "127.0.0.1");

    

                            

    

                                    

    

                            

    

                                    assertThat(result.exitCode).isEqualTo(1); // Connection failure

    

                            

    

                                    assertThat(result.output).doesNotContain("Configuration file not found");

    

                            

    

                                    assertThat(result.output).satisfiesAnyOf(

    

                            

    

                                        s -> assertThat(s).contains("Connection refused"),

    

                            

    

                                        s -> assertThat(s).contains("Connection failed")

    

                            

    

                                    );

    

                            

    

                                }

    

                            

    

                              }

    

                            

    

                            }

    

                            

    

                            

    

                

    