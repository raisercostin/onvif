///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS org.junit.jupiter:junit-jupiter:5.11.3
//DEPS org.assertj:assertj-core:3.26.3
//DEPS org.junit.platform:junit-platform-console:1.11.3
//SOURCES iot3.java

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.List;

import picocli.CommandLine;
import org.junit.jupiter.api.Test;
import com.namekis.utils.RichCli;

public class iot3_test {
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
            // Create a fresh instance for each run
            int exitCode = new CommandLine(new iot3()).execute(args);
            String output = outBuffer.toString() + errBuffer.toString();
            return new CommandResult(exitCode, output);
        } finally {
            System.setOut(originalOut);
            System.setErr(originalErr);
        }
    }

    @Test
    void helpCommandWorks() {
        CommandResult result = runCommand("--help");
        assertThat(result.exitCode).isEqualTo(0);
        assertThat(result.output).contains("iot3");
    }

    public static class DiscoveryTests {
        @Test
        void discoverCommandListsProbes() {
            CommandResult result = runCommand("discover", "--dry-run");
            assertThat(result.exitCode).isEqualTo(0);
            assertThat(result.output).contains("Starting discovery");
        }

        public static class CheckTests {
            @Test
            void checkCommandExists() {
                CommandResult result = runCommand("check", "--help");
                assertThat(result.exitCode).isEqualTo(0);
                assertThat(result.output).contains("Check device status");
            }
        }
    }

    public static class DescribeTests {
        @Test
        void describeCommandExists() {
            CommandResult result = runCommand("describe", "--help");
            assertThat(result.exitCode).isEqualTo(0);
            assertThat(result.output).contains("Describe device");
        }
    }
}
