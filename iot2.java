///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.7.5
//SOURCES com/namekis/utils/RichCli.java
//SOURCES onvif.java
//SOURCES modbus.java
//SOURCES innova.java

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.ParentCommand;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Unmatched;

import com.namekis.utils.RichCli;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Callable;

@Command(
    name = "iot2",
    mixinStandardHelpOptions = true,
    version = "0.1",
    description = "Unified IoT CLI (probe-based).",
    subcommands = {
        iot2.ProbesCmd.class,
        iot2.ProbeCmd.class
    }
)
public class iot2 implements Runnable {
    private static final Logger log = LoggerFactory.getLogger(iot2.class);
    static final Map<String, Probe> PROBES = new LinkedHashMap<>();

    static {
        register(new OnvifProbe());
        register(new InnovaProbe());
        register(new ModbusProbe());
    }

    static void register(Probe probe) {
        PROBES.put(probe.id(), probe);
    }

    public static void main(String[] args) {
        RichCli.BaseOptions opts = RichCli.configureLogbackByVerbosity(args);
        CommandLine cmd = new CommandLine(new iot2());
        cmd.setExecutionExceptionHandler((ex, commandLine, parseResult) -> {
            if (opts.trace) {
                log.warn("Execution failed:", ex);
            } else {
                log.warn("{} (Use --trace for full stack trace)", ex.getMessage());
            }
            return commandLine.getCommandSpec().exitCodeOnExecutionException();
        });
        cmd.setUnmatchedArgumentsAllowed(true);
        cmd.setUnmatchedOptionsArePositionalParams(true);
        CommandLine probeCmd = cmd.getSubcommands().get("probe");
        if (probeCmd != null) {
            probeCmd.setUnmatchedArgumentsAllowed(true);
            probeCmd.setUnmatchedOptionsArePositionalParams(true);
        }
        int res = cmd.execute(args);
        if (res != 0) {
            System.exit(res);
        }
    }

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }

    interface Probe {
        String id();
        String description();
        List<ActionDesc> actions();
        int discover(List<String> args);
        int check(List<String> args);
        int describe(List<String> args);
        int backup(List<String> args);
        int restore(List<String> args);
        int raw(List<String> args);
    }

    static class ActionDesc {
        final String name;
        final List<String> aliases;
        final String description;
        final List<ParamDesc> params;
        final ResponseDesc response;

        ActionDesc(String name, List<String> aliases, String description, List<ParamDesc> params, ResponseDesc response) {
            this.name = name;
            this.aliases = aliases;
            this.description = description;
            this.params = params;
            this.response = response;
        }
    }

    static class ParamDesc {
        final String name;
        final String description;
        final String type;
        final List<String> samples;

        ParamDesc(String name, String description, String type, List<String> samples) {
            this.name = name;
            this.description = description;
            this.type = type;
            this.samples = samples;
        }
    }

    static class ResponseDesc {
        final String description;

        ResponseDesc(String description) {
            this.description = description;
        }
    }

    static class Action {
        final ActionDesc desc;
        final List<Param> params;

        Action(ActionDesc desc, List<Param> params) {
            this.desc = desc;
            this.params = params;
        }
    }

    static class Param {
        final ParamDesc desc;
        final String value;

        Param(ParamDesc desc, String value) {
            this.desc = desc;
            this.value = value;
        }
    }

    @Command(name = "probes", description = "List available probes.")
    static class ProbesCmd implements Runnable {
        @Override
        public void run() {
            System.out.printf("%-10s %s%n", "ID", "DESCRIPTION");
            System.out.println("-".repeat(40));
            for (Probe probe : PROBES.values()) {
                System.out.printf("%-10s %s%n", probe.id(), probe.description());
            }
        }
    }

    @Command(
        name = "probe",
        description = "Interact with a specific probe.",
        subcommands = {
            ProbeProbeCmd.class,
            ProbeDiscoverCmd.class,
            ProbeCheckCmd.class,
            ProbeDescribeCmd.class,
            ProbeBackupCmd.class,
            ProbeRestoreCmd.class,
            ProbeActionsCmd.class,
            ProbeRawCmd.class
        }
    )
    static class ProbeCmd implements Callable<Integer> {
        @Parameters(index = "0", arity = "0..1", description = "Probe id (onvif|innova|modbus).")
        String probeId;

        @Unmatched
        List<String> args = new ArrayList<>();

        @Override
        public Integer call() {
            if (probeId != null && !PROBES.containsKey(probeId.toLowerCase(Locale.ROOT))) {
                if (probeId.startsWith("-")) {
                    args.add(0, probeId);
                    probeId = null;
                } else {
                    System.err.println("Unknown probe: " + probeId);
                    System.err.println("Available probes: " + String.join(", ", PROBES.keySet()));
                    return 2;
                }
            }
            if (probeId == null) {
                int exit = 0;
                for (Probe probe : PROBES.values()) {
                    List<String> scoped = filterArgsForProbe(probe.id(), args);
                    int result = probe.discover(scoped);
                    if (result != 0) {
                        exit = result;
                    }
                }
                return exit;
            }
            CommandLine.usage(this, System.out);
            return 0;
        }

        Probe resolveProbe() {
            if (probeId == null) {
                return null;
            }
            return PROBES.get(probeId.toLowerCase(Locale.ROOT));
        }
    }

    abstract static class ProbeActionBase {
        @ParentCommand
        ProbeCmd parent;

        @Unmatched
        List<String> args = new ArrayList<>();

        Probe resolveProbeOrReport() {
            Probe probe = parent.resolveProbe();
            if (probe == null) {
                System.err.println("Unknown probe: " + parent.probeId);
                System.err.println("Available probes: " + String.join(", ", PROBES.keySet()));
            }
            return probe;
        }
    }

    @Command(
        name = "probe",
        description = "Probe for devices or check a specific device."
    )
    static class ProbeProbeCmd extends ProbeActionBase implements Callable<Integer> {
        @Override
        public Integer call() {
            Probe probe = resolveProbeOrReport();
            if (probe == null) {
                return 2;
            }
            if (args.isEmpty()) {
                return probe.discover(args);
            }
            return probe.check(args);
        }
    }

    @Command(
        name = "discover",
        description = "Discover devices using a probe."
    )
    static class ProbeDiscoverCmd extends ProbeActionBase implements Callable<Integer> {
        @Override
        public Integer call() {
            Probe probe = resolveProbeOrReport();
            if (probe == null) {
                return 2;
            }
            return probe.discover(args);
        }
    }

    @Command(
        name = "check",
        description = "Check device status using a probe."
    )
    static class ProbeCheckCmd extends ProbeActionBase implements Callable<Integer> {
        @Override
        public Integer call() {
            Probe probe = resolveProbeOrReport();
            if (probe == null) {
                return 2;
            }
            return probe.check(args);
        }
    }

    @Command(
        name = "describe",
        description = "Describe a device using a probe."
    )
    static class ProbeDescribeCmd extends ProbeActionBase implements Callable<Integer> {
        @Override
        public Integer call() {
            Probe probe = resolveProbeOrReport();
            if (probe == null) {
                return 2;
            }
            return probe.describe(args);
        }
    }

    @Command(
        name = "backup",
        description = "Backup device configuration using a probe."
    )
    static class ProbeBackupCmd extends ProbeActionBase implements Callable<Integer> {
        @Override
        public Integer call() {
            Probe probe = resolveProbeOrReport();
            if (probe == null) {
                return 2;
            }
            return probe.backup(args);
        }
    }

    @Command(
        name = "restore",
        description = "Restore device configuration using a probe."
    )
    static class ProbeRestoreCmd extends ProbeActionBase implements Callable<Integer> {
        @Override
        public Integer call() {
            Probe probe = resolveProbeOrReport();
            if (probe == null) {
                return 2;
            }
            return probe.restore(args);
        }
    }

    @Command(
        name = "actions",
        description = "List supported actions for a probe."
    )
    static class ProbeActionsCmd extends ProbeActionBase implements Callable<Integer> {
        @Override
        public Integer call() {
            Probe probe = resolveProbeOrReport();
            if (probe == null) {
                return 2;
            }
            System.out.printf("%-16s %-20s %s%n", "ACTION", "ALIASES", "DESCRIPTION");
            System.out.println("-".repeat(70));
            for (ActionDesc action : probe.actions()) {
                String aliases = action.aliases == null ? "" : String.join(",", action.aliases);
                System.out.printf("%-16s %-20s %s%n", action.name, aliases, action.description);
            }
            return 0;
        }
    }

    @Command(
        name = "raw",
        aliases = {"exec", "run"},
        description = "Pass arguments directly to the probe implementation."
    )
    static class ProbeRawCmd extends ProbeActionBase implements Callable<Integer> {
        @Override
        public Integer call() {
            Probe probe = resolveProbeOrReport();
            if (probe == null) {
                return 2;
            }
            return probe.raw(args);
        }
    }

    static class OnvifProbe implements Probe {
        @Override
        public String id() {
            return "onvif";
        }

        @Override
        public String description() {
            return "ONVIF cameras and encoders.";
        }

        @Override
        public List<ActionDesc> actions() {
            List<ActionDesc> actions = new ArrayList<>();
            actions.add(new ActionDesc(
                "ptz",
                List.of("pantiltzoom"),
                "Move the camera using PTZ controls.",
                List.of(new ParamDesc("preset", "Preset name or id.", "string", List.of("home"))),
                new ResponseDesc("PTZ move response.")
            ));
            actions.add(new ActionDesc(
                "stream",
                List.of("rtsp"),
                "Retrieve stream URIs.",
                List.of(),
                new ResponseDesc("Stream profile list.")
            ));
            return actions;
        }

        @Override
        public int discover(List<String> args) {
            return executeOnvif(withLeading("discover", args));
        }

        @Override
        public int check(List<String> args) {
            if (args.isEmpty()) {
                return executeOnvif(withLeading("device", "list", "--check", args));
            }
            return executeOnvif(withDescribeTarget("describe", "-d", args));
        }

        @Override
        public int describe(List<String> args) {
            return executeOnvif(withDescribeTarget("describe", "-d", args));
        }

        @Override
        public int backup(List<String> args) {
            System.err.println("Backup is not supported for ONVIF probes.");
            return 2;
        }

        @Override
        public int restore(List<String> args) {
            System.err.println("Restore is not supported for ONVIF probes.");
            return 2;
        }

        @Override
        public int raw(List<String> args) {
            return executeOnvif(args);
        }

        private int executeOnvif(List<String> args) {
            return new CommandLine(new onvif.MainCommand()).execute(args.toArray(String[]::new));
        }
    }

    static class InnovaProbe implements Probe {
        @Override
        public String id() {
            return "innova";
        }

        @Override
        public String description() {
            return "Innova ventiloconvettors.";
        }

        @Override
        public List<ActionDesc> actions() {
            List<ActionDesc> actions = new ArrayList<>();
            actions.add(new ActionDesc(
                "status",
                List.of(),
                "Read current device status.",
                List.of(new ParamDesc("target", "Alias or IP.", "string", List.of("192.168.1.50"))),
                new ResponseDesc("Device status snapshot.")
            ));
            actions.add(new ActionDesc(
                "set",
                List.of("configure"),
                "Update device settings.",
                List.of(
                    new ParamDesc("power", "on/off", "string", List.of("on")),
                    new ParamDesc("temp", "Target temperature.", "number", List.of("22.5"))
                ),
                new ResponseDesc("Acknowledged settings change.")
            ));
            return actions;
        }

        @Override
        public int discover(List<String> args) {
            return executeInnova(withLeading("discover", args));
        }

        @Override
        public int check(List<String> args) {
            if (args.isEmpty()) {
                return executeInnova(List.of("device", "list", "--check"));
            }
            return executeInnova(withLeading("status", args));
        }

        @Override
        public int describe(List<String> args) {
            return executeInnova(withLeading("status", args));
        }

        @Override
        public int backup(List<String> args) {
            System.err.println("Backup is not supported for Innova probes.");
            return 2;
        }

        @Override
        public int restore(List<String> args) {
            System.err.println("Restore is not supported for Innova probes.");
            return 2;
        }

        @Override
        public int raw(List<String> args) {
            return executeInnova(args);
        }

        private int executeInnova(List<String> args) {
            return new CommandLine(new innova()).execute(args.toArray(String[]::new));
        }
    }

    static class ModbusProbe implements Probe {
        @Override
        public String id() {
            return "modbus";
        }

        @Override
        public String description() {
            return "Modbus TCP/RTU devices.";
        }

        @Override
        public List<ActionDesc> actions() {
            List<ActionDesc> actions = new ArrayList<>();
            actions.add(new ActionDesc(
                "set-register",
                List.of("write", "set"),
                "Write registers or coils.",
                List.of(
                    new ParamDesc("address", "Register address.", "int", List.of("100")),
                    new ParamDesc("value", "Value to write.", "int", List.of("1"))
                ),
                new ResponseDesc("Write response.")
            ));
            actions.add(new ActionDesc(
                "poll",
                List.of("read"),
                "Read registers on a schedule.",
                List.of(new ParamDesc("count", "Number of registers.", "int", List.of("10"))),
                new ResponseDesc("Poll results.")
            ));
            return actions;
        }

        @Override
        public int discover(List<String> args) {
            return executeModbus(withLeading("discover", normalizeDiscoveryArgs(args)));
        }

        @Override
        public int check(List<String> args) {
            if (shouldDiscoverWithArgs(args)) {
                return executeModbus(withLeading("discover", normalizeDiscoveryArgs(args)));
            }
            return executeModbus(withLeading("describe", args));
        }

        @Override
        public int describe(List<String> args) {
            return executeModbus(withLeading("describe", args));
        }

        @Override
        public int backup(List<String> args) {
            return executeModbus(withLeading("backup", args));
        }

        @Override
        public int restore(List<String> args) {
            return executeModbus(withLeading("restore", args));
        }

        @Override
        public int raw(List<String> args) {
            return executeModbus(args);
        }

        private int executeModbus(List<String> args) {
            return new CommandLine(new modbus()).execute(args.toArray(String[]::new));
        }

        private boolean shouldDiscoverWithArgs(List<String> args) {
            boolean hasPorts = false;
            boolean hasSubnet = false;
            boolean hasTargetSelector = false;
            boolean hasPositionalTarget = false;
            boolean skipNextValue = false;
            for (int i = 0; i < args.size(); i++) {
                String token = args.get(i);
                if (skipNextValue) {
                    skipNextValue = false;
                    continue;
                }
                if ("-p".equals(token) || "--ports".equals(token) || "--modbus.ports".equals(token)) {
                    hasPorts = true;
                    skipNextValue = true;
                    continue;
                }
                if (token.startsWith("-p=") || token.startsWith("--ports=") || token.startsWith("--modbus.ports=")) {
                    hasPorts = true;
                    continue;
                }
                if ("--subnet".equals(token)) {
                    hasSubnet = true;
                    skipNextValue = true;
                    continue;
                }
                if (token.startsWith("--subnet=")) {
                    hasSubnet = true;
                    continue;
                }
                if ("-tcp".equals(token) || "-serial".equals(token) || "-d".equals(token) || "--device".equals(token)) {
                    hasTargetSelector = true;
                    skipNextValue = true;
                    continue;
                }
                if (token.startsWith("-tcp=")
                    || token.startsWith("-serial=")
                    || token.startsWith("-d=")
                    || token.startsWith("--device=")) {
                    hasTargetSelector = true;
                    continue;
                }
                if (!token.startsWith("-")) {
                    hasPositionalTarget = true;
                }
            }
            if (hasTargetSelector || hasPositionalTarget) {
                return false;
            }
            return hasPorts || hasSubnet;
        }

        private List<String> normalizeDiscoveryArgs(List<String> args) {
            List<String> normalized = new ArrayList<>();
            boolean skipNextValue = false;
            for (int i = 0; i < args.size(); i++) {
                String token = args.get(i);
                if (skipNextValue) {
                    normalized.add(token);
                    skipNextValue = false;
                    continue;
                }
                if ("-p".equals(token) || "--modbus.ports".equals(token)) {
                    normalized.add("--ports");
                    skipNextValue = true;
                    continue;
                }
                if (token.startsWith("-p=")) {
                    normalized.add("--ports=" + token.substring(3));
                    continue;
                }
                if (token.startsWith("--modbus.ports=")) {
                    normalized.add("--ports=" + token.substring("--modbus.ports=".length()));
                    continue;
                }
                normalized.add(token);
            }
            return normalized;
        }
    }

    static List<String> withLeading(String first, List<String> args) {
        List<String> merged = new ArrayList<>(1 + args.size());
        merged.add(first);
        merged.addAll(args);
        return merged;
    }

    static List<String> withLeading(String first, String second, String third, List<String> args) {
        List<String> merged = new ArrayList<>(3 + args.size());
        merged.add(first);
        merged.add(second);
        merged.add(third);
        merged.addAll(args);
        return merged;
    }

    static List<String> withDescribeTarget(String command, String flag, List<String> args) {
        List<String> merged = new ArrayList<>();
        merged.add(command);
        if (args.isEmpty()) {
            return merged;
        }
        String first = args.get(0);
        if (!first.startsWith("-") && !args.contains(flag) && !args.contains("--device")) {
            merged.add(flag);
            merged.add(first);
            merged.addAll(args.subList(1, args.size()));
        } else {
            merged.addAll(args);
        }
        return merged;
    }

    static List<String> filterArgsForProbe(String probeId, List<String> args) {
        List<String> filtered = new ArrayList<>();
        String prefix = "--" + probeId + ".";
        boolean carryNext = false;
        for (int i = 0; i < args.size(); i++) {
            String token = args.get(i);
            if (carryNext) {
                filtered.add(token);
                carryNext = false;
                continue;
            }
            if (token.startsWith(prefix)) {
                String remainder = token.substring(prefix.length());
                if (remainder.isEmpty()) {
                    continue;
                }
                if (remainder.contains("=")) {
                    filtered.add("--" + remainder);
                } else {
                    filtered.add("--" + remainder);
                    carryNext = true;
                }
            }
        }
        return filtered;
    }
}
