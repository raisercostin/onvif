///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.7.5
//DEPS org.slf4j:slf4j-api:2.0.9
//DEPS ch.qos.logback:logback-classic:1.4.11
//DEPS com.fasterxml.jackson.dataformat:jackson-dataformat-csv:2.15.2
//DEPS com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.15.2
//DEPS com.fasterxml.jackson.core:jackson-databind:2.15.2
//DEPS com.ghgande:j2mod:3.2.0
//SOURCES com/namekis/utils/RichCli.java

import picocli.CommandLine;
import picocli.CommandLine.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.namekis.utils.RichCli;
import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.dataformat.csv.*;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import com.ghgande.j2mod.modbus.Modbus;
import com.ghgande.j2mod.modbus.facade.ModbusTCPMaster;
import com.ghgande.j2mod.modbus.procimg.InputRegister;
import com.ghgande.j2mod.modbus.procimg.SimpleRegister;
import com.ghgande.j2mod.modbus.util.BitVector;
import com.ghgande.j2mod.modbus.util.SerialParameters;
import com.ghgande.j2mod.modbus.facade.ModbusSerialMaster;

import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

@Command(name = "modbus", version = "0.3.0", mixinStandardHelpOptions = true, subcommands = {
    modbus.DeviceCmd.class,
    modbus.DiscoverCmd.class,
    modbus.DescribeCmd.class,
    modbus.BackupCmd.class,
    modbus.RestoreCmd.class,
    modbus.PollCmd.class,
    CommandLine.HelpCommand.class
}, description = "Modbus tool for backup, restore and polling.")
public class modbus {
    private static final Logger log = LoggerFactory.getLogger("modbus");
    private static final Path CONFIG_PATH = resolveConfigPath();
    private static final CsvMapper CSV_MAPPER = new CsvMapper();
    private static final YAMLMapper YAML_MAPPER = new YAMLMapper();
    
    private static Path resolveConfigPath() {
        String override = System.getProperty("MODBUS_CONFIG_PATH");
        if (override != null && !override.isBlank()) {
            return Paths.get(override);
        }
        return Paths.get(System.getProperty("user.home"), ".modbus", "config.yaml");
    }
    
    static {
        CSV_MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        CSV_MAPPER.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
        CSV_MAPPER.configure(DeserializationFeature.ACCEPT_EMPTY_STRING_AS_NULL_OBJECT, true);
        CSV_MAPPER.enable(CsvParser.Feature.TRIM_SPACES);
    }

    final Config cfg = Config.load();

    public static void main(String[] args) {
        RichCli.main(args, () -> new modbus());
    }

    @Spec Model.CommandSpec spec;

    static class StandardOptions extends RichCli.BaseOptions {}

    @ArgGroup(exclusive = false, heading = "Development options:\n", order = 100)
    StandardOptions standardOpts = new StandardOptions();

    // --- SHARED DEVICE OPTIONS ---
    static class DeviceOptions {
        @Option(names = {"-d", "--device"}, description = "Target device alias. Candidates: ${COMPLETION-CANDIDATES}", completionCandidates = DeviceAliasCandidates.class)
        String device;

        @ArgGroup(exclusive = true, heading = "Transport (Overrides device config):\n")
        Transport transport;

        static class Transport {
            @ArgGroup(exclusive = false, heading = "TCP Options:\n")
            TcpOptions tcp;

            @ArgGroup(exclusive = false, heading = "Serial Options:\n")
            SerialOptions serial;
        }

        static class TcpOptions {
            @Option(names = "-tcp", required = true, description = "Host name/IP for MODBUS/TCP.")
            String host;

            @Option(names = "-p", description = "Port (default: 502).", defaultValue = "502")
            int port = 502;
        }

        static class SerialOptions {
            @Option(names = "-serial", required = true, description = "Serial port (e.g. /dev/ttyUSB0, COM1).")
            String port;

            @Option(names = {"-b", "--baud"}, description = "Baudrate (default: 19200).", defaultValue = "19200")
            int baudRate = 19200;

            @Option(names = {"-db", "--data-bits"}, description = "Data bits (default: 8).", defaultValue = "8", hidden = true)
            int dataBits = 8;

            @Option(names = {"-s", "--stop-bits"}, description = "Stop bits (default: 1).", defaultValue = "1", hidden = true)
            int stopBits = 1;

            @Option(names = "--parity", description = "Parity (none, even, odd, mark, space). Default: none.", defaultValue = "none", hidden = true)
            String parity = "none";
        }

        @Option(names = {"-u", "--unit-id"}, description = "Unit ID (Slave ID). Overrides config.")
        Integer unitId;
    }

    @ArgGroup(exclusive = false, heading = "Device Options:\n", order = 50)
    DeviceOptions deviceOpts = new DeviceOptions();

    // --- DEVICE MANAGEMENT MODULE ---
    @Command(name = "device", description = "Manage Modbus device inventory.", mixinStandardHelpOptions = true)
    public static class DeviceCmd {
        @ParentCommand modbus parent;

        @ArgGroup(exclusive = false, heading = "Device Options:\n", order = 50)
        DeviceOptions deviceOpts = new DeviceOptions();

        @ArgGroup(exclusive = false, heading = "Development options:\n", order = 100)
        StandardOptions standardOpts = new StandardOptions();

        @Command(description = "Manually add a device profile.")
        public void add(
            @Parameters(index = "0", description = "Device alias") String name,
            @ArgGroup(exclusive = false) DeviceOptions locals) {
            
            DeviceProfile p = new DeviceProfile();
            p.alias = name;
            
            DeviceOptions opts = (locals != null && (locals.transport != null || locals.device != null)) ? locals : parent.deviceOpts;
            
            if (opts.transport != null && opts.transport.tcp != null) {
                p.type = "tcp";
                p.host = opts.transport.tcp.host;
                p.port = opts.transport.tcp.port;
            } else if (opts.transport != null && opts.transport.serial != null) {
                p.type = "serial";
                p.serialPort = opts.transport.serial.port;
                p.baudRate = opts.transport.serial.baudRate;
                p.dataBits = opts.transport.serial.dataBits;
                p.stopBits = opts.transport.serial.stopBits;
                p.parity = opts.transport.serial.parity;
            } else {
                throw new RuntimeException("Provide connection details: modbus device add <name> -tcp <host> OR -serial <port>");
            }
            
            p.unitId = opts.unitId != null ? opts.unitId : 1;
            
            parent.cfg.devices.put(name, p);
            parent.cfg.save();
            System.out.println("Device '" + name + "' added.");
        }

        @Command(description = "List registered devices.")
        public void list() {
            if (parent.cfg.devices.isEmpty()) {
                System.out.println("No devices registered.");
                return;
            }
            System.out.printf("%2s %15s %10s %30s %10s\n", "", "ALIAS", "TYPE", "TARGET", "UNIT ID");
            System.out.println("-".repeat(70));
            parent.cfg.devices.forEach((id, p) -> {
                String marker = id.equals(parent.cfg.activeDevice) ? "*" : " ";
                String target = "tcp".equals(p.type) ? p.host + ":" + p.port : p.serialPort + " (" + p.baudRate + ")";
                System.out.printf("%s %15s %10s %30s %10d\n", marker, id, p.type, target, p.unitId);
            });
        }

        @Command(description = "Select the default device.")
        public void use(@Parameters(index = "0") String name) {
            if (!parent.cfg.devices.containsKey(name)) throw new RuntimeException("Unknown device: " + name);
            parent.cfg.activeDevice = name;
            parent.cfg.save();
            System.out.println("Active device: " + name);
        }

        @Command(description = "Remove a device.")
        public void remove(@Parameters(index = "0") String name) {
            if (parent.cfg.devices.remove(name) != null) {
                if (name.equals(parent.cfg.activeDevice)) parent.cfg.activeDevice = null;
                parent.cfg.save();
                System.out.println("Device '" + name + "' removed.");
            } else {
                System.out.println("Device '" + name + "' not found.");
            }
        }
    }

    // --- DISCOVER COMMAND ---
    @Command(name = "discover", description = "Scan local network for Modbus devices (Port 502).", mixinStandardHelpOptions = true)
    public static class DiscoverCmd implements Callable<Integer> {
        @ParentCommand modbus parent;

        @ArgGroup(exclusive = false, heading = "Development options:\n", order = 100)
        StandardOptions standardOpts = new StandardOptions();

        @Option(names = "--subnet", description = "Subnet to scan (e.g. 192.168.1). Defaults to local subnet.")
        String subnet;

        @Option(names = "--timeout", description = "Connect timeout in ms (default: 500).", defaultValue = "500")
        int timeout;

        @Option(names = "--ports", description = "Ports to scan (default: 502).", defaultValue = "502")
        String portsParam;

        @Override
        public Integer call() throws Exception {
            String targetSubnet = subnet;
            if (targetSubnet == null) {
                targetSubnet = detectSubnet();
            }
            if (targetSubnet == null) {
                System.err.println("Could not detect local subnet. Please use --subnet 192.168.x");
                return 1;
            }

            List<Integer> ports = Arrays.stream(portsParam.split(","))
                .map(String::trim)
                .map(Integer::parseInt)
                .collect(Collectors.toList());

            System.out.printf("Scanning %s.1-254 for ports %s...\n", targetSubnet, ports);
            
            ExecutorService executor = Executors.newFixedThreadPool(50);
            List<Future<String>> futures = new ArrayList<>();

            for (int i = 1; i < 255; i++) {
                final String host = targetSubnet + "." + i;
                for (int port : ports) {
                    futures.add(executor.submit(() -> {
                        if (checkPort(host, port, timeout)) {
                            return host + ":" + port;
                        }
                        return null;
                    }));
                }
            }

            List<String> found = new ArrayList<>();
            for (Future<String> f : futures) {
                try {
                    String result = f.get();
                    if (result != null) found.add(result);
                } catch (Exception ignored) {}
            }
            executor.shutdown();

            if (found.isEmpty()) {
                System.out.println("No devices found.");
            } else {
                System.out.println("\nFound Modbus Devices:");
                for (String device : found) {
                    System.out.printf(" - %s\n", device);
                }
            }
            return 0;
        }

        private String detectSubnet() {
            try {
                InetAddress localHost = InetAddress.getLocalHost();
                String hostAddress = localHost.getHostAddress();
                int lastDot = hostAddress.lastIndexOf('.');
                if (lastDot > 0) {
                    return hostAddress.substring(0, lastDot);
                }
            } catch (Exception e) {
                log.debug("Failed to detect subnet: {}", e.getMessage());
            }
            return null;
        }

        private boolean checkPort(String host, int port, int timeout) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), timeout);
                return true;
            } catch (Exception e) {
                return false;
            }
        }
    }

    // --- DESCRIBE COMMAND ---
    @Command(name = "describe", description = "Fingerprint device by reading common registers.", mixinStandardHelpOptions = true)
    public static class DescribeCmd implements Callable<Integer> {
        @ParentCommand modbus parent;

        @ArgGroup(exclusive = false, heading = "Device Options:\n", order = 50)
        DeviceOptions locals = new DeviceOptions();

        @ArgGroup(exclusive = false, heading = "Development options:\n", order = 100)
        StandardOptions standardOpts = new StandardOptions();

        @Parameters(index = "0", arity = "0..1", description = "Device alias or IP")
        String targetParam;

        @Override
        public Integer call() throws Exception {
            DeviceProfile p = parent.resolveTarget(targetParam, locals);
            try (ModbusClient client = new ModbusClient(p)) {
                System.out.println("--- Device Fingerprint ---");
                System.out.println("Alias:  " + p.alias);
                System.out.println("Target: " + ("tcp".equals(p.type) ? p.host + ":" + p.port : p.serialPort));
                System.out.println("Unit ID: " + p.unitId);
                
                System.out.println("\n[Holding Registers 0-19] (Configuration/Settings)");
                try {
                    int[] holding = client.read(ModbusType.holding, 0, 20);
                    printRegisters(0, holding);
                } catch (Exception e) {
                    System.out.println("  Failed to read: " + e.getMessage());
                }

                System.out.println("\n[Input Registers 0-19] (Sensors/Status)");
                try {
                    int[] input = client.read(ModbusType.input, 0, 20);
                    printRegisters(0, input);
                } catch (Exception e) {
                    System.out.println("  Failed to read: " + e.getMessage());
                }
            }
            return 0;
        }

        private void printRegisters(int start, int[] values) {
            boolean empty = true;
            for (int i = 0; i < values.length; i++) {
                if (values[i] != 0) {
                    System.out.printf("  %04d: %-6d (0x%04X)\n", start + i, values[i], values[i]);
                    empty = false;
                }
            }
            if (empty) System.out.println("  (All zeros)");
        }
    }

    // --- BACKUP COMMAND ---
    @Command(name = "backup", description = "Read parameters from device and save to CSV.", mixinStandardHelpOptions = true)
    public static class BackupCmd implements Callable<Integer> {
        @ParentCommand modbus parent;

        @ArgGroup(exclusive = false, heading = "Device Options:\n", order = 50)
        DeviceOptions locals = new DeviceOptions();

        @ArgGroup(exclusive = false, heading = "Development options:\n", order = 100)
        StandardOptions standardOpts = new StandardOptions();

        @Parameters(index = "0", arity = "0..1", description = "Device alias or IP")
        String targetParam;

        @Option(names = {"-c", "--config"}, description = "Input mapping/config CSV file. Defaults to 'modbus.csv'.")
        File configFile;

        @Option(names = {"-o", "--output"}, description = "Output CSV file. Defaults to stdout.")
        File outputFile;

        @Option(names = {"-f", "--force"}, description = "Overwrite output file if exists.")
        boolean force;

        @Override
        public Integer call() throws Exception {
            List<ModbusParam> params;
            File cfg = configFile != null ? configFile : new File("modbus.csv");
            
            if (cfg.exists()) {
                params = CsvUtil.read(cfg);
                if (outputFile != null) log.info("Loaded {} parameters from {}", params.size(), cfg);
            } else if (configFile != null) {
                // User explicitly asked for a file that doesn't exist -> Error
                System.err.println("Error: Configuration file not found: " + cfg.getAbsolutePath());
                return 1;
            } else {
                // No flag, no default file -> Use internal default
                if (outputFile != null) log.info("No config file found. Using default backup strategy (Holding 0-9).");
                params = new ArrayList<>();
                for (int i = 0; i < 10; i++) {
                    ModbusParam p = new ModbusParam();
                    p.name = "Register_" + i;
                    p.type = ModbusType.holding;
                    p.address = i;
                    params.add(p);
                }
            }

            if (outputFile != null && outputFile.exists() && !force) {
                throw new RuntimeException("Output file exists. Use --force to overwrite.");
            }

            // Only log info if we are NOT writing to stdout (to avoid polluting pipe output)
            boolean verbose = (outputFile != null);

            Map<ModbusType, List<ModbusParam>> byType = params.stream()
                .filter(p -> p.type != null && p.address >= 0)
                .collect(Collectors.groupingBy(p -> p.type));

            DeviceProfile target = parent.resolveTarget(targetParam, locals);
            try (ModbusClient client = new ModbusClient(target)) {
                for (Map.Entry<ModbusType, List<ModbusParam>> entry : byType.entrySet()) {
                    ModbusType type = entry.getKey();
                    List<ModbusParam> groupParams = entry.getValue();
                    if (groupParams.isEmpty()) continue;
                    
                    int min = groupParams.stream().mapToInt(p -> p.address).min().getAsInt();
                    int max = groupParams.stream().mapToInt(p -> p.address).max().getAsInt();
                    int count = max - min + 1;

                    if (verbose) log.info("Reading {} [{}-{}] (Count: {})", type, min, max, count);
                    int[] values = client.read(type, min, count);
                    
                    for (ModbusParam p : groupParams) {
                        int offset = p.address - min;
                        if (offset >= 0 && offset < values.length) {
                            p.setModbusValue(values[offset]);
                        }
                    }
                }
            }

            if (outputFile != null) {
                CsvUtil.write(outputFile, params);
                log.info("Backup saved to {}", outputFile);
            } else {
                CsvUtil.write(System.out, params);
            }
            return 0;
        }
    }

    // --- RESTORE COMMAND ---
    @Command(name = "restore", description = "Write parameters from CSV to device.", mixinStandardHelpOptions = true)
    public static class RestoreCmd implements Callable<Integer> {
        @ParentCommand modbus parent;

        @ArgGroup(exclusive = false, heading = "Device Options:\n", order = 50)
        DeviceOptions locals = new DeviceOptions();

        @ArgGroup(exclusive = false, heading = "Development options:\n", order = 100)
        StandardOptions standardOpts = new StandardOptions();

        @Parameters(index = "0", arity = "0..1", description = "Device alias or IP")
        String targetParam;

        @Option(names = {"-i", "--input"}, description = "Input CSV file with values to restore. Defaults to 'modbus.csv'.")
        File inputFile;

        @Option(names = {"--dry-run"}, description = "Simulate writes without changing device state.")
        boolean dryRun;

        @Override
        public Integer call() throws Exception {
            File input = inputFile != null ? inputFile : new File("modbus.csv");
            if (!input.exists()) {
                 System.err.println("Error: Input file not found: " + input.getAbsolutePath());
                 return 1;
            }

            List<ModbusParam> params = CsvUtil.read(input);
            log.info("Loaded {} parameters from {}", params.size(), input);

            int success = 0;
            int failed = 0;

            DeviceProfile target = parent.resolveTarget(targetParam, locals);
            try (ModbusClient client = new ModbusClient(target)) {
                for (ModbusParam p : params) {
                    if (p.modbusValue == null || !p.type.isWritable()) continue;

                    log.info("Writing {}: {} -> {}", p.name, p.address, p.modbusValue);
                    if (!dryRun) {
                        try {
                            client.write(p);
                            success++;
                        } catch (Exception e) {
                            log.error("Failed to write {}: {}", p.name, e.getMessage());
                            failed++;
                        }
                    }
                }
            }
            log.info("Restore complete. Written: {}, Failed: {}", success, failed);
            return 0;
        }
    }

    // --- POLL COMMAND ---
    @Command(name = "poll", description = "Poll a specific register range.", mixinStandardHelpOptions = true)
    public static class PollCmd implements Callable<Integer> {
        @ParentCommand modbus parent;

        @ArgGroup(exclusive = false, heading = "Device Options:\n", order = 50)
        DeviceOptions locals = new DeviceOptions();

        @ArgGroup(exclusive = false, heading = "Development options:\n", order = 100)
        StandardOptions standardOpts = new StandardOptions();

        @Parameters(index = "0", arity = "0..1", description = "Device alias or IP")
        String targetParam;

        @Option(names = {"-t", "--type"}, description = "Register Type (coil, discrete, holding, input). Default: holding.", defaultValue = "holding")
        ModbusType type;

        @Option(names = {"-a", "--address"}, required = true, description = "Start Address.")
        int address;

        @Option(names = {"-c", "--count"}, description = "Number of registers. Default: 1.", defaultValue = "1")
        int count;

        @Option(names = {"-l", "--loop"}, description = "Poll continuously every N ms.")
        Integer loopMs;

        @Override
        public Integer call() throws Exception {
            DeviceProfile target = parent.resolveTarget(targetParam, locals);
            try (ModbusClient client = new ModbusClient(target)) {
                do {
                    int[] values = client.read(type, address, count);
                    System.out.printf("[%s] Read %s @ %d (Count: %d)\n", java.time.LocalTime.now(), type, address, count);
                    for (int i = 0; i < values.length; i++) {
                        System.out.printf("  %d: %d\n", address + i, values[i]);
                    }
                    if (loopMs != null) Thread.sleep(loopMs);
                } while (loopMs != null);
            }
            return 0;
        }
    }

    // --- INTERNAL HELPERS ---
    private DeviceProfile resolveTarget(String positionalValue, DeviceOptions local) {
        String deviceOverride = (local != null && local.device != null) ? local.device : deviceOpts.device;
        String targetName = (deviceOverride != null) ? deviceOverride
                          : (positionalValue != null && cfg.devices.containsKey(positionalValue) ? positionalValue : cfg.activeDevice);
        
        DeviceProfile p;
        if (targetName != null && cfg.devices.containsKey(targetName)) {
            p = cfg.devices.get(targetName).copy();
        } else if (positionalValue != null) {
             // Fallback for direct IP if no alias matches
             p = new DeviceProfile();
             p.alias = "direct";
             p.type = "tcp";
             p.host = positionalValue;
             p.port = 502;
        } else {
            p = new DeviceProfile();
            p.alias = "direct";
        }

        // Apply overrides from local flags
        if (local != null) {
            if (local.transport != null) {
                if (local.transport.tcp != null) {
                    p.type = "tcp";
                    p.host = local.transport.tcp.host;
                    p.port = local.transport.tcp.port;
                } else if (local.transport.serial != null) {
                    p.type = "serial";
                    p.serialPort = local.transport.serial.port;
                    p.baudRate = local.transport.serial.baudRate;
                    p.dataBits = local.transport.serial.dataBits;
                    p.stopBits = local.transport.serial.stopBits;
                    p.parity = local.transport.serial.parity;
                }
            }
            if (local.unitId != null) p.unitId = local.unitId;
        }

        if (p.type == null) {
            throw new RuntimeException("No target specified. Use 'device use <alias>', -d <alias>, -tcp <host>, or -serial <port>.");
        }
        return p;
    }

    static class DeviceAliasCandidates implements Iterable<String> {
        @Override
        public Iterator<String> iterator() {
            Config c = Config.load();
            return c.devices.keySet().iterator();
        }
    }

    // --- MODBUS CLIENT ---
    static class ModbusClient implements AutoCloseable {
        private ModbusTCPMaster tcpMaster;
        private ModbusSerialMaster serialMaster;
        private final int unitId;
        private static final int MAX_BATCH = 120;

        public ModbusClient(DeviceProfile p) {
            this.unitId = p.unitId;
            try {
                if ("tcp".equals(p.type)) {
                    log.debug("Connecting to TCP {}:{} (Unit: {})", p.host, p.port, unitId);
                    tcpMaster = new ModbusTCPMaster(p.host, p.port);
                    tcpMaster.connect();
                } else if ("serial".equals(p.type)) {
                    log.debug("Connecting to Serial {} (Baud: {}) (Unit: {})", p.serialPort, p.baudRate, unitId);
                    SerialParameters params = new SerialParameters();
                    params.setPortName(p.serialPort);
                    params.setBaudRate(p.baudRate);
                    params.setDatabits(p.dataBits != null ? p.dataBits : 8);
                    params.setStopbits(p.stopBits != null ? p.stopBits : 1);
                    params.setParity(parseParity(p.parity));
                    params.setEncoding(Modbus.SERIAL_ENCODING_RTU);
                    params.setEcho(false);
                    serialMaster = new ModbusSerialMaster(params);
                    serialMaster.connect();
                }
            } catch (Exception e) {
                throw new RuntimeException("Connection failed: " + e.getMessage(), e);
            }
        }

        private int parseParity(String p) {
            if (p == null) return 0;
            switch (p.toLowerCase()) {
                case "even": return 2;
                case "odd": return 1;
                case "mark": return 3;
                case "space": return 4;
                default: return 0;
            }
        }

        public int[] read(ModbusType type, int start, int count) throws Exception {
            int[] result = new int[count];
            int read = 0;
            while (read < count) {
                int batchSize = Math.min(MAX_BATCH, count - read);
                int currentAddr = start + read;
                int[] batch = readBatch(type, currentAddr, batchSize);
                System.arraycopy(batch, 0, result, read, batchSize);
                read += batchSize;
            }
            return result;
        }

        private int[] readBatch(ModbusType type, int start, int count) throws Exception {
            if (tcpMaster != null) {
                switch (type) {
                    case coil: return bitsToInts(tcpMaster.readCoils(unitId, start, count));
                    case discrete: return bitsToInts(tcpMaster.readInputDiscretes(unitId, start, count));
                    case holding: return regsToInts(tcpMaster.readMultipleRegisters(unitId, start, count));
                    case input: return regsToInts(tcpMaster.readInputRegisters(unitId, start, count));
                }
            } else if (serialMaster != null) {
                switch (type) {
                    case coil: return bitsToInts(serialMaster.readCoils(unitId, start, count));
                    case discrete: return bitsToInts(serialMaster.readInputDiscretes(unitId, start, count));
                    case holding: return regsToInts(serialMaster.readMultipleRegisters(unitId, start, count));
                    case input: return regsToInts(serialMaster.readInputRegisters(unitId, start, count));
                }
            }
            throw new IllegalArgumentException("Not connected or unknown type: " + type);
        }

        public void write(ModbusParam p) throws Exception {
             if (tcpMaster != null) {
                 switch (p.type) {
                     case coil: tcpMaster.writeCoil(unitId, p.address, p.modbusValue != 0); break;
                     case holding: tcpMaster.writeSingleRegister(unitId, p.address, new SimpleRegister(p.modbusValue)); break;
                     default: throw new IllegalArgumentException("Cannot write type: " + p.type);
                 }
             } else if (serialMaster != null) {
                 switch (p.type) {
                     case coil: serialMaster.writeCoil(unitId, p.address, p.modbusValue != 0); break;
                     case holding: serialMaster.writeSingleRegister(unitId, p.address, new SimpleRegister(p.modbusValue)); break;
                     default: throw new IllegalArgumentException("Cannot write type: " + p.type);
                 }
             }
        }

        private int[] bitsToInts(BitVector bv) {
            int[] res = new int[bv.size()];
            for (int i = 0; i < bv.size(); i++) res[i] = bv.getBit(i) ? 1 : 0;
            return res;
        }

        private int[] regsToInts(InputRegister[] regs) {
            int[] res = new int[regs.length];
            for (int i = 0; i < regs.length; i++) res[i] = regs[i].toShort() & 0xFFFF;
            return res;
        }

        @Override
        public void close() {
            if (tcpMaster != null) tcpMaster.disconnect();
            if (serialMaster != null) serialMaster.disconnect();
        }
    }

    // --- DATA MODEL ---
    enum ModbusType { coil, discrete, holding, input; 
        boolean isWritable() { return this == coil || this == holding; }
    }

    @JsonPropertyOrder({ "param", "group", "level", "name", "description", "values", "Default", "Min", "Max", "remarks", "unit", "step", "precision", "offset", "scale", "value", "type", "address", "modbusValue" })
    public static class ModbusParam {
        public String param, group, level, name, description, values, defaultValue, minValue, maxValue, remarks, unit, step;
        public Integer precision;
        public BigDecimal offset, scale, value;
        public ModbusType type;
        public int address;
        public Integer modbusValue;

        public void setModbusValue(int raw) {
            this.modbusValue = raw;
            BigDecimal v = new BigDecimal(raw);
            if (scale != null) v = v.multiply(scale);
            if (offset != null) v = v.add(offset);
            this.value = v;
        }
        
        public void setValue(BigDecimal v) {
            this.value = v;
            if (v == null) {
                this.modbusValue = null;
                return;
            }
            BigDecimal raw = v;
            if (offset != null) raw = raw.subtract(offset);
            if (scale != null) raw = raw.divide(scale, RoundingMode.HALF_UP);
            this.modbusValue = raw.intValue();
        }
    }

    static class DeviceProfile {
        public String alias, type, host, serialPort, parity;
        public Integer port, baudRate, dataBits, stopBits;
        public int unitId = 1;

        public DeviceProfile copy() {
            DeviceProfile p = new DeviceProfile();
            p.alias = alias; p.type = type; p.host = host; p.port = port;
            p.serialPort = serialPort; p.baudRate = baudRate; p.dataBits = dataBits;
            p.stopBits = stopBits; p.parity = parity; p.unitId = unitId;
            return p;
        }
    }

    static class Config {
        public String activeDevice;
        public Map<String, DeviceProfile> devices = new HashMap<>();

        static Config load() {
            try {
                if (Files.exists(CONFIG_PATH)) return YAML_MAPPER.readValue(CONFIG_PATH.toFile(), Config.class);
            } catch (Exception e) { log.debug("Config load failed: {}", e.getMessage()); }
            return new Config();
        }

        void save() {
            try {
                Files.createDirectories(CONFIG_PATH.getParent());
                YAML_MAPPER.writerWithDefaultPrettyPrinter().writeValue(CONFIG_PATH.toFile(), this);
            } catch (Exception e) { throw new RuntimeException(e); }
        }
    }

    static class CsvUtil {
        static List<ModbusParam> read(File file) throws IOException {
            List<String> lines = Files.readAllLines(file.toPath());
            
            // Find header line to support files with/without metadata preamble
            int headerIndex = 0;
            for (int i = 0; i < Math.min(lines.size(), 10); i++) {
                if (lines.get(i).trim().toLowerCase().startsWith("param")) {
                    headerIndex = i;
                    break;
                }
            }
            
            // Fallback: If no "param" header found but file is large, maybe it's just data?
            // But we rely on Jackson matching header names. 
            // If headerIndex is 0 and line 0 doesn't look like header, Jackson might fail or skip.
            // For now, robustly skipping metadata if "param" is found.
            
            List<String> dataLines = lines.subList(headerIndex, lines.size());
            if (dataLines.isEmpty()) return Collections.emptyList();
            
            CsvSchema schema = CsvSchema.emptySchema().withHeader();
            try (MappingIterator<ModbusParam> it = CSV_MAPPER.readerFor(ModbusParam.class).with(schema).readValues(String.join("\n", dataLines))) {
                return it.readAll();
            }
        }

        static void write(File file, List<ModbusParam> params) throws IOException {
            CsvSchema schema = CSV_MAPPER.schemaFor(ModbusParam.class).withHeader();
            CSV_MAPPER.writer(schema).writeValue(file, params);
        }
        
        static void write(java.io.PrintStream out, List<ModbusParam> params) throws IOException {
            CsvSchema schema = CSV_MAPPER.schemaFor(ModbusParam.class).withHeader();
            // Don't close System.out!
            CSV_MAPPER.writer(schema).writeValue(out, params);
        }
    }
}