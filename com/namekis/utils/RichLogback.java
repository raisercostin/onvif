package com.namekis.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.filter.LevelFilter;
import ch.qos.logback.classic.filter.ThresholdFilter;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.ConsoleAppender;
import ch.qos.logback.core.pattern.color.ANSIConstants;
import ch.qos.logback.core.pattern.color.ForegroundCompositeConverterBase;
import ch.qos.logback.core.spi.FilterReply;
import picocli.CommandLine;
import picocli.CommandLine.Help.Visibility;
import picocli.CommandLine.Option;
import picocli.CommandLine.ScopeType;
import picocli.CommandLine.TraceLevel;
import java.util.concurrent.Callable;
import java.util.function.Supplier;

/**
 * A utility class to configure Logback logging based on verbosity levels(0-5).
 *
 * <li>level 0 - Normal: Only INFO and above are logged to stdout, WARN and
 * ERROR to stderr. No detailed logs on caller, timestamp, or thread.
 * <li>level 1 - Normal Detailed: Similar to level 0, but includes detailed logs
 * on caller, timestamp, and thread. Useful for debugging without overwhelming
 * output.
 * <li>level 2 - Info: Logs INFO and above to stdout, WARN and ERROR to stderr.
 * Includes detailed logs on caller, timestamp, and thread.
 * <li>level 3 - Debug: Logs DEBUG and above to stdout, WARN and ERROR to
 * stderr.
 * <li>level 4 - Trace: Logs TRACE and above to stdout, WARN and ERROR to
 * stderr.
 * <li>level 5 - LogDebug: Logs all levels (TRACE, DEBUG, INFO, WARN, ERROR) to
 * stdout and stderr.
 *
 * It sets up console appenders for both standard output and error streams with
 * appropriate filters. The verbosity levels range from detailed debug logs to
 * quiet error logs.
 *
 * TODO: Add levels increased by 10 for more granularity if needed. How will
 * affect -vvvv or -qqqq
 */
public class RichLogback {
  private static final int LEVEL5_LOGDEBUG = 5;
  private static final int LEVEL4_TRACE = 4;
  private static final int LEVEL3_DEBUG = 3;
  private static final int LEVEL2_INFO = 2;
  private static final int LEVEL1_NORMAL_DETAILED = 1;
  private static final int LEVEL0_NORMAL = 0; // nothing from logs
  private static final Logger log = LoggerFactory.getLogger(RichLogback.class);

  public static class BaseOptions {
    @Option(names = { "-q",
        "--quiet" }, description = "Suppress almost all log output. Use multiple (-qqq)", scope = ScopeType.INHERIT)
    public boolean[] quiet = new boolean[0];

    @Option(names = { "-v",
        "--verbose" }, description = "Increase verbosity. Use multiple (-vvv)", scope = ScopeType.INHERIT)
    public boolean[] verbosity = new boolean[0];

    @Option(names = { "-co",
        "--color" }, description = "Enable colored output (default: true).", defaultValue = "true", negatable = true, showDefaultValue = Visibility.ALWAYS, scope = ScopeType.INHERIT)
    public boolean color = true;

    @Option(names = { "-de",
        "--debug" }, description = "Enable debug (default: false).", defaultValue = "false", showDefaultValue = Visibility.ALWAYS, scope = ScopeType.INHERIT)
    public boolean debug = false;

    @Option(names = { "-tr",
        "--trace" }, description = "Show full stack traces for errors.", defaultValue = "false", scope = ScopeType.INHERIT)
    public boolean trace = false;

    @Option(names = {
        "--workdir" }, description = "Base directory for operations (default: current dir)", scope = ScopeType.INHERIT)
    public String workdir = System.getProperty("user.dir");

    public boolean isQuiet() {
      return verbosity.length - quiet.length < LEVEL0_NORMAL;
    }

    public void info(Logger log, String message, Exception e) {
      if (trace) {
        log.info("{}:", message, e);
      } else {
        log.info("{}: {}. (Use --trace for full stack trace)", message, e.getMessage());
      }
    }

    public void debug(Logger log, String message, Exception e) {
      if (trace) {
        log.debug("{}:", message, e);
      } else {
        log.debug("{}: {}. (Use --trace for full stack trace)", message, e.getMessage());
      }
    }
  }

  public static class LevelColorConverter extends ForegroundCompositeConverterBase<ILoggingEvent> {
    @Override
    protected String getForegroundColorCode(ILoggingEvent event) {
      Level level = event.getLevel();
      switch (level.toInt()) {
        case Level.ERROR_INT:
          return ANSIConstants.BOLD + "91";// ANSIConstants.RED_FG;
        case Level.WARN_INT:
          return "91";// ANSIConstants.RED_FG;
        case Level.INFO_INT:
          // return "33";//
          return ANSIConstants.DEFAULT_FG;
        case Level.DEBUG_INT:
          return ANSIConstants.YELLOW_FG;
        case Level.TRACE_INT:
          return ANSIConstants.MAGENTA_FG;
        default:
          return ANSIConstants.DEFAULT_FG;
      }
    }
  }

  public static BaseOptions configureLogbackByVerbosity(String... args) {
    BaseOptions args2 = (BaseOptions) new CommandLine(new BaseOptions()).setUnmatchedArgumentsAllowed(true)
        .setCaseInsensitiveEnumValuesAllowed(true).setUsageHelpWidth(100).parseArgs(args).commandSpec().userObject();
    configureLogbackByVerbosity(null, args2.verbosity.length, args2.quiet.length, args2.color, args2.debug);
    return args2;
  }

  public static void main(String[] args, Supplier<Object> command) {
    BaseOptions opts = configureLogbackByVerbosity(args);
    CommandLine cmd = new CommandLine(command.get());
    cmd.setExecutionExceptionHandler((ex, commandLine, parseResult) -> {
      if (opts.trace) {
        log.warn("Execution failed:", ex);
      } else {
        log.warn("{} (Use --trace for full stack trace)", ex.getMessage());
      }
      return commandLine.getCommandSpec().exitCodeOnExecutionException();
    });
    int res = cmd.execute(args);
    if (res != 0) {
      System.exit(res);
    }
  }

  public static void configureLogbackByVerbosity(String categories, int verbosity, int quiet, boolean color,
      boolean debug) {
    LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
    context.reset();
    verbosity -= quiet; // quiet decreases verbosity

    String simplePattern = color ? "%highlight(%msg) %n" : "%msg %n";
    String detailedPattern = color
        ? "%-5r/%d{yyyy-MM-dd HH:mm:ss.SSS} %highlight(%-5level) [%-4thread] %highlight(%msg) - %logger{36} @ %C.%M\\(%F:%L\\)%n"
        : "%-5r/%d{yyyy-MM-dd HH:mm:ss.SSS} %-5level [%-4thread] %msg - %logger{36} @ %C.%M\\(%F:%L\\)%n";

    // Pattern selection by verbosity: verbosity == LEVEL0_NORMAL ? simplePattern :
    // detailedPattern;
    String pattern = debug ? detailedPattern : simplePattern;

    ch.qos.logback.classic.PatternLayout.DEFAULT_CONVERTER_MAP.put("highlight", LevelColorConverter.class.getName());
    // STDOUT appender: INFO/DEBUG/TRACE (but not WARN/ERROR)
    PatternLayoutEncoder outEncoder = new PatternLayoutEncoder();
    outEncoder.setContext(context);
    outEncoder.setPattern(pattern);
    outEncoder.start();

    ConsoleAppender<ILoggingEvent> outAppender = new ConsoleAppender<>();
    outAppender.setContext(context);
    outAppender.setTarget("System.out");
    outAppender.setEncoder(outEncoder);
    outAppender.setWithJansi(color);

    // Accept levels for stdout: adjust by verbosity
    ThresholdFilter stdOutFilter = new ThresholdFilter();
    if (verbosity >= LEVEL4_TRACE) {
      stdOutFilter.setLevel("TRACE");
    } else if (verbosity >= LEVEL3_DEBUG) {
      stdOutFilter.setLevel("DEBUG");
    } else if (verbosity >= LEVEL0_NORMAL) {
      stdOutFilter.setLevel("INFO");
    } else {
      stdOutFilter.setLevel("WARN");
    }
    stdOutFilter.start();
    outAppender.addFilter(stdOutFilter);
    // Deny WARN on STDOUT
    LevelFilter denyWarn = new LevelFilter();
    denyWarn.setLevel(Level.WARN);
    denyWarn.setOnMatch(FilterReply.DENY);
    denyWarn.setOnMismatch(FilterReply.NEUTRAL);
    denyWarn.start();
    outAppender.addFilter(denyWarn);

    // Deny ERROR on STDOUT
    LevelFilter denyError = new LevelFilter();
    denyError.setLevel(Level.ERROR);
    denyError.setOnMatch(FilterReply.DENY);
    denyError.setOnMismatch(FilterReply.NEUTRAL);
    denyError.start();
    outAppender.addFilter(denyError);

    outAppender.start();

    // STDERR appender: WARN/ERROR only
    PatternLayoutEncoder errEncoder = new PatternLayoutEncoder();
    errEncoder.setContext(context);
    errEncoder.setPattern(pattern);
    errEncoder.start();

    ConsoleAppender<ILoggingEvent> errAppender = new ConsoleAppender<>();
    errAppender.setContext(context);
    errAppender.setTarget("System.err");
    errAppender.setEncoder(errEncoder);
    errAppender.setWithJansi(color);

    ThresholdFilter errFilter = new ThresholdFilter();
    errFilter.setLevel("WARN"); // Accept WARN and above
    errFilter.start();
    errAppender.addFilter(errFilter);

    errAppender.start();

    // Set logger level according to verbosity
    Level logLevel = Level.INFO;
    if (verbosity >= LEVEL4_TRACE)
      logLevel = Level.TRACE;
    else if (verbosity == LEVEL3_DEBUG)
      logLevel = Level.DEBUG;
    else if (verbosity == LEVEL2_INFO)
      logLevel = Level.INFO;
    else if (verbosity == LEVEL1_NORMAL_DETAILED)
      logLevel = Level.INFO;
    else if (verbosity == LEVEL0_NORMAL)
      logLevel = Level.INFO;
    else if (verbosity < LEVEL0_NORMAL && quiet <= 0)
      logLevel = Level.WARN;
    else if (verbosity < LEVEL0_NORMAL && quiet > 0)
      logLevel = Level.ERROR;
    else
      logLevel = Level.INFO;

    categories = (categories == null || categories.isEmpty()) ? org.slf4j.Logger.ROOT_LOGGER_NAME : categories;
    // foreach
    for (String category : categories.split(",")) {
      category = category.trim();
      ch.qos.logback.classic.Logger logger = context.getLogger(category);
      logger.setLevel(logLevel);
      logger.setAdditive(false); // avoid double logging
      logger.addAppender(outAppender);
      logger.addAppender(errAppender);
      log.debug("Logback configured with category {} with verbosity {}", category, verbosity);
    }
    if (verbosity >= LEVEL5_LOGDEBUG) {
      System.out.println(String.format("Logback configured with verbosity %d, quiet %d, color %s, debug %s", verbosity,
          quiet, color, debug));
      System.err.println(String.format("Logback configured with verbosity %d, quiet %d, color %s, debug %s", verbosity,
          quiet, color, debug));
      log.trace("test trace");
      log.debug("test debug");
      log.info("test info");
      log.warn("test warn");
      log.error("test error");

      String os = System.getProperty("os.name", "").toLowerCase();
      boolean isWindows = os.contains("win");

      String conEmu = System.getenv("ConEmuANSI");
      String ansicon = System.getenv("ANSICON");
      String picocliAnsi = System.getProperty("picocli.ansi");
      String jansiPassthrough = System.getProperty("jansi.passthrough");

      // If Windows ANSI is forced and terminal advertises ANSI via ConEmu/ANSICON,
      // but JANSI is in passthrough mode, stderr may not be colorized unless
      // ConEmuHk injection is enabled.
      if (isWindows && "true".equalsIgnoreCase(picocliAnsi) && jansiPassthrough != null
          && (conEmu != null || ansicon != null)) {
        System.err.println("Hint: If ANSI escapes appear on stderr, enable 'Inject ConEmuHk' in ConEmu settings.");
      }
      CommandLine.tracer().setLevel(TraceLevel.DEBUG);
    }
  }
}
