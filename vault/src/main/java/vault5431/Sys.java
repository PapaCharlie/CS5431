package vault5431;

import vault5431.auth.AuthenticationHandler.Token;
import vault5431.crypto.SymmetricUtils;
import vault5431.crypto.exceptions.BadCiphertextException;
import vault5431.crypto.exceptions.InvalidSignatureException;
import vault5431.io.Base64String;
import vault5431.io.FileUtils;
import vault5431.logging.CSVUtils;
import vault5431.logging.LogType;
import vault5431.logging.SystemLogEntry;
import vault5431.routes.Routes;
import vault5431.users.User;
import vault5431.users.exceptions.CorruptedLogException;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.time.LocalDateTime;

import static vault5431.Vault.getAdminLoggingKey;
import static vault5431.Vault.home;

/**
 * System class. Contains all methods required to act with admin authority.
 *
 * @author papacharlie
 */
public class Sys {

    public static final String SYS = "SYS";
    public static final String NO_IP = "N/A";
    private static final File logFile = new File(home, "log");
    private static final SecretKey firstLoggingKey = getAdminLoggingKey();
    private static SecretKey currentLoggingKey = firstLoggingKey;

    protected synchronized static void initialize() {
        if (!logFile.exists()) {
            try {
                if (!logFile.createNewFile()) {
                    System.err.printf("Could not create system log file at %s!%n", logFile.getAbsoluteFile());
                    System.exit(1);
                }
            } catch (IOException err) {
                err.printStackTrace();
                System.err.printf("Could not create system log file at %s!%n", logFile.getAbsoluteFile());
                throw new RuntimeException(err);
            }
        } else {
            loadLog();
        }
    }

    /**
     * Logs an error in the system log.
     *
     * @param message      Reason for error
     * @param affectedUser Affected user
     * @param ip           IP causing error
     */
    public static void error(String message, User affectedUser, String ip) {
        appendToLog(new SystemLogEntry(LogType.ERROR, ip, affectedUser, LocalDateTime.now(), message));
    }

    public static void error(String message, String ip) {
        appendToLog(new SystemLogEntry(LogType.ERROR, ip, SYS, LocalDateTime.now(), message));
    }

    public static void error(String message, Token token) {
        appendToLog(new SystemLogEntry(LogType.ERROR, token.getIp(), token.getUser(), LocalDateTime.now(), message));
    }

    public static void error(String message, User affectedUser) {
        appendToLog(new SystemLogEntry(LogType.ERROR, NO_IP, affectedUser, LocalDateTime.now(), message));
    }

    public static void error(String message) {
        appendToLog(new SystemLogEntry(LogType.ERROR, NO_IP, SYS, LocalDateTime.now(), message));
    }

    /**
     * Logs a warning in the system log.
     *
     * @param message      Reason for warning
     * @param affectedUser Affected user
     * @param ip           IP causing warning
     */
    public static void warning(String message, User affectedUser, String ip) {
        appendToLog(new SystemLogEntry(LogType.WARNING, ip, affectedUser, LocalDateTime.now(), message));
    }

    public static void warning(String message, String ip) {
        appendToLog(new SystemLogEntry(LogType.WARNING, ip, SYS, LocalDateTime.now(), message));
    }

    public static void warning(String message, Token token) {
        appendToLog(new SystemLogEntry(LogType.WARNING, token.getIp(), token.getUser(), LocalDateTime.now(), message));
    }

    public static void warning(String message, User affectedUser) {
        appendToLog(new SystemLogEntry(LogType.WARNING, NO_IP, affectedUser, LocalDateTime.now(), message));
    }

    public static void warning(String message) {
        appendToLog(new SystemLogEntry(LogType.WARNING, NO_IP, SYS, LocalDateTime.now(), message));
    }

    /**
     * Logs an info message in the system log.
     *
     * @param message      Message contents
     * @param affectedUser Affected user
     * @param ip           Relevant IP
     */
    public static void info(String message, User affectedUser, String ip) {
        appendToLog(new SystemLogEntry(LogType.INFO, ip, affectedUser, LocalDateTime.now(), message));
    }

    public static void info(String message, String ip) {
        appendToLog(new SystemLogEntry(LogType.INFO, ip, SYS, LocalDateTime.now(), message));
    }

    public static void info(String message, Token token) {
        appendToLog(new SystemLogEntry(LogType.INFO, token.getIp(), token.getUser(), LocalDateTime.now(), message));
    }

    public static void info(String message, User affectedUser) {
        appendToLog(new SystemLogEntry(LogType.INFO, NO_IP, affectedUser, LocalDateTime.now(), message));
    }

    public static void info(String message) {
        appendToLog(new SystemLogEntry(LogType.INFO, NO_IP, SYS, LocalDateTime.now(), message));
    }

    /**
     * Logs a debug message in the system log.
     *
     * @param message      Message contents
     * @param affectedUser Affected user
     * @param ip           Relevant IP
     */
    public static void debug(String message, User affectedUser, String ip) {
        appendToLog(new SystemLogEntry(LogType.DEBUG, ip, affectedUser, LocalDateTime.now(), message));
    }

    public static void debug(String message, String ip) {
        appendToLog(new SystemLogEntry(LogType.DEBUG, ip, SYS, LocalDateTime.now(), message));
    }

    public static void debug(String message, Token token) {
        appendToLog(new SystemLogEntry(LogType.DEBUG, token.getIp(), token.getUser(), LocalDateTime.now(), message));
    }

    public static void debug(String message, User affectedUser) {
        appendToLog(new SystemLogEntry(LogType.DEBUG, NO_IP, affectedUser, LocalDateTime.now(), message));
    }

    public static void debug(String message) {
        appendToLog(new SystemLogEntry(LogType.DEBUG, NO_IP, SYS, LocalDateTime.now(), message));
    }

    private static void iterateLoggingKey() {
        synchronized (firstLoggingKey) {
            currentLoggingKey = SymmetricUtils.hashIterateKey(currentLoggingKey);
        }
    }

    private static SecretKey deriveLogEncryptionKey() {
        synchronized (firstLoggingKey) {
            return SymmetricUtils.combine(currentLoggingKey, "encryption".getBytes());
        }
    }

    private static SecretKey deriveLogSigningKey() {
        synchronized (firstLoggingKey) {
            return SymmetricUtils.combine(currentLoggingKey, "signing".getBytes());
        }
    }

    /**
     * Append LogEntry to system log.
     * Suppresses most errors
     *
     * @param entry Entry to log
     */
    public synchronized static void appendToLog(SystemLogEntry entry) {
        synchronized (logFile) {
            synchronized (firstLoggingKey) {
                try {
                    try {
                        FileUtils.append(logFile, SymmetricUtils.authEnc(entry.toCSV().getBytes(), deriveLogEncryptionKey(), deriveLogSigningKey()));
                        iterateLoggingKey();
                        System.out.println("[SYS] " + entry.toString());
                    } catch (BadCiphertextException err) {
                        System.err.println("Cannot System log entry! Fatal error. Halting.");
                        throw new RuntimeException(err);
                    }
                } catch (IOException err) {
                    Routes.panic(err);
                    throw new RuntimeException(err);
                }
            }
        }
    }

    /**
     * Load system log from disk, only for demonstration purposes. System should not be decryptable by anyone but sys admins.
     *
     * @return Set of LogEntries loaded from disk.
     */
    public synchronized static SystemLogEntry[] loadLog() {
        synchronized (logFile) {
            synchronized (firstLoggingKey) {
                try {
                    Base64String[] encryptedEntries = FileUtils.read(logFile);
                    SystemLogEntry[] decryptedEntries = new SystemLogEntry[encryptedEntries.length];
                    currentLoggingKey = firstLoggingKey;
                    for (int i = 0; i < encryptedEntries.length; i++) {
                        String entry = new String(SymmetricUtils.authDec(encryptedEntries[i], deriveLogEncryptionKey(), deriveLogSigningKey()));
                        decryptedEntries[i] = SystemLogEntry.fromCSV(CSVUtils.parseRecord(entry).getRecords().get(0));
                        iterateLoggingKey();
                    }
                    return decryptedEntries;
                } catch (IllegalArgumentException | InvalidSignatureException | IOException err) {
                    System.err.println("System log was corrupted. Exiting.");
                    System.exit(1);
                    throw new RuntimeException();
                }
            }
        }
    }

}
