package vault5431;

import org.apache.commons.csv.CSVRecord;
import vault5431.crypto.SymmetricUtils;
import vault5431.crypto.exceptions.BadCiphertextException;
import vault5431.io.Base64String;
import vault5431.io.FileUtils;
import vault5431.logging.CSVUtils;
import vault5431.logging.LogType;
import vault5431.logging.SystemLogEntry;
import vault5431.users.User;

import java.io.File;
import java.io.IOException;
import java.time.LocalDateTime;

import static vault5431.Vault.adminEncryptionKey;
import static vault5431.Vault.home;

/**
 * System class. Will contain Master keys and all methods required to act with Sys authority.
 */
public class Sys {

    public static final String SYS = "SYS";
    public static final String NO_IP = "0.0.0.0";
    public static final File logFile = new File(home, "log");

    /**
     * Logs an error in the system log
     *
     * @param message      Reason for error
     * @param affectedUser Affected user
     * @param ip           IP causing error
     */
    public static void error(String message, User affectedUser, String ip) {
        appendToLog(new SystemLogEntry(LogType.ERROR, ip, affectedUser, LocalDateTime.now(), message, ""));
    }

    public static void error(String message, String ip) {
        appendToLog(new SystemLogEntry(LogType.ERROR, ip, SYS, LocalDateTime.now(), message, ""));
    }

    public static void error(String message, User affectedUser) {
        appendToLog(new SystemLogEntry(LogType.ERROR, NO_IP, affectedUser, LocalDateTime.now(), message, ""));
    }

    public static void error(String message) {
        appendToLog(new SystemLogEntry(LogType.ERROR, NO_IP, SYS, LocalDateTime.now(), message, ""));
    }

    /**
     * Logs a warning in the system log
     *
     * @param message      Reason for warning
     * @param affectedUser Affected user
     * @param ip           IP causing warning
     */
    public static void warning(String message, User affectedUser, String ip) {
        appendToLog(new SystemLogEntry(LogType.WARNING, ip, affectedUser, LocalDateTime.now(), message, ""));
    }

    public static void warning(String message, String ip) {
        appendToLog(new SystemLogEntry(LogType.WARNING, ip, SYS, LocalDateTime.now(), message, ""));
    }

    public static void warning(String message, User affectedUser) {
        appendToLog(new SystemLogEntry(LogType.WARNING, NO_IP, affectedUser, LocalDateTime.now(), message, ""));
    }

    public static void warning(String message) {
        appendToLog(new SystemLogEntry(LogType.WARNING, NO_IP, SYS, LocalDateTime.now(), message, ""));
    }

    /**
     * Logs an info message in the system log
     *
     * @param message      Message contents
     * @param affectedUser Affected user
     * @param ip           Relevant IP
     */
    public static void info(String message, User affectedUser, String ip) {
        appendToLog(new SystemLogEntry(LogType.INFO, ip, affectedUser, LocalDateTime.now(), message, ""));
    }

    public static void info(String message, String ip) {
        appendToLog(new SystemLogEntry(LogType.INFO, ip, SYS, LocalDateTime.now(), message, ""));
    }

    public static void info(String message, User affectedUser) {
        appendToLog(new SystemLogEntry(LogType.INFO, NO_IP, affectedUser, LocalDateTime.now(), message, ""));
    }

    public static void info(String message) {
        appendToLog(new SystemLogEntry(LogType.INFO, NO_IP, SYS, LocalDateTime.now(), message, ""));
    }

    /**
     * Logs a debug message in the system log
     *
     * @param message      Message contents
     * @param affectedUser Affected user
     * @param ip           Relevant IP
     */
    public static void debug(String message, User affectedUser, String ip) {
        appendToLog(new SystemLogEntry(LogType.DEBUG, ip, affectedUser, LocalDateTime.now(), message, ""));
    }

    public static void debug(String message, String ip) {
        appendToLog(new SystemLogEntry(LogType.DEBUG, ip, SYS, LocalDateTime.now(), message, ""));
    }

    public static void debug(String message, User affectedUser) {
        appendToLog(new SystemLogEntry(LogType.DEBUG, NO_IP, affectedUser, LocalDateTime.now(), message, ""));
    }

    public static void debug(String message) {
        appendToLog(new SystemLogEntry(LogType.DEBUG, NO_IP, SYS, LocalDateTime.now(), message, ""));
    }


    /**
     * Append LogEntry to system log.
     * Suppresses most errors
     *
     * @param entry Entry to log
     */
    public static void appendToLog(SystemLogEntry entry) {
        synchronized (logFile) {
            try {
                System.out.println(entry.toString());
                try {
                    Base64String encryptedEntry = SymmetricUtils.encrypt(entry.toCSV().getBytes(), adminEncryptionKey);
                    FileUtils.append(logFile, encryptedEntry);
                } catch (BadCiphertextException err) {
                    err.printStackTrace();
                    System.err.println("Cannot System log entry! Fatal error. Halting.");
                    System.exit(1);
                }
            } catch (IOException err) {
                err.printStackTrace();
                System.err.println("[WARNING] Failed to log as System! Continuing.");
            }
        }
    }

    /**
     * Load system log from disk, only for demonstration purposes. System should be decryptable by anyone but sys admins
     *
     * @return Set of LogEntries loaded from disk.
     * @throws IOException
     */
    public static SystemLogEntry[] loadLog() {
        synchronized (logFile) {
            try {
                Base64String[] encryptedEntries = FileUtils.read(logFile);
                SystemLogEntry[] decryptedEntries = new SystemLogEntry[encryptedEntries.length];
                for (int i = 0; i < encryptedEntries.length; i++) {
                    try {
                        String entry = new String(SymmetricUtils.decrypt(encryptedEntries[i], adminEncryptionKey));
                        CSVRecord record = CSVUtils.parseRecord(entry).getRecords().get(0);
                        decryptedEntries[i] = SystemLogEntry.fromCSV(record);
                    } catch (BadCiphertextException err) {
                        err.printStackTrace();
                        System.err.println("Cannot load/decrypt system log! Fatal! Halting.");
                        System.exit(1);
                    }
                }
                return decryptedEntries;
            } catch (IOException err) {
                err.printStackTrace();
                System.err.println("[WARNING] Failed to load system log! Continuing.");
                return new SystemLogEntry[0];
            }
        }
    }

}
