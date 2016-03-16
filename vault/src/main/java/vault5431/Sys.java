package vault5431;

import org.apache.commons.csv.CSVRecord;
import vault5431.io.Base64String;
import vault5431.io.FileUtils;
import vault5431.logging.CSVUtils;
import vault5431.logging.LogType;
import vault5431.logging.SystemLogEntry;
import vault5431.users.User;

import java.io.File;
import java.io.IOException;
import java.time.LocalDateTime;

import static vault5431.Vault.home;

/**
 * System class. Will contain Master keys and all methods required to act with Sys authority.
 */
public class Sys {

    public static final String SYS = "SYS";
    public static final String NO_IP = "0.0.0.0";
    public static final File logFile = new File(home, "log");

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


    public static void appendToLog(SystemLogEntry entry) {
        synchronized (logFile) {
            try {
                FileUtils.append(logFile, new Base64String(entry.toCSV()));
            } catch (IOException err) {
                err.printStackTrace();
                System.err.println("[WARNING] Failed to log as System! Continuing.");
            }
        }
    }

    public static SystemLogEntry[] loadLog() throws IOException {
        synchronized (logFile) {
            Base64String[] encryptedEntries = FileUtils.read(logFile);
            SystemLogEntry[] decryptedEntries = new SystemLogEntry[encryptedEntries.length];
            for (int i = 0; i < encryptedEntries.length; i++) {
                CSVRecord record = CSVUtils.parseRecord(encryptedEntries[i].decodeString()).getRecords().get(0);
                decryptedEntries[i] = SystemLogEntry.fromCSV(record);
            }
            return decryptedEntries;
        }
    }

}
