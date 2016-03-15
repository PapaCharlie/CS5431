package vault5431;

import org.apache.commons.csv.CSVRecord;
import vault5431.io.Base64String;
import vault5431.io.FileUtils;
import vault5431.logging.CSVUtils;
import vault5431.logging.LogType;
import vault5431.logging.SystemLogEntry;

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
    public static final File logFile = new File(home + File.separator + "log");

    public static void error(String ip, String affectedUser, String message) throws IOException {
        appendToLog(new SystemLogEntry(LogType.ERROR, ip, affectedUser, LocalDateTime.now(), message, ""));
    }

    public static void error(String ip, String message) throws IOException {
        appendToLog(new SystemLogEntry(LogType.ERROR, ip, SYS, LocalDateTime.now(), message, ""));
    }

    public static void error(String message) throws IOException {
        appendToLog(new SystemLogEntry(LogType.ERROR, NO_IP, SYS, LocalDateTime.now(), message, ""));
    }

    public static void warning(String ip, String affectedUser, String message) throws IOException {
        appendToLog(new SystemLogEntry(LogType.WARNING, ip, affectedUser, LocalDateTime.now(), message, ""));
    }

    public static void warning(String ip, String message) throws IOException {
        appendToLog(new SystemLogEntry(LogType.WARNING, ip, SYS, LocalDateTime.now(), message, ""));
    }

    public static void warning(String message) throws IOException {
        appendToLog(new SystemLogEntry(LogType.WARNING, NO_IP, SYS, LocalDateTime.now(), message, ""));
    }

    public static void info(String ip, String affectedUser, String message) throws IOException {
        appendToLog(new SystemLogEntry(LogType.INFO, ip, affectedUser, LocalDateTime.now(), message, ""));
    }

    public static void info(String ip, String message) throws IOException {
        appendToLog(new SystemLogEntry(LogType.INFO, ip, SYS, LocalDateTime.now(), message, ""));
    }

    public static void info(String message) throws IOException {
        appendToLog(new SystemLogEntry(LogType.INFO, NO_IP, SYS, LocalDateTime.now(), message, ""));
    }

    public static void debug(String ip, String affectedUser, String message) throws IOException {
        appendToLog(new SystemLogEntry(LogType.DEBUG, ip, affectedUser, LocalDateTime.now(), message, ""));
    }

    public static void debug(String ip, String message) throws IOException {
        appendToLog(new SystemLogEntry(LogType.DEBUG, ip, SYS, LocalDateTime.now(), message, ""));
    }

    public static void debug(String message) throws IOException {
        appendToLog(new SystemLogEntry(LogType.DEBUG, NO_IP, SYS, LocalDateTime.now(), message, ""));
    }

    public static void appendToLog(SystemLogEntry entry) throws IOException {
        synchronized (logFile) {
            FileUtils.append(logFile, new Base64String(entry.toCSV()));
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
