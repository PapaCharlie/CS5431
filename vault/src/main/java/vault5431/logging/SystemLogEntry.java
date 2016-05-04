package vault5431.logging;

import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import vault5431.users.User;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Represents a system log entry for use by the system admins to check
 * for suspicious activity.
 */
public  class SystemLogEntry extends LogEntry {

    public SystemLogEntry(LogType logType, String ip, String affectedUser,
                          LocalDateTime timestamp, String message, String signature) {
        this.logType = logType;
        this.ip = ip;
        this.affectedUser = affectedUser;
        this.timestamp = timestamp;
        this.message = message;
        this.signature = signature;
    }

    public SystemLogEntry(LogType logType, String ip, User affectedUser,
                          LocalDateTime timestamp, String message, String signature) {
        this(logType, ip, affectedUser.getShortHash(), timestamp, message, signature);
    }

    /**
     * @param entry is a CSV record representation of a SystemLogEntry
     * @return a SystemLogEntry with the relevant information from the CSV string
     */
    public static SystemLogEntry fromCSV(CSVRecord entry) {
        return new SystemLogEntry(LogType.fromString(entry.get(0)), entry.get(1), entry.get(2), LocalDateTime.parse(entry.get(3)), entry.get(4), entry.get(5));
    }

    /**
     * @param entries is a CSVParser containing multiple CSVRecords, each of which represents
     *                a SystemLogEntry
     * @return Array of SystemLogEntries derived from the CSVParser
     * @throws IOException
     */
    public static SystemLogEntry[] fromCSV(CSVParser entries) throws IOException {
        List<CSVRecord> records = entries.getRecords();
        SystemLogEntry[] parsedEntries = new SystemLogEntry[records.size()];
        for (int i = 0; i < parsedEntries.length; i++) {
            CSVRecord entry = records.get(i);
            parsedEntries[i] = new SystemLogEntry(LogType.fromString(entry.get(0)), entry.get(1), entry.get(2), LocalDateTime.parse(entry.get(3)), entry.get(4), entry.get(5));
        }
        return parsedEntries;
    }

    /**
     * Checks the signature of a log to ensure that the log entry is written by the
     * system and not an outsider user/attacker
     *
     * @param signature
     * @return true if there if signatures match, false otherwise.
     */
    public boolean checkSignature(String signature) {
        return signature.equals(this.signature);
    }

    @Override
    public String toString() {
        StringBuilder logString = new StringBuilder();
        return logString.append("[").append(logType).append("]").append(" ").append(ip)
                .append(" ").append(affectedUser).append(" ").append(timestamp)
                .append(" ").append(message).append(" ").toString();
    }

    /**
     * @return a String[] representation of the SystemLogEntry
     */
    public String[] asArray() {
        return new String[]{logType.toString(), ip, affectedUser, timestamp.toString(), message, signature};
    }

    /**
     * @return CSV formatted String representation of a SystemLogEntry
     * @throws IOException
     */
    public String toCSV() throws IOException {
        return CSVUtils.makeRecord(logType, ip, affectedUser, timestamp, message, signature);
    }

    /**
     * @return the hashcode of the concatenation of the fields as strings
     */
    public int hashCode() {
        return (logType.toString() + ip + affectedUser + timestamp.toString() + message + signature).hashCode();
    }

    /**
     * @param obj
     * @return true if the objects contain the same information and false otherwise
     */
    public boolean equals(Object obj) {
        if (obj instanceof SystemLogEntry) {
            SystemLogEntry other = (SystemLogEntry) obj;
            return (logType.equals(other.logType) &&
                    ip.equals(other.ip) &&
                    affectedUser.equals(other.affectedUser) &&
                    timestamp.equals(other.timestamp) &&
                    message.equals(other.message) &&
                    signature.equals(other.signature)
            );
        } else {
            return false;
        }
    }
}
