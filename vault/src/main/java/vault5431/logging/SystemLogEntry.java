package vault5431.logging;

import org.apache.commons.csv.CSVRecord;
import vault5431.users.User;

import java.io.IOException;
import java.time.LocalDateTime;

/**
 * Represents a system log entry for use by the system admins to check
 * for suspicious activity.
 */
public final class SystemLogEntry extends LogEntry {

    public SystemLogEntry(LogType logType, String ip, User affectedUser,
                          LocalDateTime timestamp, String message) {
        this(logType, ip, affectedUser.getShortHash(), timestamp, message);
    }

    public SystemLogEntry(LogType logType, String ip, String affectedUser,
                          LocalDateTime timestamp, String message) {
        this.logType = logType;
        this.ip = ip;
        this.affectedUser = affectedUser;
        this.timestamp = timestamp;
        this.message = message;
    }

    /**
     * @param entry is a CSV record representation of a SystemLogEntry
     * @return a SystemLogEntry with the relevant information from the CSV string
     */
    public static SystemLogEntry fromCSV(CSVRecord entry) {
        return new SystemLogEntry(
                LogType.fromString(entry.get(0)),
                entry.get(1),
                entry.get(2),
                LocalDateTime.parse(entry.get(3)),
                entry.get(4)
        );
    }

    /**
     * @return CSV formatted String representation of a SystemLogEntry
     * @throws IOException
     */
    public String toCSV() throws IOException {
        return CSVUtils.makeRecord(logType, ip, affectedUser, timestamp, message);
    }

    /**
     * @return the hashcode of the concatenation of the fields as strings
     */
    public int hashCode() {
        return (logType.toString() + ip + affectedUser + timestamp.toString() + message).hashCode();
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
                    message.equals(other.message)
            );
        } else {
            return false;
        }
    }
}
