package vault5431.logging;

import org.apache.commons.csv.CSVRecord;
import vault5431.users.User;

import java.io.IOException;
import java.time.LocalDateTime;

/**
 * Represents a user log entry for use by the users to check
 * for suspicious activity on his vault.
 */
public final class UserLogEntry extends LogEntry {

    public UserLogEntry(LogType logType, String ip, String affectedUser,
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
    public static UserLogEntry fromCSV(CSVRecord entry) {
        return new UserLogEntry(
                LogType.fromString(entry.get(0)),
                entry.get(1),
                entry.get(2),
                LocalDateTime.parse(entry.get(3)),
                entry.get(4)
        );
    }

    /**
     * @return a String[] representation of the UserLogEntry
     */
    @Override
    public String toString() {
        return "[" + logType + "]" + " " + ip +
                " " + affectedUser + " " + timestamp +
                " " + message + " ";
    }

    /**
     * @return CSV formatted String representation of a UserLogEntry
     * @throws IOException
     */
    public String[] asArray() {
        return new String[]{logType.toString(), ip, timestamp.toString(), message};
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
        if (obj instanceof UserLogEntry) {
            UserLogEntry other = (UserLogEntry) obj;
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