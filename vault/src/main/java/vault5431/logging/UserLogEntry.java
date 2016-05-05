package vault5431.logging;

import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import vault5431.users.User;

import vault5431.crypto.SigningUtils;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Represents a user log entry for use by the users to check
 * for suspicious activity on his vault.
 */
public class UserLogEntry extends LogEntry {

    public UserLogEntry(LogType logType, String ip, User affectedUser,
                        LocalDateTime timestamp, String message) {
        this(logType, ip, affectedUser.getShortHash(), timestamp, message);

    }

    public UserLogEntry(LogType logType, String ip, String affectedUser,
                        LocalDateTime timestamp, String message) {
        this.logType = logType;
        this.ip = ip;
        this.affectedUser = affectedUser;
        this.timestamp = timestamp;
        this.message = message;
    }

    private UserLogEntry(LogType logType, String ip, String affectedUser,
                        LocalDateTime timestamp, String message, String signature) {
        this.logType = logType;
        this.ip = ip;
        this.affectedUser = affectedUser;
        this.timestamp = timestamp;
        this.message = message;
        this.signature = signature;
    }

    public UserLogEntry(LogType logType, String ip, User affectedUser,
                        LocalDateTime timestamp, String message, String signature) {
        this(logType, ip, affectedUser.getShortHash(), timestamp, message, signature);
    }

    /**
     * @param entry is a CSV record representation of a SystemLogEntry
     * @return a SystemLogEntry with the relevant information from the CSV string
     */
    public static UserLogEntry fromCSV(CSVRecord entry) {
        return new UserLogEntry(LogType.fromString(entry.get(0)), entry.get(1), entry.get(2), LocalDateTime.parse(entry.get(3)), entry.get(4), entry.get(5));
    }

    /**
     * @param entries is a CSVParser containing multiple CSVRecords, each of which represents
     *                a SystemLogEntry
     * @return Array of SystemLogEntries derived from the CSVParser
     * @throws IOException
     */
    public static UserLogEntry[] fromCSV(CSVParser entries) throws IOException {
        List<CSVRecord> records = entries.getRecords();
        UserLogEntry[] parsedEntries = new UserLogEntry[records.size()];
        for (int i = 0; i < parsedEntries.length; i++) {
            CSVRecord entry = records.get(i);
            parsedEntries[i] = new UserLogEntry(LogType.fromString(entry.get(0)), entry.get(1), entry.get(2), LocalDateTime.parse(entry.get(3)), entry.get(4), entry.get(5));
        }
        return parsedEntries;
    }

    /**
     * Signs the UserLog based on its contents.
     */
    public void signUserLog(SecretKey sigKey) {
        String stringContent = logType + ip + affectedUser + message;
        byte[] byteContent = stringContent.getBytes();
        signature = SigningUtils.sign(byteContent, sigKey).toString();
    }

    /**
     * Checks the signature of a log to ensure that the log entry is written by the
     * system and not an outsider user/attacker
     *
     * @param signature
     * @return true if there if signatures match, false otherwise.
     */
    public boolean checkSignature(UserLogEntry unverifiedEntry) {
        return unverifiedEntry.signature.equals(this.signature);
    }

    /**
     * @return a String[] representation of the UserLogEntry
     */
    @Override
    public String toString() {
        StringBuilder logString = new StringBuilder();
        return logString.append("[").append(logType).append("]").append(" ").append(ip)
                .append(" ").append(affectedUser).append(" ").append(timestamp)
                .append(" ").append(message).append(" ").toString();
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
        if (obj instanceof UserLogEntry) {
            UserLogEntry other = (UserLogEntry) obj;
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