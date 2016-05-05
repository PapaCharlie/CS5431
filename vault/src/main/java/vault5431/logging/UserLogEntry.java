package vault5431.logging;

import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import vault5431.io.Base64String;
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
                        LocalDateTime timestamp, String message, SecretKey userSigningKey) {
        this(logType, ip, affectedUser.getShortHash(), timestamp, message, userSigningKey);

    }

    public UserLogEntry(LogType logType, String ip, String affectedUser,
                        LocalDateTime timestamp, String message, SecretKey userSigningKey) {
        this.logType = logType;
        this.ip = ip;
        this.affectedUser = affectedUser;
        this.timestamp = timestamp;
        this.message = message;
        this.signature = SigningUtils.sign(toSignatureContent(logType, ip, affectedUser, timestamp, message), userSigningKey);
    }

    private UserLogEntry(LogType logType, String ip, String affectedUser,
                         LocalDateTime timestamp, String message, Base64String signature, SecretKey userSigningKey) {
        this.logType = logType;
        this.ip = ip;
        this.affectedUser = affectedUser;
        this.timestamp = timestamp;
        this.message = message;
        if (!SigningUtils.verify(toSignatureContent(logType, ip, affectedUser, timestamp, message), signature, userSigningKey)) {
            throw new IllegalArgumentException("UserLogEntry signature does not match.");
        }
        this.signature = signature;
    }

    private byte[] toSignatureContent(LogType logType, String ip, String affectedUser, LocalDateTime timestamp, String message) {
        return (logType.toString() + ip + affectedUser + timestamp.toString() + message).getBytes();
    }

    /**
     * @param entry is a CSV record representation of a SystemLogEntry
     * @return a SystemLogEntry with the relevant information from the CSV string
     */
    public static UserLogEntry fromCSV(CSVRecord entry, SecretKey userSigningKey) {
        return new UserLogEntry(
                LogType.fromString(entry.get(0)),
                entry.get(1),
                entry.get(2),
                LocalDateTime.parse(entry.get(3)),
                entry.get(4),
                Base64String.fromBase64(entry.get(5)),
                userSigningKey
        );
    }

    /**
     * @param entries is a CSVParser containing multiple CSVRecords, each of which represents
     *                a SystemLogEntry
     * @return Array of SystemLogEntries derived from the CSVParser
     * @throws IOException
     */
    public static UserLogEntry[] fromCSV(CSVParser entries, SecretKey userSigningKey) throws IOException {
        List<CSVRecord> records = entries.getRecords();
        UserLogEntry[] parsedEntries = new UserLogEntry[records.size()];
        for (int i = 0; i < parsedEntries.length; i++) {
            CSVRecord entry = records.get(i);
            parsedEntries[i] = new UserLogEntry(
                    LogType.fromString(entry.get(0)),
                    entry.get(1),
                    entry.get(2),
                    LocalDateTime.parse(entry.get(3)),
                    entry.get(4),
                    Base64String.fromBase64(entry.get(5)),
                    userSigningKey
            );
        }
        return parsedEntries;
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
        return CSVUtils.makeRecord(logType, ip, affectedUser, timestamp, message, signature.getB64String());
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