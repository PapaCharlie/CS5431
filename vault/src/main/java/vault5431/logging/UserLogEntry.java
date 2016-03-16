package vault5431.logging;

import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import vault5431.users.User;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Created by CYJ on 3/14/16.
 */
public class UserLogEntry extends LogEntry {

    private LogType logType;
    private String ip;
    private String affectedUser;
    private LocalDateTime timestamp;
    private String message;
    private String signature;

    public UserLogEntry(LogType logType, String ip, String affectedUser,
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

    public String[] asArray() {
        return new String[]{logType.toString(), ip, timestamp.toString(), message};
    }

    public String toCSV() throws IOException {
        return CSVUtils.makeRecord(logType, ip, affectedUser, timestamp, message, signature);
    }

    public static UserLogEntry fromCSV(CSVRecord entry) {
        return new UserLogEntry(LogType.fromString(entry.get(0)), entry.get(1), entry.get(2), LocalDateTime.parse(entry.get(3)), entry.get(4), entry.get(5));
    }

    public static UserLogEntry[] fromCSV(CSVParser entries) throws IOException {
        List<CSVRecord> records = entries.getRecords();
        UserLogEntry[] parsedEntries = new UserLogEntry[records.size()];
        for (int i = 0; i < parsedEntries.length; i++) {
            CSVRecord entry = records.get(i);
            parsedEntries[i] = new UserLogEntry(LogType.fromString(entry.get(0)), entry.get(1), entry.get(2), LocalDateTime.parse(entry.get(3)), entry.get(4), entry.get(5));
        }
        return parsedEntries;
    }


    public boolean equals(Object object) {
        if (object instanceof UserLogEntry) {
            UserLogEntry other = (UserLogEntry) object;
            return (this.logType.equals(other.logType) &&
                    this.ip.equals(other.ip) &&
                    this.affectedUser.equals(other.affectedUser) &&
                    this.timestamp.equals(other.timestamp) &&
                    this.message.equals(other.message) &&
                    this.signature.equals(signature)
            );
        } else {
            return false;
        }
    }

}