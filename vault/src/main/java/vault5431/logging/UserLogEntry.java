package vault5431.logging;

import org.apache.commons.csv.CSVRecord;

import java.io.IOException;
import java.time.LocalDateTime;

/**
 * Created by CYJ on 3/14/16.
 */
public class UserLogEntry implements LogEntry {
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

    public boolean checkSignature(String signature) {
        return signature.equals(this.signature);
    }

    @Override
    public String toString() {
        StringBuilder logString = new StringBuilder();
        return logString.append(logType).append(" ").append(ip)
                .append(" ").append(affectedUser).append(" ").append(timestamp)
                .append(" ").append(message).append(" ").toString();
    }

    public String[] asArray() {
        return new String[]{logType.toString(), ip, affectedUser, timestamp.toString(), message, signature};
    }

    public String toCSV() throws IOException {
        return CSVUtils.makeRecord(logType, ip, affectedUser, timestamp, message, signature);
    }

    public static UserLogEntry fromCSV(CSVRecord entry) {
        return new UserLogEntry(LogType.fromString(entry.get(0)), entry.get(1), entry.get(2), LocalDateTime.parse(entry.get(3)), entry.get(4), entry.get(5));
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