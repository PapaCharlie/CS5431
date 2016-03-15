package vault5431.logging;

import org.apache.commons.csv.CSVRecord;

import java.io.IOException;
import java.time.LocalDateTime;

/**
 * Created by CYJ on 3/14/16.
 */
public class SystemLogEntry implements LogEntry {
    private LogType logType;
    private String ip;
    private String affectedUser;
    private LocalDateTime timestamp;
    private String message;
    private String signature;

    public SystemLogEntry(LogType logType, String ip, String affectedUser,
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
        return logString.append(logType).append(" ").append(affectedUser)
                .append(" ").append(timestamp).append(" ")
                .append(message).append(" ").toString();
    }

    public String[] asArray() {
        String[] csvArray = {logType.toString(), affectedUser, timestamp.toString(), message, signature};
        return csvArray;
    }

    public String toCSV() throws IOException {
        return CSVUtils.makeRecord(logType, affectedUser, timestamp, message, signature);
    }

    public static SystemLogEntry fromCSV(CSVRecord entry) {
        return new SystemLogEntry(LogType.fromString(entry.get(0)), entry.get(1), entry.get(2),LocalDateTime.parse(entry.get(3)), entry.get(4), entry.get(5));
    }

    public boolean equals(Object object) {
        if (object instanceof SystemLogEntry) {
            SystemLogEntry other = (SystemLogEntry) object;
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
