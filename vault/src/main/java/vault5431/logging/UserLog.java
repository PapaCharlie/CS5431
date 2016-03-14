package vault5431.logging;

import java.time.LocalDateTime;

/**
 * Created by CYJ on 3/14/16.
 */
public class UserLog implements  AbstractLog{
    private String logType;
    private String ip;
    private String affectedUser;
    private String timestamp;
    private String message;
    private String signature;

    public UserLog(LogType logType, String ip, String affectedUser,
                   LocalDateTime timestamp, String message, String signature) {
        this.logType = logType.toString();
        this.ip = ip;
        this.affectedUser = affectedUser;
        this.timestamp = timestamp.toString();
        this.message = message;
        this.signature = signature;
    }

    public boolean checkSignature(String signature) {
        return signature.equals(this.signature);
    }

    public String toString() {
        StringBuilder logString = new StringBuilder();
        return logString.append(logType).append(" ").append(ip)
                .append(" ").append(affectedUser).append(" ").append(timestamp)
                .append(" ").append(message).append(" ").toString();
    }
}
