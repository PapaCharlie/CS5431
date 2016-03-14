package vault5431.logging;

import java.time.LocalDateTime;

/**
 * Created by CYJ on 3/14/16.
 */
public class SystemLog implements AbstractLog {
    private String logType;
    private String affectedUser;
    private String timestamp;
    private String message;
    private String signature;

    public SystemLog(LogType logType, String affectedUser,
                     LocalDateTime timestamp, String message, String signature) {
        this.logType = logType.toString();
        this.affectedUser = affectedUser;
        this.timestamp = timestamp.toString();
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
        String[] csvArray = {logType, affectedUser, timestamp, message, signature};
        return csvArray;
    }

}
