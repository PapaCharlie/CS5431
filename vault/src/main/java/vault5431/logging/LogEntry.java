package vault5431.logging;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * An abstract class containing the basic fields all logs in our system will have.
 * All types of LogEntry will extend this class.
 */
public abstract class LogEntry {

    LogType logType; //INFO, DEBUG, WARNING, ERROR
    String ip; //IP from which log entry was made
    String affectedUser; //Whose log the entry was written in
    LocalDateTime timestamp; //When the log was generated
    String message; //The message of the log

    public abstract String toCSV() throws IOException;

    public String toString() {
        return String.format("%s %15s %10s %s %s", logType.toColorString(), ip, affectedUser, timestamp, message);
    }

    /**
     * @return a Map representation of a SystemLogEntry
     */
    public Map<String, String> toMap() {
        Map<String, String> hash = new HashMap<>(6);
        hash.put("logType", logType.toString());
        hash.put("ip", ip);
        hash.put("affectedUser", affectedUser);
        hash.put("timestamp", timestamp.toString());
        hash.put("message", message);
        return hash;
    }
}
