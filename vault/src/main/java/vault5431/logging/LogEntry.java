package vault5431.logging;

import java.io.IOException;
import java.time.LocalDateTime;

/**
 * Created by CYJ on 3/14/16.
 * Placeholder in case our Sys Log and User Log begin to deviate significantly but share
 * common functions.
 */
public abstract class LogEntry {

    private LogType logType;
    private String ip;
    private String affectedUser;
    private LocalDateTime timestamp;
    private String message;
    private String signature;

    public abstract boolean checkSignature(String signature);

    public abstract String toCSV() throws IOException;

    public abstract String toString();

}
