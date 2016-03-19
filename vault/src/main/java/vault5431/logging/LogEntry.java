package vault5431.logging;

import java.io.IOException;
import java.time.LocalDateTime;

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
    String signature; //Signature of the creator of the log

    public abstract boolean checkSignature(String signature);

    public abstract String toCSV() throws IOException;

    public abstract String toString();

    public abstract String[] asArray();

}
