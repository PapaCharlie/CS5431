package vault5431.logging;

/**
 * Created by CYJ on 3/14/16.
 */
public enum LogType {
    INFO, DEBUG, WARNING, ERROR;

    @Override
    public String toString() {
        switch (this) {
            case INFO:
                return "INFO";
            case DEBUG:
                return "DEBUG";
            case WARNING:
                return "WARNING";
            case ERROR:
                return "ERROR";
        }
        return super.toString();
    }

    public static LogType fromString(String t) {
        switch (t) {
            case "INFO":
                return INFO;
            case "DEBUG":
                return DEBUG;
            case "WARNING":
                return WARNING;
            case "ERROR":
                return ERROR;
            default:
                return null;
        }

    }

}
