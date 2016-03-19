package vault5431.logging;

/**
 * An enum of types that a log can be.
 */
public enum LogType {
    INFO, DEBUG, WARNING, ERROR;

    /**
     * @return String form of the LogType enum
     */
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

    /**
     * @param t is a String representation of the LogType enum
     * @return The corresponding LogType of the String if there is a match. Otherwise returns null.
     */
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
