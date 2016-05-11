package vault5431.logging;

import sun.text.resources.ro.CollationData_ro;

/**
 * An enum of types that a log can be.
 */
public enum LogType {
    INFO, DEBUG, WARNING, ERROR;

    public enum Colors {
        RED, YELLOW, GREEN, WHITE, RESET;

        public String toString() {
            switch (this) {
                case RED:
                    return "\u001B[31m";
                case GREEN:
                    return "\u001B[32m";
                case YELLOW:
                    return "\u001B[33m";
                case WHITE:
                    return "\u001B[37m";
                default:
                    return "\u001B[0m";
            }
        }

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

    /**
     * @return String form of the LogType enum
     */
    @Override
    public String toString() {
        switch (this) {
            case ERROR:
                return "ERROR";
            case WARNING:
                return "WARNING";
            case INFO:
                return "INFO";
            case DEBUG:
                return "DEBUG";
            default:
                return "";
        }
    }

    public String toColorString() {
        switch (this) {
            case ERROR:
                return String.format("[%s%7s%s]", Colors.RED, "ERROR", Colors.RESET);
            case WARNING:
                return String.format("[%s%7s%s]", Colors.YELLOW, "WARNING", Colors.RESET);
            case INFO:
                return String.format("[%s%7s%s]", Colors.GREEN, "INFO", Colors.RESET);
            case DEBUG:
                return String.format("[%s%7s%s]", Colors.WHITE, "DEBUG", Colors.RESET);
            default:
                return "";
        }
    }

}
