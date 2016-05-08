package vault5431.users.exceptions;

/**
 * Thrown when the a log entry cannot be deserialized.
 *
 * @author papacharlie
 */
public class CorruptedLogException extends Exception {

    public CorruptedLogException() {
        super();
    }

    public CorruptedLogException(Throwable cause) {
        super(cause);
    }
}
