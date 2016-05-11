package vault5431.users.exceptions;

import vault5431.FatalException;

/**
 * Thrown when the a log entry cannot be deserialized.
 *
 * @author papacharlie
 */
public class CorruptedLogException extends FatalException {

    public CorruptedLogException() {
        super();
    }

    public CorruptedLogException(Throwable cause) {
        super(cause);
    }
}
