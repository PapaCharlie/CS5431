package vault5431.users.exceptions;

import vault5431.FatalException;

/**
 * Thrown when Settings cannot be loaded from disk, decrypted and deserialized into a {@link vault5431.users.Settings} instance.
 *
 * @author papacharlie
 */
public class CouldNotLoadSettingsException extends FatalException {

    public CouldNotLoadSettingsException() {
        super();
    }

}
