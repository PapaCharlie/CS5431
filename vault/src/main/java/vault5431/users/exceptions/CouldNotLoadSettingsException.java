package vault5431.users.exceptions;

/**
 * Thrown when Settings cannot be loaded from disk, decrypted and deserialized into a {@link vault5431.users.Settings} instance.
 *
 * @author papacharlie
 */
public class CouldNotLoadSettingsException extends Exception {

    public CouldNotLoadSettingsException() {
        super();
    }

}
