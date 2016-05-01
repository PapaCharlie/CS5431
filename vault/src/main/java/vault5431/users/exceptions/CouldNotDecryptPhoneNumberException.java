package vault5431.users.exceptions;

/**
 * Thrown when a user's phone number cannot be loaded from disk and decrypted.
 *
 * @author papacharlie
 */
public class CouldNotDecryptPhoneNumberException extends Exception {

    public CouldNotDecryptPhoneNumberException() {
        super();
    }

}
