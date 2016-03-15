package vault5431;

import org.apache.commons.validator.routines.EmailValidator;

/**
 * Basic email and username verification methods
 */
public class Utils {

    public static boolean verifyEmail(String email) {
        return EmailValidator.getInstance().isValid(email);
    }

    public static boolean verifyUsername(String username) {
        // TODO
        return false;
    }

}
