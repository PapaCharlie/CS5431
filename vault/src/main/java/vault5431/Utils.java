package vault5431;

import org.apache.commons.validator.routines.EmailValidator;

/**
 * Created by papacharlie on 2/23/16.
 */
public class Utils {

    public static boolean verifyEmail(String email) {
        return EmailValidator.getInstance().isValid(email);
    }

    public static String extractUsername(String email) {
        if (verifyEmail(email)) {
            return email.split("@")[0];
        } else {
            throw new IllegalArgumentException("Email is invlid!");
        }
    }

}
