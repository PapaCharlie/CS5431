package vault5431;

import java.util.UUID;
import org.apache.commons.validator.routines.EmailValidator;

/**
 * User class.
 * TODO: Provide enc and dec methods
 */
public class User {

    private String firstName;
    private String lastName;
    private String email;
    private UUID userId;

    User(String firstName, String lastName, String email) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        userId = UUID.randomUUID();
    }

}
