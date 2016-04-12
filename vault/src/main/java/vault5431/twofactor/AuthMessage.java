package vault5431.twofactor;

import java.security.SecureRandom;

/**
 * Created by cyj on 4/8/16.
 */
public class AuthMessage {
    private static final SecureRandom random = new SecureRandom();

    protected int authCode;

    public AuthMessage() {
        authCode = random.nextInt(1000000);
    }

    @Override
    public String toString() {
        return "Please enter the following code: " + authCode;
    }

}
