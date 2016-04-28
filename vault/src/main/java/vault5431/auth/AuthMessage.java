package vault5431.auth;

import java.security.SecureRandom;

/**
 * Created by cyj on 4/8/16.
 */
public class AuthMessage {
    private static final SecureRandom random = new SecureRandom();
    public final int authCode;

    public AuthMessage() {
        int code = random.nextInt(10);
        for (int i = 0; i < 5; i++) {
            code *= 10;
            code += random.nextInt(10);
        }
        authCode = code;
    }

    @Override
    public String toString() {
        return "Please enter the following authentication code: " + String.format("%06d", authCode);
    }

}
