package vault5431.auth;

import java.security.SecureRandom;

/**
 * Class providing random number generation and presentation for 2FA.
 *
 * @author cyj
 */
final class AuthMessage {
    private static final SecureRandom random = new SecureRandom();
    public final int authCode;

    /**
     * Create a new AuthMessage instance with a random, 6 digit number.
     */
    public AuthMessage() {
        int code = random.nextInt(10);
        for (int i = 0; i < 5; i++) {
            code *= 10;
            code += random.nextInt(10);
        }
        authCode = code;
    }

    public String toString() {
        return "Please enter the following authentication code: " + String.format("%06d", authCode);
    }

}
