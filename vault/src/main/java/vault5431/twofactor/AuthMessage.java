package vault5431.twofactor;

import java.security.SecureRandom;

/**
 * Created by cyj on 4/8/16.
 */
public class AuthMessage {
    private static final SecureRandom random = new SecureRandom();
    private static final String[] digits = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9",};
    public int authCode;

    public AuthMessage() {
        StringBuilder authCodeString = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            authCodeString.append(digits[random.nextInt(digits.length)]);
            System.out.println(authCodeString.toString());
        }

        authCode = Integer.parseInt(authCodeString.toString());
    }

    @Override
    public String toString() {
        return "Please enter the following authentication code: " + String.format("%06d", authCode);
    }

}
