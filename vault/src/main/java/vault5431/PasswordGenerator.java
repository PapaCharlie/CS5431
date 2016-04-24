package vault5431;

import java.security.SecureRandom;

/**
 * Basic password generator class
 * TODO: Pronounceable passwords?
 */
public class PasswordGenerator {
    private static final SecureRandom random = new SecureRandom();

    private static final String LOWERCASE = new String(new char[]{
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
    });

    private static final String UPPERCASE = new String(new char[]{
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
    });

    private static final String NUMBERS = new String(new char[]{
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
    });

    private static final String SYMBOLS = new String(new char[]{
            '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=', '{', '}', '[', ']', '<', '>', '?'
    });


    public static String generatePassword(int length, boolean lower, boolean upper, boolean numbers, boolean symbols) throws IllegalArgumentException {
        String charset = "";
        if (!(lower || upper || numbers || symbols)) {
            throw new IllegalArgumentException("At least one charset is required.");
        }
        if (lower) {
            charset += LOWERCASE;
        }
        if (upper) {
            charset += UPPERCASE;
        }
        if (numbers) {
            charset += NUMBERS;
        }
        if (symbols) {
            charset += SYMBOLS;
        }
        StringBuilder password = new StringBuilder();
        for (int i = 0; i < length; i++) {
            password.append(charset.charAt(random.nextInt(charset.length())));
        }
        return password.toString();
    }

    public static String generatePassword(int length) {
        return generatePassword(length, true, true, true, true);
    }

}