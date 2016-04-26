package vault5431;

import org.json.JSONObject;
import vault5431.io.Base64String;

import java.io.*;
import java.security.SecureRandom;
import java.util.HashMap;

/**
 * Basic password generator class
 * TODO: Pronounceable passwords?
 */
public class PasswordGenerator {
    private static final SecureRandom random = new SecureRandom();

    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";

    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    private static final String NUMBERS = "0123456789";

    private static final String SYMBOLS = "!@#$%^&*()-_+={}[]<>?";

    private static final HashMap<String, String> PRECEDENCE_MAP = new HashMap<>();

    static {
        try (BufferedReader br = new BufferedReader(new InputStreamReader(PasswordGenerator.class.getResourceAsStream("/adjacency.json")))) {
            String line;
            while ((line = br.readLine()) != null) {
                JSONObject dict = new JSONObject(line);
                for (String key : dict.keySet()) {
                    PRECEDENCE_MAP.put(key, dict.getString(key));
                }
            }
        } catch (IOException err) {
            System.err.println("Could not load adjacency list for pronounceable passwords!");
            System.exit(1);
        }
    }

    private static final String[] SYLLABLES = PRECEDENCE_MAP.keySet().toArray(new String[PRECEDENCE_MAP.keySet().size()]);

    private static String randomChar(String s) {
        return Character.toString(s.charAt(random.nextInt(s.length())));
    }

    private static String generatePronounceablePassword(int length, boolean lower, boolean upper) {
        if (!lower && !upper) {
            throw new IllegalArgumentException("At least one charset is required.");
        }
        if (12 <= length && length <= 100) {
            StringBuilder password = new StringBuilder();
            String last = SYLLABLES[random.nextInt(SYLLABLES.length)];
            for (char c : last.toCharArray()) {
                if (lower && upper) {
                    password.append(random.nextBoolean() ? Character.toUpperCase(c) : Character.toLowerCase(c));
                } else {
                    password.append(upper ? Character.toUpperCase(c) : Character.toLowerCase(c));
                }
            }
            while (password.length() < length) {
                if (PRECEDENCE_MAP.containsKey(last)) {
                    String next = randomChar(PRECEDENCE_MAP.get(last));
                    last = last.substring(1) + next;
                    if (lower && upper) {
                        password.append(random.nextBoolean() ? next.toUpperCase() : next.toLowerCase());
                    } else {
                        password.append(upper ? next.toUpperCase() : next.toLowerCase());
                    }
                } else {
                    throw new RuntimeException();
                }
            }
            return password.toString();
        } else {
            throw new IllegalArgumentException("Pronounceable passwords must be at least 12 characters in length.");
        }
    }

    public static String generatePassword(int length, boolean lower, boolean upper, boolean numbers, boolean symbols, boolean pronounceable) throws IllegalArgumentException {
        if (6 <= length && length <= 100) {
            if (pronounceable) {
                return generatePronounceablePassword(length, lower, upper);
            }
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
        } else {
            throw new IllegalArgumentException();
        }
    }

    public static String generatePassword(int length) throws IllegalArgumentException {
        return generatePassword(length, true, true, true, true, false);
    }

}