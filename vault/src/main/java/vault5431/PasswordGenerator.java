package vault5431;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.HashMap;

/**
 * The server side implementation of the password generator. The client has its own version.
 *
 * @author papacharlie
 */
public class PasswordGenerator {

    private static final SecureRandom random = new SecureRandom();

    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";

    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    private static final String NUMBERS = "0123456789";

    private static final String SYMBOLS = "!@#$%^&*()-_+={}[]<>?";

    private static final HashMap<String, String> PRECEDENCE_MAP = new HashMap<>(3372);
    private static final String[] SYLLABLES;

    static {
        // Read the adjacency list from the resource directory.
        try (BufferedReader br = new BufferedReader(new InputStreamReader(PasswordGenerator.class.getResourceAsStream("/adjacency.json")))) {
            String line;
            while ((line = br.readLine()) != null) {
                JSONObject dict = new JSONObject(line);
                for (String key : dict.keySet()) {
                    PRECEDENCE_MAP.put(key, dict.getString(key));
                }
            }
            SYLLABLES = PRECEDENCE_MAP.keySet().toArray(new String[PRECEDENCE_MAP.keySet().size()]);
        } catch (IOException err) {
            System.err.println("Could not load adjacency list for pronounceable passwords!");
            throw new RuntimeException(err);
        }
    }

    /**
     * Picks a random character from the string.
     *
     * @param s the string from which to pick the random character
     * @return The character.
     * @throws IllegalArgumentException If string is empty.
     */
    private static String randomChar(String s) {
        return Character.toString(s.charAt(random.nextInt(s.length())));
    }

    /**
     * Generates a pronounceable password. Based on english pronunciations. See "adjacency.json" for the map that maps
     * three letter strings to characters that may follow them. In other words, if the pair "thr" -> "oeai" is in the
     * map, it means that o, e, a and i may follow thr. To create the password, randomly pick the first three letters
     * from the map's keys. Then, pick a letter from the value, append it to the last two letters of the key to form a
     * new three letter key. Look up this new key in the map to find the next letter, so on an so forth. The map read
     * from "adjacency.json" has the property that any string created by taking the last two characters of a key and
     * appending any character from the key's value always creates a key that is contained in the map. In other words,
     * one can generate infinitely many passwords from this. On the other hand, because each mapping was created by only
     * looking at 4 letters at any given time, rather than the whole word, the odds of actually generating a real
     * english word are in fact very low.
     * <p>
     * Password space analysis:
     * There are 95 printable characters in the ASCII alphabet. Therefore the best password space (i.e. largest
     * number of possible passwords for a given password length) is the space of passwords that are random strings
     * of those 95 characters. We can use n^95 as the benchmark for comparing password spaces, where n is the
     * password length.
     * <p>
     * By generating every possible pronounceable password of a given length using this method, we can fit an
     * exponential curve to then estimate the number of possible passwords of a given length.
     * The best exponential fit is 15.94 e^(1.595 n). As a point of reference, the optimal password space for
     * 6 letter passwords contains about as many passwords as the 15 letter pronounceable password space. The
     * 8 letter optimal password space contains about as many passwords as the 21 letter pronounceable password
     * space.
     * <p>
     * Obviously, the pronounceable password space is much smaller than the optimal password space, but not
     * incredibly so. Additionally, if the passwords are truly pronounceable, making them longer should be much
     * easier. Finally, in practice, a pronounceable is only weaker than an optimal password of the same length
     * if and only if the attacker knows that the password is indeed pronounceable.
     *
     * @param length length of the password to generate
     * @param lower  whether to use lowercase letters
     * @param upper  whether to use uppercase letters
     * @return The pronounceable password.
     * @throws IllegalArgumentException If the desired length is smaller than 12, or if both {@code lower} and
     *                                  {@code upper} are false.
     */
    private static String generatePronounceablePassword(int length, boolean lower, boolean upper) throws IllegalArgumentException {
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
                    throw new RuntimeException("adjacency.json has led to an impossible password!");
                }
            }
            return password.toString();
        } else {
            throw new IllegalArgumentException("Pronounceable passwords must be at least 12 characters in length.");
        }
    }

    /**
     * Generate a random password from the desired charset.
     *
     * @param length        length of the password to generate
     * @param lower         whether to use lowercase letters
     * @param upper         whether to use uppercase letters
     * @param numbers       whether to use numbers
     * @param symbols       whether to use symbols
     * @param pronounceable whether the password should be pronounceable
     * @return The randomly generated password.
     * @throws IllegalArgumentException If all the charsets are set to false, or the password length is not between
     *                                  6 and 100.
     */
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
            throw new IllegalArgumentException("The password length must be between 6 and 100");
        }
    }

    public static String generatePassword(int length) throws IllegalArgumentException {
        return generatePassword(length, true, true, true, true, false);
    }

    public static String generatePassword() throws IllegalArgumentException {
        return generatePassword(16, true, true, true, true, false);
    }

}