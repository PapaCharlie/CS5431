package vault5431.crypto;

import org.bouncycastle.util.Arrays;
import vault5431.io.Base64String;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * Password hashing and verification utilities.
 *
 * @author papacharlie
 */
public class PasswordUtils {

    private static final int ITERATIONS = 1000;
    private static final int KEY_SIZE = 256;
    private static final int SALT_SIZE = KEY_SIZE / 8;

    private static final SecureRandom random = new SecureRandom();
    private static final String HASH_ALG = "PBKDF2WithHmacSHA512";

    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_SIZE];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Derive an AES-256 key from a password using PBKDF2.
     *
     * @param password the password from which to derive the key
     * @param salt     the salt to use
     * @return The AES secret key derived after {@link #ITERATIONS} iterations.
     */
    public static SecretKey deriveKey(char[] password, byte[] salt) {
        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(HASH_ALG);
            PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_SIZE);
            return SymmetricUtils.keyFromBytes(secretKeyFactory.generateSecret(spec).getEncoded());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException err) {
            err.printStackTrace();
            throw new RuntimeException(err);
        }
    }

    public static void hashAndSavePassword(File passwordFile, Base64String password) throws IOException {
        hashAndSavePassword(passwordFile, password.decodeString());
    }

    /**
     * Generate a random salt and derive a SecretKey using {@link #deriveKey(char[], byte[])}. The secret key is saved
     * to disk, with the first {@link #SALT_SIZE} bytes being the salt, and the remaining bytes the hashed password.
     *
     * @param passwordFile file to write the salt and password to.
     * @param password     password to hash.
     * @throws IOException If the file cannot be written to.
     */
    public static void hashAndSavePassword(File passwordFile, String password) throws IOException {
        byte[] salt = generateSalt();
        new Base64String(Arrays.concatenate(salt, deriveKey(password.toCharArray(), salt).getEncoded())).saveToFile(passwordFile);
    }

    public static boolean verifyPasswordInFile(File passwordFile, Base64String password) throws IOException {
        return verifyPasswordInFile(passwordFile, password.decodeString());
    }

    /**
     * Verify that a previous call to {@link #hashAndSavePassword} saved the same password as the one that is being
     * currently given.
     *
     * @param passwordFile file in which to find the saved password
     * @param password     password to check
     * @return Whether the given password was indeed the same as the password that was saved.
     * @throws IOException If the file cannot be read.
     */
    public static boolean verifyPasswordInFile(File passwordFile, String password) throws IOException {
        Base64String hashedPassword = Base64String.loadFromFile(passwordFile)[0];
        byte[] decoded = hashedPassword.decodeBytes();
        byte[] salt = Arrays.copyOfRange(decoded, 0, KEY_SIZE / 8);
        byte[] hash = Arrays.copyOfRange(decoded, KEY_SIZE / 8, decoded.length);
        SecretKey key = deriveKey(password.toCharArray(), salt);
        return Arrays.areEqual(hash, key.getEncoded());
    }

}
