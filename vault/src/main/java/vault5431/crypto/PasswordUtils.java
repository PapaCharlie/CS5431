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
 * Password hashing and verification utilities
 */
public class PasswordUtils {

    public static final int ITERATIONS = 1000;
    public static final int KEY_SIZE = 256;
    public static final int SALT_SIZE = KEY_SIZE / 8;

    private static final SecureRandom random = new SecureRandom();
    private static final String HASH_ALG = "PBKDF2WithHmacSHA512";

    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_SIZE];
        random.nextBytes(salt);
        return salt;
    }

    public static SecretKey deriveKey(String password, byte[] salt) {
        SecretKey key = null;
        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(HASH_ALG);
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_SIZE);
            key = SymmetricUtils.keyFromBytes(secretKeyFactory.generateSecret(spec).getEncoded());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return key;
    }

    public static Base64String hashPassword(String password) {
        return HashUtils.hash256(password.getBytes(), 2);
    }

    private static boolean verifyHashedPassword(Base64String hashedPassword, String password) {
        byte[] decoded = hashedPassword.decodeBytes();
        byte[] salt = Arrays.copyOfRange(decoded, 0, KEY_SIZE / 8);
        byte[] hash = Arrays.copyOfRange(decoded, KEY_SIZE / 8, decoded.length);
        SecretKey key = deriveKey(password, salt);
        return Arrays.areEqual(hash, key.getEncoded());
    }

    public static void savePassword(File passwordFile, Base64String password) throws IOException {
        savePassword(passwordFile, password.decodeString());
    }

    public static void savePassword(File passwordFile, String password) throws IOException {
        byte[] salt = generateSalt();
        new Base64String(Arrays.concatenate(salt, deriveKey(password, salt).getEncoded())).saveToFile(passwordFile);
    }

    public static boolean verifyPasswordInFile(File passwordFile, Base64String password) throws IOException {
        return verifyPasswordInFile(passwordFile, password.decodeString());
    }

    public static boolean verifyPasswordInFile(File passwordFile, String password) throws IOException {
        return verifyHashedPassword(Base64String.loadFromFile(passwordFile)[0], password);
    }

}
