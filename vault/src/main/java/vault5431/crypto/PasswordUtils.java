package vault5431.crypto;

import org.bouncycastle.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOError;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * Created by papacharlie on 2016-03-12.
 */
public class PasswordUtils {

    public static final int ITERATIONS = 1000;
    public static final int KEY_SIZE = 256;

    private static final SecureRandom random = new SecureRandom();

    private static byte[] generateSalt() {
        byte[] salt = new byte[KEY_SIZE / 8];
        random.nextBytes(salt);
        return salt;
    }

    private static String HASH_ALG = "PBKDF2WithHmacSHA512";

    public static Base64String hashPassword(String password) {
        Base64String hashedPassword = null;
        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(HASH_ALG);
            byte[] salt = generateSalt();
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_SIZE);
            SecretKey key = secretKeyFactory.generateSecret(spec);
            hashedPassword = new Base64String(Arrays.concatenate(salt, key.getEncoded()));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return hashedPassword;
    }

    public static boolean verifyHashedPassword(Base64String hashedPassword, String password) throws InvalidKeySpecException {
        boolean result = false;
        try {
            byte[] decoded = hashedPassword.decodeBytes();
            byte[] salt = Arrays.copyOfRange(decoded, 0, KEY_SIZE / 8);
            byte[] hash = Arrays.copyOfRange(decoded, KEY_SIZE / 8, decoded.length);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(HASH_ALG);
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_SIZE);
            SecretKey key = secretKeyFactory.generateSecret(spec);
            result = Arrays.areEqual(hash, key.getEncoded());
        } catch (NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return result;
    }

    public static void savePassword(String passwordFile, String password) throws IOError, IOException {
        hashPassword(password).saveToFile(passwordFile);
    }

    public static boolean verifyPasswordInFile(String passwordFile, String password) throws IOError, IOException, InvalidKeySpecException {
        return verifyHashedPassword(Base64String.loadFromFile(passwordFile), password);
    }

}
