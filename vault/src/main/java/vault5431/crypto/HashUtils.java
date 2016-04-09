package vault5431.crypto;

import vault5431.io.Base64String;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Hashing utilities
 */
public class HashUtils {

    private static Base64String hash(byte[] data, String alg, int n) {
        Base64String hashString = null;
        try {
            MessageDigest cipher = MessageDigest.getInstance(alg, "BC");
            cipher.update(data);
            byte[] hash = cipher.digest();
            while (n - 1 > 0) {
                cipher.update(hash);
                hash = cipher.digest();
                n--;
            }
            hashString = new Base64String(hash);
        } catch (NoSuchProviderException | NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return hashString;
    }

    public static Base64String hash512(byte[] data) {
        return hash(data, "SHA-512", 1);
    }

    public static Base64String hash512(byte[] data, int n) {
        return hash(data, "SHA-512", n);
    }

    public static Base64String hash256(byte[] data) {
        return hash(data, "SHA-256", 1);
    }

    public static Base64String hash256(byte[] data, int n) {
        return hash(data, "SHA-256", n);
    }
}
