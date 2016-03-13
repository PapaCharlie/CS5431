package vault5431.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by papacharlie on 3/1/16.
 */
public class HashUtils {

    private static Base64String hash(Base64String data, String alg) {
        Base64String hash = null;
        try {
            MessageDigest hasher = MessageDigest.getInstance(alg);
            hasher.update(data.getB64Bytes());
            hash = new Base64String(hasher.digest());
        } catch (NoSuchAlgorithmException e) {
            System.err.println(alg + " hashing algorithm does not exist!");
            System.exit(1);
        }
        return hash;
    }

    public static Base64String hash512(Base64String data) {
        return hash(data, "SHA-512");
    }

    public static Base64String hash256(Base64String data) {
        return hash(data, "SHA-256");
    }

    public static Base64String hash128(Base64String data) {
        return hash(data, "SHA-1");
    }

}
