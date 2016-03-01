package vault5431.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by papacharlie on 3/1/16.
 */
public class HashUtils {

    private static String HASH_ALG = "SHA-512";

    public static Base64String hash(Base64String data) {
        try {
            MessageDigest hasher = MessageDigest.getInstance(HASH_ALG);
            hasher.update(data.getBytes());
            return new Base64String(hasher.digest());
        } catch (NoSuchAlgorithmException e) {
            System.err.println(HASH_ALG + " hashing algorithm does not exist!");
            System.exit(1);
            return Base64String.empty();
        }
    }

}
