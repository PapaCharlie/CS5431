package vault5431.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Created by papacharlie on 3/1/16.
 */
public class HashUtils {

    private static Base64String hash(Base64String data, String alg) {
        Base64String hash = null;
        try {
            MessageDigest hasher = MessageDigest.getInstance(alg, "BC");
            hasher.update(data.getB64Bytes());
            hash = new Base64String(hasher.digest());
        } catch (NoSuchProviderException | NoSuchAlgorithmException err) {
            err.printStackTrace();
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
}
