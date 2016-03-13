package vault5431.crypto;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Signing utilities.
 */
public class SigningUtils {

    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA256";

    public static Base64String getSignature(Base64String content, SecretKey key) throws InvalidKeyException {
        Base64String sig = null;
        try {
            Mac cipher = Mac.getInstance(HMAC_SHA1_ALGORITHM);
            cipher.init(key);
            byte[] mac = cipher.doFinal(content.getB64Bytes());
            sig = new Base64String(mac);
        } catch (NoSuchAlgorithmException e) {
            System.err.println(HMAC_SHA1_ALGORITHM + " signing algorithm does not exist!");
            System.exit(1);
        }
        return sig;
    }

    public static boolean verifySignature(Base64String content, Base64String signature, SecretKey key) throws InvalidKeyException {
        boolean result = false;
        try {
            Mac cipher = Mac.getInstance(HMAC_SHA1_ALGORITHM);
            cipher.init(key);
            result = Arrays.equals(cipher.doFinal(content.getB64Bytes()), signature.getB64Bytes());
        } catch (NoSuchAlgorithmException e) {
            System.err.println(HMAC_SHA1_ALGORITHM + " signing algorithm does not exist!");
            System.exit(1);
        }
        return result;
    }


}
