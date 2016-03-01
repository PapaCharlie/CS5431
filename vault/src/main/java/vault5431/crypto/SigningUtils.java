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
        try {
            Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
            mac.init(key);
            byte[] rawHmac = mac.doFinal(content.getBytes());
            return new Base64String(rawHmac);
        } catch (NoSuchAlgorithmException e) {
            System.err.println(HMAC_SHA1_ALGORITHM + " signing algorithm does not exist!");
            System.exit(1);
            return Base64String.empty();
        }
    }

    public static boolean verifySignature(Base64String content, Base64String signature, SecretKey key) throws InvalidKeyException {
        try {
            Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
            mac.init(key);
            return Arrays.equals(mac.doFinal(content.getBytes()), signature.getBytes());
        } catch (NoSuchAlgorithmException e) {
            System.err.println(HMAC_SHA1_ALGORITHM + " signing algorithm does not exist!");
            System.exit(1);
            return false;
        }
    }


}
