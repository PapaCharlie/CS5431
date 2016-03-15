package vault5431.crypto;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Signing utilities.
 */
public class SigningUtils {

    private static final String HMAC_SHA256 = "HmacSHA256";

    public static Base64String getSignature(byte[] content, SecretKey key) throws InvalidKeyException {
        Base64String sig = null;
        try {
            Mac cipher = Mac.getInstance(HMAC_SHA256);
            cipher.init(key);
            byte[] mac = cipher.doFinal(content);
            sig = new Base64String(mac);
        } catch (NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return sig;
    }

    public static boolean verifySignature(byte[] content, Base64String signature, SecretKey key) throws InvalidKeyException {
        Base64String newSig = getSignature(content, key);
        return newSig.equals(signature);
    }


}
