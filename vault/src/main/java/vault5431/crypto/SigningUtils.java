package vault5431.crypto;

import vault5431.io.Base64String;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Signing utilities. Signing is done with HMAC under SHA256.
 *
 * @author papacharlie
 */
public class SigningUtils {

    private static final String HMAC_SHA256 = "HmacSHA256";

    public static Base64String sign(byte[] content, SecretKey key) {
        try {
            Mac cipher = Mac.getInstance(HMAC_SHA256);
            cipher.init(key);
            byte[] mac = cipher.doFinal(content);
            return new Base64String(mac);
        } catch (NoSuchAlgorithmException err) {
            throw new RuntimeException(err);
        } catch (InvalidKeyException err) {
            System.err.println("Generated a wrong key! Requires immediate action.");
            throw new RuntimeException(err);
        }
    }

    public static boolean verify(byte[] content, Base64String signature, SecretKey key) {
        Base64String newSig = sign(content, key);
        return newSig.equals(signature);
    }

}
