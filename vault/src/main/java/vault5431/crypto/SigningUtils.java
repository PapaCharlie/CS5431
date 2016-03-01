package vault5431.crypto;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by papacharlie on 2/29/16.
 */
public class SigningUtils {

    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

    public static Base64String getSignature(Base64String content, SecretKey key) throws InvalidKeyException {
        try {
            Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
            mac.init(key);
            byte[] rawHmac = mac.doFinal(content.getBytes());
            return new Base64String(rawHmac);
        } catch (NoSuchAlgorithmException e) {
            System.exit(1);
            return null;
        }
    }


}
