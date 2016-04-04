package vault5431.crypto;

import vault5431.Vault;
import vault5431.io.Base64String;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

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

    public static Base64String signPublicKey(PublicKey publicKey) {
        Base64String sig = null;
        try {
            sig = getSignature(publicKey.getEncoded(), Vault.adminSigningKey);
        } catch (InvalidKeyException err) {
            err.printStackTrace();
            System.err.println("adminSigningKey is invalid!! Panicking.");
            System.exit(1);
        }
        return sig;
    }

    public static boolean verifyPublicKeySignature(PublicKey publicKey, Base64String signature) {
        return signPublicKey(publicKey).equals(signature);
    }


}
