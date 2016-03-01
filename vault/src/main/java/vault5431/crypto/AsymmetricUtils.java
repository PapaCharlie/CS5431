package vault5431.crypto;

import javax.crypto.Cipher;
import java.security.*;

/**
 * Created by papacharlie on 2/29/16.
 */
public class AsymmetricUtils {

    private static String keyPairAlg = "RSA/ECB/PKCS1Padding";

    public static KeyPair generateKeyPair() {
        int keySize = 2048;
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(keySize, new SecureRandom());
            return gen.generateKeyPair();
        } catch (NoSuchAlgorithmException err) {
            return null;
        }
    }

    public static byte[] encrypt(byte[] content, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(keyPairAlg);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(content);
    }

    public static byte[] decrypt(byte[] encryptedContent, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(keyPairAlg);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedContent);
    }

}
