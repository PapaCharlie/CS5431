package vault5431.crypto;

import javax.crypto.Cipher;
import java.security.*;

/**
 * Created by papacharlie on 2/29/16.
 */
public class AsymmetricUtils {

    private static String RSA = "RSA";
    private static String RSA_ALG = RSA + "/ECB/PKCS1Padding";

    public static KeyPair getNewKeyPair() {
        int keySize = 2048;
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance(RSA);
            gen.initialize(keySize, new SecureRandom());
            return gen.generateKeyPair();
        } catch (NoSuchAlgorithmException err) {
            System.err.println(RSA + " key generation algorithm does not exist!");
            System.exit(1);
            return null;
        }
    }

    public static byte[] encrypt(Base64String content, PublicKey publicKey) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALG);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(content.getBytes());
        } catch (NoSuchAlgorithmException e) {
            System.err.println(RSA_ALG + " encryption algorithm does not exist!");
            System.exit(1);
            return null;
        }
    }

    public static Base64String decrypt(byte[] encryptedContent, PrivateKey privateKey) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALG);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return Base64String.fromBase64(cipher.doFinal(encryptedContent));
        } catch (NoSuchAlgorithmException e) {
            System.err.println(RSA_ALG + " encryption algorithm does not exist!");
            System.exit(1);
            return null;
        }
    }

}
