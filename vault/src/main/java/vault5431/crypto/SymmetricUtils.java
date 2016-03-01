package vault5431.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Utils class for Symmetric encryption
 */
public class SymmetricUtils {

    private static String AES = "AES";
    private static String AES_ALG = AES + "/CBC/PKCS5PADDING";

    public static SecretKey getNewKey() {
        try {
            int keySize = 128;
            KeyGenerator gen = KeyGenerator.getInstance(AES);
            gen.init(keySize);
            return gen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            System.exit(1);
            return null;
        }
    }

    public static IvParameterSpec getNewIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static byte[] encrypt(Base64String content, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher aesCipher = Cipher.getInstance(AES_ALG);
        aesCipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return aesCipher.doFinal(content.getBytes());
    }

    public static Base64String decrypt(byte[] encryptedContent, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher aesCipher = Cipher.getInstance(AES_ALG);
        aesCipher.init(Cipher.DECRYPT_MODE, key, iv);
        return Base64String.fromBase64(aesCipher.doFinal(encryptedContent));
    }

}
