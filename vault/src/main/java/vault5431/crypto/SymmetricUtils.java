package vault5431.crypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Utils class for Symmetric encryption
 */
public class SymmetricUtils {

    private static final SecureRandom random = new SecureRandom();

    public static String AES = "AES";
    public static String AES_ALG = AES + "/CBC/PKCS5PADDING";
    public static int keySize = 256;
    public static int ivSize = 16;

    public static SecretKey getNewKey() {
        SecretKey key = null;
        try {
            KeyGenerator gen = KeyGenerator.getInstance(AES);
            gen.init(keySize);
            key = gen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            System.err.println(AES + " key generation algorithm does not exist!");
            System.exit(1);
        }
        return key;
    }

    public static IvParameterSpec getNewIV() {
        byte[] iv = new byte[ivSize];
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static byte[] encrypt(Base64String content, SecretKey key, IvParameterSpec iv)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] ciphertext = null;
        try {
            Cipher aesCipher = Cipher.getInstance(AES_ALG);
            aesCipher.init(Cipher.ENCRYPT_MODE, key, iv);
            ciphertext = aesCipher.doFinal(content.getB64Bytes());
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            System.err.println(AES_ALG + " encryption algorithm does not exist!");
            System.exit(1);
        }
        return ciphertext;
    }

    public static Base64String decrypt(byte[] encryptedContent, SecretKey key, IvParameterSpec iv)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Base64String decryptedText = null;
        try {
            Cipher aesCipher = Cipher.getInstance(AES_ALG);
            aesCipher.init(Cipher.DECRYPT_MODE, key, iv);
            decryptedText = Base64String.fromBase64(aesCipher.doFinal(encryptedContent));
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            System.err.println(AES_ALG + " encryption algorithm does not exist!");
            System.exit(1);
        }
        return decryptedText;
    }

}
