package vault5431.crypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

/**
 * Utils class for Symmetric encryption
 */
public class SymmetricUtils {

    private static final SecureRandom random = new SecureRandom();

    public static final int KEY_SIZE = 256;
    public static final int IV_SIZE = 16;

    private static Cipher getCipher() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        return Cipher.getInstance("AES/CBC/PKCS5PADDING", "BC");
    }

    public static SecretKey getNewKey() {
        SecretKey key = null;
        try {
            KeyGenerator gen = KeyGenerator.getInstance("AES");
            gen.init(KEY_SIZE);
            key = gen.generateKey();
        } catch (NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return key;
    }

    public static IvParameterSpec getNewIV() {
        byte[] iv = new byte[IV_SIZE];
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static byte[] encrypt(Base64String content, SecretKey key, IvParameterSpec iv)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] ciphertext = null;
        try {
            Cipher aesCipher = getCipher();
            aesCipher.init(Cipher.ENCRYPT_MODE, key, iv);
            ciphertext = aesCipher.doFinal(content.getB64Bytes());
        } catch (NoSuchProviderException | NoSuchPaddingException | NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return ciphertext;
    }

    public static Base64String decrypt(byte[] encryptedContent, SecretKey key, IvParameterSpec iv)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Base64String decryptedText = null;
        try {
            Cipher aesCipher = getCipher();
            aesCipher.init(Cipher.DECRYPT_MODE, key, iv);
            decryptedText = Base64String.fromBase64(aesCipher.doFinal(encryptedContent));
        } catch (NoSuchProviderException | NoSuchPaddingException | NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return decryptedText;
    }

}
