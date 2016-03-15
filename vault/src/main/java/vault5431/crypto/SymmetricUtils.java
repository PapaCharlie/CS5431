package vault5431.crypto;

import vault5431.io.Base64String;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.security.*;

/**
 * Utils class for Symmetric encryption
 */
public class SymmetricUtils {

    public static final int KEY_SIZE = 256;
    public static final int IV_SIZE = 16;
    private static final SecureRandom random = new SecureRandom();

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

    public static Base64String encrypt(byte[] content, SecretKey key, IvParameterSpec iv)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Base64String ciphertext = null;
        try {
            Cipher aesCipher = getCipher();
            aesCipher.init(Cipher.ENCRYPT_MODE, key, iv);
            ciphertext = new Base64String(aesCipher.doFinal(content));
        } catch (NoSuchProviderException | NoSuchPaddingException | NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return ciphertext;
    }

    public static byte[] decrypt(Base64String encryptedContent, SecretKey key, IvParameterSpec iv)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] decryptedText = null;
        try {
            Cipher aesCipher = getCipher();
            aesCipher.init(Cipher.DECRYPT_MODE, key, iv);
            decryptedText = aesCipher.doFinal(encryptedContent.decodeBytes());
        } catch (NoSuchProviderException | NoSuchPaddingException | NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return decryptedText;
    }

    public static void saveSecretKey(File keyFile, SecretKey key, PublicKey publicKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        Base64String encryptedKey = AsymmetricUtils.encrypt(key.getEncoded(), publicKey);
        encryptedKey.saveToFile(keyFile);
    }

    public static SecretKey loadSecretKey(File file, PrivateKey privateKey) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Base64String encryptedKey = Base64String.loadFromFile(file)[0];
        byte[] key = AsymmetricUtils.decrypt(encryptedKey, privateKey);
        return new SecretKeySpec(key, "AES");
    }

}
