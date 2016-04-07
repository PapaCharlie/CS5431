package vault5431.crypto;

import org.bouncycastle.jcajce.provider.symmetric.AES;
import org.bouncycastle.util.Arrays;
import vault5431.Sys;
import vault5431.crypto.exceptions.BadCiphertextException;
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

    public static SecretKey keyFromBytes(byte[] bytes) {
        return new SecretKeySpec(bytes, "AES");
    }

    public static SecretKey getNewKey() {
        SecretKey key = null;
        try {
            KeyGenerator gen = KeyGenerator.getInstance("AES", "BC");
            gen.init(KEY_SIZE);
            key = gen.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return key;
    }

    public static IvParameterSpec generateIV() {
        byte[] iv = new byte[IV_SIZE];
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static Base64String encrypt(byte[] content, SecretKey key)
            throws BadCiphertextException {
        Base64String ciphertext = null;
        IvParameterSpec iv = generateIV();
        try {
            Cipher aesCipher = getCipher();
            aesCipher.init(Cipher.ENCRYPT_MODE, key, iv);
            ciphertext = new Base64String(Arrays.concatenate(iv.getIV(), aesCipher.doFinal(content)));
        } catch (InvalidAlgorithmParameterException | NoSuchProviderException | NoSuchPaddingException | NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        } catch (IllegalBlockSizeException err) {
            err.printStackTrace();
            throw new BadCiphertextException();
        } catch (BadPaddingException err) {
            // Only thrown in decryption mode, we're okay.
            err.printStackTrace();
        } catch (InvalidKeyException err) {
            Sys.error("Generated a wrong key! Requires immediate action.");
            throw new RuntimeException("Generated a wrong key!");
        }
        return ciphertext;
    }

    public static byte[] decrypt(Base64String encryptedContent, SecretKey key) throws BadCiphertextException {
        byte[] decryptedText = null;
        try {
            Cipher aesCipher = getCipher();
            byte[] content = encryptedContent.decodeBytes();
            IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(content, 0, IV_SIZE));
            byte[] cipherText = Arrays.copyOfRange(content, IV_SIZE, content.length);
            aesCipher.init(Cipher.DECRYPT_MODE, key, iv);
            decryptedText = aesCipher.doFinal(cipherText);
        } catch (InvalidAlgorithmParameterException | NoSuchProviderException | NoSuchPaddingException | NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        } catch (BadPaddingException | IllegalBlockSizeException  err) {
            err.printStackTrace();
            throw new BadCiphertextException();
        }  catch (InvalidKeyException err) {
            Sys.error("Generated a wrong key! Requires immediate action.");
            throw new RuntimeException("Generated a wrong key!");
        }
        return decryptedText;
    }

    public static void saveSecretKey(File keyFile, SecretKey key, PublicKey publicKey) throws BadCiphertextException, IOException {
        Base64String encryptedKey = AsymmetricUtils.encrypt(key.getEncoded(), publicKey);
        encryptedKey.saveToFile(keyFile);
    }

    public static SecretKey loadSecretKey(File file, PrivateKey privateKey) throws IOException, BadCiphertextException {
        Base64String encryptedKey = Base64String.loadFromFile(file)[0];
        byte[] key = AsymmetricUtils.decrypt(encryptedKey, privateKey);
        return keyFromBytes(key);
    }

}
