package vault5431.crypto;

import org.bouncycastle.util.Arrays;
import vault5431.crypto.exceptions.BadCiphertextException;
import vault5431.io.Base64String;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

/**
 * Utils class for Symmetric encryption.
 *
 * @author papacharlie
 */
public class SymmetricUtils {

    public static final int KEY_SIZE = 256;
    public static final int IV_SIZE = 16;
    private static final SecureRandom random = new SecureRandom();

    private static Cipher getCipher() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        return Cipher.getInstance("AES/CBC/PKCS5PADDING", "BC");
    }

    public static SecretKey keyFromBytes(byte[] bytes) {
        if (bytes.length != KEY_SIZE / 8) {
            throw new IllegalArgumentException(
                    String.format("Can only generate %d bit keys (received incorrect number of bytes", KEY_SIZE));
        }
        return new SecretKeySpec(bytes, "AES");
    }

    public static SecretKey hashIterateKey(SecretKey key) {
        return keyFromBytes(HashUtils.hash256(key.getEncoded()).decodeBytes());
    }

    public static SecretKey combine(SecretKey key, byte[] bytes) {
        return keyFromBytes(HashUtils.hash256(Arrays.concatenate(key.getEncoded(), bytes)).decodeBytes());
    }

    public static SecretKey combine(SecretKey key, Base64String bytes) {
        return keyFromBytes(HashUtils.hash256(Arrays.concatenate(key.getEncoded(), bytes.decodeBytes())).decodeBytes());
    }

    public static SecretKey getNewKey() {
        try {
            KeyGenerator gen = KeyGenerator.getInstance("AES", "BC");
            gen.init(KEY_SIZE);
            return gen.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException err) {
            err.printStackTrace();
            throw new RuntimeException(err);
        }
    }

    public static IvParameterSpec generateIV() {
        byte[] iv = new byte[IV_SIZE];
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static Base64String encrypt(byte[] content, SecretKey key) throws BadCiphertextException {
        try {
            IvParameterSpec iv = generateIV();
            Cipher aesCipher = getCipher();
            aesCipher.init(Cipher.ENCRYPT_MODE, key, iv);
            return new Base64String(Arrays.concatenate(iv.getIV(), aesCipher.doFinal(content)));
        } catch (InvalidAlgorithmParameterException | NoSuchProviderException | NoSuchPaddingException | NoSuchAlgorithmException err) {
            err.printStackTrace();
            throw new RuntimeException(err);
        } catch (IllegalBlockSizeException | BadPaddingException err) {
            err.printStackTrace();
            throw new BadCiphertextException();
        } catch (InvalidKeyException err) {
            System.err.println("Generated a wrong key. Aborting.");
            throw new RuntimeException(err);
        }
    }

    public static byte[] decrypt(Base64String encryptedContent, SecretKey key) throws BadCiphertextException {
        try {
            Cipher aesCipher = getCipher();
            byte[] content = encryptedContent.decodeBytes();
            IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(content, 0, IV_SIZE));
            byte[] cipherText = Arrays.copyOfRange(content, IV_SIZE, content.length);
            aesCipher.init(Cipher.DECRYPT_MODE, key, iv);
            return aesCipher.doFinal(cipherText);
        } catch (InvalidAlgorithmParameterException | NoSuchProviderException | NoSuchPaddingException | NoSuchAlgorithmException err) {
            throw new RuntimeException(err);
        } catch (BadPaddingException | IllegalBlockSizeException err) {
            err.printStackTrace();
            throw new BadCiphertextException();
        } catch (InvalidKeyException err) {
            System.err.println("Generated a wrong key! Aborting.");
            throw new RuntimeException(err);
        }
    }


}
