package vault5431.crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

/**
 * Asymmetric encryption utils.
 */
public class AsymmetricUtils {

    private static String RSA = "RSA";
    private static String RSA_ALG = RSA + "/ECB/PKCS1Padding";
    private static int keySize = 2048;

    public static KeyPair getNewKeyPair() {
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

    public static byte[] encrypt(Base64String content, PublicKey publicKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALG);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(content.getBytes());
        } catch (NoSuchAlgorithmException e) {
            System.err.println(RSA_ALG + " encryption algorithm does not exist!");
            System.exit(1);
            return new byte[0];
        } catch (NoSuchPaddingException e) {
            System.err.println(RSA_ALG + " encryption algorithm does not exist!");
            System.exit(1);
            return new byte[0];
        }
    }

    public static Base64String decrypt(byte[] encryptedContent, PrivateKey privateKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALG);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return Base64String.fromBase64(cipher.doFinal(encryptedContent));
        } catch (NoSuchAlgorithmException e) {
            System.err.println(RSA_ALG + " encryption algorithm does not exist!");
            System.exit(1);
            return Base64String.empty();
        } catch (NoSuchPaddingException e) {
            System.err.println(RSA_ALG + " encryption algorithm does not exist!");
            System.exit(1);
            return Base64String.empty();
        }
    }

}
