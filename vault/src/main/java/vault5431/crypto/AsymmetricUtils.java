package vault5431.crypto;

import vault5431.Sys;
import vault5431.crypto.exceptions.BadCiphertextException;
import vault5431.crypto.exceptions.CouldNotLoadKeyException;
import vault5431.crypto.exceptions.CouldNotSaveKeyException;
import vault5431.io.Base64String;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Asymmetric encryption utils.
 */
public class AsymmetricUtils {

    /**
     * Asymmetric key size
     */
    public static final int KEY_SIZE = 4096;

    /**
     * Acquire RSA algorithm.
     * Will cause system exit if RSA algorithm not found (impossible, tried and tested)
     *
     * @return RSA Cipher object.
     */
    private static Cipher getCipher() {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA512AndMGF1Padding", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return cipher;
    }

    /**
     * Acquire RSA keypair.
     * WARNING: expensive function. Call at your own risk.
     *
     * @return Generated pair of KEY_SIZE bits
     */
    public static KeyPair getNewKeyPair() {
        KeyPair keyPair = null;
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");
            gen.initialize(KEY_SIZE, new SecureRandom());
            keyPair = gen.generateKeyPair();
        } catch (NoSuchProviderException | NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return keyPair;
    }

    public static Base64String encrypt(byte[] content, PublicKey publicKey) throws BadCiphertextException {
        try {
            Cipher cipher = getCipher();
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return new Base64String(cipher.doFinal(content));
        } catch (IllegalBlockSizeException | BadPaddingException err) {
            err.printStackTrace();
            throw new BadCiphertextException();
        } catch (InvalidKeyException err) {
            Sys.error("Generated a wrong key! Requires immediate action.");
            throw new RuntimeException("Generated a wrong key!");
        }
    }

    public static byte[] decrypt(Base64String encryptedContent, PrivateKey privateKey) throws BadCiphertextException {
        try {
            Cipher cipher = getCipher();
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encryptedContent.decodeBytes());
        } catch (IllegalBlockSizeException | BadPaddingException err) {
            err.printStackTrace();
            throw new BadCiphertextException();
        } catch (InvalidKeyException err) {
            Sys.error("Generated a wrong key! Requires immediate action.");
            throw new RuntimeException("Generated a wrong key!");
        }
    }

    public static void savePublicKey(File keyfile, PublicKey key) throws IOException {
        Base64String key64 = new Base64String(key.getEncoded());
        key64.saveToFile(keyfile);
    }

    public static PublicKey loadPublicKey(File keyfile) throws IOException, CouldNotLoadKeyException {
        PublicKey publicKey = null;
        try {
            byte[] key64 = Base64String.loadFromFile(keyfile)[0].decodeBytes();
            publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(key64));
        } catch (NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        } catch (InvalidKeySpecException err) {
            err.printStackTrace();
            throw new CouldNotLoadKeyException();
        }
        return publicKey;
    }

    public static void savePrivateKey(File keyfile, PrivateKey privateKey, SecretKey key) throws IOException, CouldNotSaveKeyException {
        try {
            Base64String encryptedKey = SymmetricUtils.encrypt(privateKey.getEncoded(), key);
            encryptedKey.saveToFile(keyfile);
        } catch (BadCiphertextException err) {
            err.printStackTrace();
            throw new CouldNotSaveKeyException();
        }
    }

    public static PrivateKey loadPrivateKey(File keyfile, SecretKey key) throws IOException, CouldNotLoadKeyException {
        PrivateKey privateKey = null;
        try {
            Base64String encryptedKey = Base64String.loadFromFile(keyfile)[0];
            byte[] decryptedPrivateKeyBytes = SymmetricUtils.decrypt(encryptedKey, key);
            privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decryptedPrivateKeyBytes));
        } catch (NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        } catch (BadCiphertextException | InvalidKeySpecException err) {
            throw new CouldNotLoadKeyException();
        }
        return privateKey;
    }

}
