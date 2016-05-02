package vault5431.crypto;

import vault5431.Sys;
import vault5431.crypto.exceptions.BadCiphertextException;
import vault5431.crypto.exceptions.CouldNotLoadKeyException;
import vault5431.crypto.exceptions.CouldNotSaveKeyException;
import vault5431.io.Base64String;

import javax.crypto.*;
import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Asymmetric encryption utils.
 *
 * @author papacharlie
 */
public class AsymmetricUtils {

    /**
     * Asymmetric key size.
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
     * @return Generated pair of {@link #KEY_SIZE} bits
     */
    public static KeyPair getNewKeyPair() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");
            gen.initialize(KEY_SIZE, new SecureRandom());
            return gen.generateKeyPair();
        } catch (NoSuchProviderException | NoSuchAlgorithmException err) {
            err.printStackTrace();
            throw new RuntimeException(err);
        }
    }

    /**
     * Encrypt the content using the provided key.
     *
     * @param content   content to be encrypted
     * @param publicKey public key with which to encrypt
     * @return Encrypted string as a {@link Base64String}.
     * @throws BadCiphertextException If the #content cannot be encrypted.
     */
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

    /**
     * Returns the decrypted data encrypted by {@link #encrypt}.
     *
     * @param encryptedContent encrypted content
     * @param privateKey       private key of pair used to encrypt
     * @return Decrypted content.
     * @throws BadCiphertextException If the content cannot be decrypted/is corrupted. Should not be thrown if the
     *                                parameter has truly been returned by {@link #encrypt}.
     */
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

    /**
     * Save public key to disk.
     *
     * @param keyFile file in which to write the key
     * @param key     key to save
     * @throws IOException If the file cannot be written to.
     */
    public static void savePublicKey(File keyFile, PublicKey key) throws IOException {
        Base64String key64 = new Base64String(key.getEncoded());
        key64.saveToFile(keyFile);
    }

    /**
     * Returns the public key saved by {@link #savePublicKey(File, PublicKey)}.
     *
     * @param keyFile file from which to read the key
     * @return The loaded public key.
     * @throws IOException              If the file cannot be read.
     * @throws CouldNotLoadKeyException If the saved key was invalid. Should not be thrown if the key was truly saved by
     *                                  {@link #savePublicKey(File, PublicKey)}.
     */
    public static PublicKey loadPublicKey(File keyFile) throws IOException, CouldNotLoadKeyException {
        PublicKey publicKey = null;
        try {
            byte[] key64 = Base64String.loadFromFile(keyFile)[0].decodeBytes();
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

    /**
     * Save the private key to a file, encrypted under a secret key.
     *
     * @param keyFile    file to write the key to
     * @param privateKey private key to encrypt and save
     * @param key        secret key under which to encrypt the private key
     * @throws IOException              If the file cannot be written to.
     * @throws CouldNotSaveKeyException If the private key could not be encrypted.
     */
    public static void savePrivateKey(File keyFile, PrivateKey privateKey, SecretKey key) throws IOException, CouldNotSaveKeyException {
        try {
            Base64String encryptedKey = SymmetricUtils.encrypt(privateKey.getEncoded(), key);
            encryptedKey.saveToFile(keyFile);
        } catch (BadCiphertextException err) {
            err.printStackTrace();
            throw new CouldNotSaveKeyException();
        }
    }

    /**
     * Returns the private key loaded from disk, presumably encrypted and saved by {@link #savePrivateKey(File, PrivateKey, SecretKey)}.
     * WARNING: Likely not to throw an error if the given {@link SecretKey} was not the one the private key was encrypted under.
     *
     * @param keyFile file in which the private key is stored
     * @param key     secret key under which the key was encrypted
     * @return The decrypted and loaded key.
     * @throws IOException              If the file cannot be read.
     * @throws CouldNotLoadKeyException If the private key could not be decrypted, or decrypted to an invalid {@link PrivateKey}.
     */
    public static PrivateKey loadPrivateKey(File keyFile, SecretKey key) throws IOException, CouldNotLoadKeyException {
        try {
            Base64String encryptedKey = Base64String.loadFromFile(keyFile)[0];
            byte[] decryptedPrivateKeyBytes = SymmetricUtils.decrypt(encryptedKey, key);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decryptedPrivateKeyBytes));
        } catch (NoSuchAlgorithmException err) {
            err.printStackTrace();
            throw new RuntimeException(err);
        } catch (BadCiphertextException | InvalidKeySpecException err) {
            throw new CouldNotLoadKeyException();
        }
    }

}
