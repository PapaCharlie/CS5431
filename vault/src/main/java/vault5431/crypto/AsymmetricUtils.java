package vault5431.crypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOError;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static vault5431.crypto.HashUtils.hash256;

/**
 * Asymmetric encryption utils.
 */
public class AsymmetricUtils {

    private static final int KEY_SIZE = 4096;

    private static Cipher getCipher() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        return Cipher.getInstance("RSA/NONE/OAEPWithSHA512AndMGF1Padding", "BC");
    }

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

    public static Base64String encrypt(byte[] content, PublicKey publicKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Base64String ciphertext = null;
        try {
            Cipher cipher = getCipher();
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            ciphertext = new Base64String(cipher.doFinal(content));
        } catch (NoSuchProviderException | NoSuchPaddingException | NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return ciphertext;
    }

    public static byte[] decrypt(Base64String encryptedContent, PrivateKey privateKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] decryptedText = null;
        try {
            Cipher cipher = getCipher();
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            decryptedText = cipher.doFinal(encryptedContent.decodeBytes());
        } catch (NoSuchProviderException | NoSuchPaddingException | NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return decryptedText;
    }

    public static void savePublicKey(File keyfile, PublicKey key) throws IOException {
        Base64String key64 = new Base64String(key.getEncoded());
        key64.saveToFile(keyfile);
    }

    public static PublicKey loadPublicKey(File keyfile) throws IOError, IOException, InvalidKeySpecException {
        PublicKey publicKey = null;
        try {
            byte[] key64 = Base64String.loadFromFile(keyfile)[0].decodeBytes();
            publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(key64));
        } catch (NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return publicKey;
    }

    private static SecretKey keyFromPassword(String password) {
        byte[] hashedPassword = hash256(password.getBytes()).decodeBytes();
        return new SecretKeySpec(hashedPassword, "AES");
    }

    public static void savePrivateKey(File keyfile, File ivFile, PrivateKey privateKey, String password)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOError, IOException {
        SecretKey key = keyFromPassword(password);
        IvParameterSpec iv = SymmetricUtils.getNewIV();
        Base64String encryptedKey = SymmetricUtils.encrypt(privateKey.getEncoded(), key, iv);
        new Base64String(iv.getIV()).saveToFile(ivFile);
        encryptedKey.saveToFile(keyfile);
    }

    public static PrivateKey loadPrivateKey(File keyfile, File ivFile, String password, File passwordFile)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOError, IOException, InvalidKeySpecException {
        PrivateKey privateKey = null;
        try {
            if (PasswordUtils.verifyPasswordInFile(passwordFile, password)) {
                Base64String encryptedKey = Base64String.loadFromFile(keyfile)[0];
                byte[] iv = Base64String.loadFromFile(ivFile)[0].decodeBytes();
                SecretKey key = keyFromPassword(password);
                byte[] decryptedPrivateKeyBytes = SymmetricUtils.decrypt(encryptedKey, key, new IvParameterSpec(iv));
                privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decryptedPrivateKeyBytes));
            }
        } catch (NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return privateKey;
    }

}
