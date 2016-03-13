package vault5431.crypto;

import org.bouncycastle.util.Arrays;

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

    private static int keySize = 4096;

    private static Cipher getCipher() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        return Cipher.getInstance("RSA/NONE/OAEPWithSHA512AndMGF1Padding", "BC");
    }

    public static KeyPair getNewKeyPair() {
        KeyPair keyPair = null;
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");
            gen.initialize(keySize, new SecureRandom());
            keyPair = gen.generateKeyPair();
        } catch (NoSuchProviderException | NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return keyPair;
    }

    public static byte[] encrypt(Base64String content, PublicKey publicKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] ciphertext = null;
        try {
            Cipher cipher = getCipher();
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            ciphertext = cipher.doFinal(content.getB64Bytes());
        } catch (NoSuchProviderException | NoSuchPaddingException | NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return ciphertext;
    }

    public static Base64String decrypt(byte[] encryptedContent, PrivateKey privateKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Base64String decryptedText = null;
        try {
            Cipher cipher = getCipher();
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            decryptedText = Base64String.fromBase64(cipher.doFinal(encryptedContent));
        } catch (NoSuchProviderException | NoSuchPaddingException | NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return decryptedText;
    }

    public static boolean savePublicKey(File keyfile, PublicKey key) throws IOException {
        Base64String key64 = new Base64String(key.getEncoded());
        return key64.saveToFile(keyfile);
    }

    public static PublicKey loadPublicKey(File keyfile) throws IOError, IOException, InvalidKeySpecException {
        PublicKey publicKey = null;
        try {
            byte[] key64 = Base64String.loadFromFile(keyfile).decodeBytes();
            publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(key64));
        } catch (NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return publicKey;
    }

    private static SecretKey keyFromPassword(String password) {
        byte[] hashedPassword = hash256(new Base64String(password)).decodeBytes();
        return new SecretKeySpec(hashedPassword, "AES");
    }

    public static boolean savePrivateKey(File keyfile, PrivateKey privateKey, String password)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOError, IOException {
        SecretKey key = keyFromPassword(password);
        Base64String privateKey64 = new Base64String(privateKey.getEncoded());
        IvParameterSpec iv = SymmetricUtils.getNewIV();
        byte[] encryptedKey = SymmetricUtils.encrypt(privateKey64, key, iv);
        return new Base64String(Arrays.concatenate(iv.getIV(), encryptedKey)).saveToFile(keyfile);
    }

    public static PrivateKey loadPrivateKey(File keyfile, String password, File passwordFile)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOError, IOException, InvalidKeySpecException {
        PrivateKey privateKey = null;
        try {
            if (PasswordUtils.verifyPasswordInFile(passwordFile, password)) {
                byte[] key64 = Base64String.loadFromFile(keyfile).decodeBytes();
                byte[] iv = Arrays.copyOfRange(key64, 0, SymmetricUtils.ivSize);
                byte[] encryptedPrivateKeyBytes = Arrays.copyOfRange(key64, SymmetricUtils.ivSize, key64.length);
                SecretKey key = keyFromPassword(password);
                byte[] decryptedPrivateKeyBytes = SymmetricUtils.decrypt(encryptedPrivateKeyBytes, key, new IvParameterSpec(iv)).decodeBytes();
                privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decryptedPrivateKeyBytes));
            }
        } catch (NoSuchAlgorithmException err) {
            err.printStackTrace();
            System.exit(1);
        }
        return privateKey;
    }


}
