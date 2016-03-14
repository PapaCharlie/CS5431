package vault5431.crypto;

import org.junit.Test;
import vault5431.PasswordGenerator;
import vault5431.VaultTest;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.Assert.*;

/**
 * Tests basic encryption functionality. Requires further testing for robustness.
 */
public class CryptoTest extends VaultTest {

    private String testString = "testString";
    private static final KeyPair keys = AsymmetricUtils.getNewKeyPair();

    @Test
    public void testAsymmetricEncDec() throws Exception {
        byte[] encrypted = AsymmetricUtils.encrypt(new Base64String(testString), keys.getPublic());
        Base64String decrypted = AsymmetricUtils.decrypt(encrypted, keys.getPrivate());
        assertEquals(decrypted.decodeString(), testString);
    }

    @Test
    public void testSymmetricEncDec() throws Exception {
        SecretKey key = SymmetricUtils.getNewKey();
        IvParameterSpec iv = SymmetricUtils.getNewIV();
        byte[] encrypted = SymmetricUtils.encrypt(new Base64String(testString), key, iv);
        Base64String decrypted = SymmetricUtils.decrypt(encrypted, key, iv);
        assertEquals(decrypted.decodeString(), testString);
    }

    @Test
    public void testHMAC() throws Exception {
        SecretKey key = SymmetricUtils.getNewKey();
        Base64String signature1 = SigningUtils.getSignature(new Base64String(testString), key);
        Base64String signature2 = SigningUtils.getSignature(new Base64String("somethingElse"), key);
        assertFalse(signature1.equals(signature2));
        assertTrue(SigningUtils.verifySignature(new Base64String(testString), signature1, key));
    }

    @Test
    public void hashTest() throws Exception {
        Base64String hash = HashUtils.hash512(new Base64String(testString));
        Base64String diffHash = HashUtils.hash512(new Base64String("a"));
        assertFalse(hash.equals(diffHash));
    }

    @Test
    public void testPublicKeySaveToFile() throws Exception {
        File pubKeyFile = File.createTempFile("id_rsa", ".pub");
        AsymmetricUtils.savePublicKey(pubKeyFile.getAbsolutePath(), keys.getPublic());
        PublicKey pubkey = AsymmetricUtils.loadPublicKey(pubKeyFile.getAbsolutePath());
        assertArrayEquals(keys.getPublic().getEncoded(), pubkey.getEncoded());
        pubKeyFile.deleteOnExit();
    }

    @Test
    public void testPrivateKeySaveToFile() throws Exception {
        File privKeyFile = File.createTempFile("id_rsa", null);
        String password = PasswordGenerator.generatePassword(20);
        File passwordFile = File.createTempFile("password", null);
        PasswordUtils.savePassword(passwordFile.getAbsolutePath(), password);
        AsymmetricUtils.savePrivateKey(privKeyFile.getAbsolutePath(), keys.getPrivate(), password);
        PrivateKey privateKey = AsymmetricUtils.loadPrivateKey(privKeyFile.getAbsolutePath(), password, passwordFile.getAbsolutePath());
        assertNotNull(privateKey);
        assertArrayEquals(keys.getPrivate().getEncoded(), privateKey.getEncoded());
        privKeyFile.deleteOnExit();
        passwordFile.deleteOnExit();
    }

    @Test
    public void testPasswordHashing() throws Exception {
        for (int i = 0; i < 10; i++) {
            String password = PasswordGenerator.generatePassword(20);
            assertEquals(20, password.length());
            Base64String hashedPassword = PasswordUtils.hashPassword(password);
            assertTrue(PasswordUtils.verifyHashedPassword(hashedPassword, password));
        }
    }

}
