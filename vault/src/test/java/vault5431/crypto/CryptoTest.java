package vault5431.crypto;

import org.junit.Ignore;
import org.junit.Test;
import vault5431.PasswordGenerator;
import vault5431.VaultTest;
import vault5431.io.Base64String;

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

    private static final KeyPair keys = AsymmetricUtils.getNewKeyPair();
    private String testString = "testString";

    @Test
    public void testAsymmetricEncDec() throws Exception {
        Base64String encrypted = AsymmetricUtils.encrypt(testString.getBytes(), keys.getPublic());
        String decrypted = new String(AsymmetricUtils.decrypt(encrypted, keys.getPrivate()));
        assertEquals(decrypted, testString);
    }

    @Test
    public void testSymmetricEncDec() throws Exception {
        SecretKey key = SymmetricUtils.getNewKey();
        Base64String encrypted = SymmetricUtils.encrypt(testString.getBytes(), key);
        String decrypted = new String(SymmetricUtils.decrypt(encrypted, key));
        assertEquals(decrypted, testString);
    }

    @Test
    public void testHMAC() throws Exception {
        SecretKey key = SymmetricUtils.getNewKey();
        Base64String signature1 = SigningUtils.getSignature(testString.getBytes(), key);
        Base64String signature2 = SigningUtils.getSignature("somethingElse".getBytes(), key);
        assertFalse(signature1.equals(signature2));
        assertTrue(SigningUtils.verifySignature(testString.getBytes(), signature1, key));
    }

    @Test
    public void hashTest() throws Exception {
        Base64String hash = HashUtils.hash512(testString.getBytes());
        Base64String diffHash = HashUtils.hash512("a".getBytes());
        assertFalse(hash.equals(diffHash));
    }

    @Test
    public void testSecretKeySaveToFile() throws Exception {
        SecretKey key = SymmetricUtils.getNewKey();
        File secretKeyFile = getTempFile("key");
        SymmetricUtils.saveSecretKey(secretKeyFile, key, keys.getPublic());
        SecretKey loadedKey = SymmetricUtils.loadSecretKey(secretKeyFile, keys.getPrivate());
        assertArrayEquals(key.getEncoded(), loadedKey.getEncoded());
    }

    @Test
    public void testPublicKeySaveToFile() throws Exception {
        File pubKeyFile = getTempFile("id_rsa", ".pub");
        AsymmetricUtils.savePublicKey(pubKeyFile, keys.getPublic());
        PublicKey pubkey = AsymmetricUtils.loadPublicKey(pubKeyFile);
        assertArrayEquals(keys.getPublic().getEncoded(), pubkey.getEncoded());
    }

    @Test
    public void testPrivateKeySaveToFile() throws Exception {
        File privKeyFile = getTempFile("id_rsa");
        String password = PasswordGenerator.generatePassword(20);
        SecretKey key = SymmetricUtils.getNewKey();
        File passwordFile = getTempFile("password");
        PasswordUtils.savePassword(passwordFile, password);
        AsymmetricUtils.savePrivateKey(privKeyFile, keys.getPrivate(), key);
        PrivateKey privateKey = AsymmetricUtils.loadPrivateKey(privKeyFile, key);
        assertNotNull(privateKey);
        assertArrayEquals(keys.getPrivate().getEncoded(), privateKey.getEncoded());
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

    @Ignore
    public void testMaxRSALength() throws Exception {
        String s = "";
        while (s.length() < AsymmetricUtils.KEY_SIZE) {
            System.out.printf("String length: %d\n", s.length());
            AsymmetricUtils.encrypt(s.getBytes(), keys.getPublic());
            s += "=";
        }
    }

}
