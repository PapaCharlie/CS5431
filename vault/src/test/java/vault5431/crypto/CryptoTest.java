package vault5431.crypto;

import org.junit.Test;
import vault5431.VaultTest;
import vault5431.io.Base64String;

import javax.crypto.SecretKey;
import java.io.File;

import static org.junit.Assert.*;

/**
 * Tests basic encryption functionality.
 *
 * @author papacharlie
 */
public class CryptoTest extends VaultTest {

    private String testString = "testString";

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
        Base64String signature1 = SigningUtils.sign(testString.getBytes(), key);
        Base64String signature2 = SigningUtils.sign("somethingElse".getBytes(), key);
        assertFalse(signature1.equals(signature2));
        assertTrue(SigningUtils.verify(testString.getBytes(), signature1, key));
    }

    @Test
    public void hashTest() throws Exception {
        Base64String hash = HashUtils.hash512(testString.getBytes());
        Base64String diffHash = HashUtils.hash512("a".getBytes());
        assertFalse(hash.equals(diffHash));
    }

    @Test
    public void testSavePassword() throws Exception {
        File passwordFile = getTempFile("password");
        PasswordUtils.hashAndSavePassword(passwordFile, "password");
        assertTrue(PasswordUtils.verifyPasswordInFile(passwordFile, "password"));
    }

}
