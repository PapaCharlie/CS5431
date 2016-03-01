package vault5431.crypto;

import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Tests basic encryption functionality. Requires further testing for robustness.
 */
public class UtilsTest {

    public String testString = "testString";

    @Test
    public void testAsymmetricEncDec() throws Exception {
        KeyPair keys = AsymmetricUtils.getNewKeyPair();
        assertNotNull("Utils.getNewKeyPair() returned a null", keys);
        byte[] encrypted = AsymmetricUtils.encrypt(new Base64String(testString), keys.getPublic());
        Base64String decrypted = AsymmetricUtils.decrypt(encrypted, keys.getPrivate());
        assertEquals(decrypted.decodeAsString(), testString);
    }

    @Test
    public void testSymmetricEncDec() throws Exception {
        SecretKey key = SymmetricUtils.getNewKey();
        IvParameterSpec iv = SymmetricUtils.getNewIV();
        byte[] encrypted = SymmetricUtils.encrypt(new Base64String(testString), key, iv);
        Base64String decrypted = SymmetricUtils.decrypt(encrypted, key, iv);
        assertEquals(decrypted.decodeAsString(), testString);
    }

    @Test
    public void testHMAC() throws Exception {
        SecretKey key = SymmetricUtils.getNewKey();
        Base64String signature1 = SigningUtils.getSignature(new Base64String(testString), key);
        Base64String signature2 = SigningUtils.getSignature(new Base64String("somethingElse"), key);
        assertFalse(signature1.equals(signature2));
    }

    @Test
    public void hashTest() throws Exception {
        Base64String hash = HashUtils.hash(new Base64String(testString));
        Base64String diffHash = HashUtils.hash(new Base64String("a"));
        assertNotNull(hash);
        assertNotNull(diffHash);
        assertFalse(hash.equals(diffHash));;
        System.out.println(HashUtils.hash(new Base64String("hello")));
    }

}
