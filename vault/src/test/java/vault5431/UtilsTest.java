package vault5431;

import org.junit.Test;
import vault5431.crypto.AsymmetricUtils;

import java.security.KeyPair;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Created by papacharlie on 2016-02-27.
 */
public class UtilsTest {

    @Test
    public void testEncryptor() throws Exception {
        KeyPair keys = AsymmetricUtils.generateKeyPair();
        assertNotNull("Utils.generateKeyPair() returned a null", keys);
        String testString = "testString";
        byte[] encrypted = AsymmetricUtils.encrypt(testString.getBytes(), keys.getPublic());
        byte[] decrypted = AsymmetricUtils.decrypt(encrypted, keys.getPrivate());
        assertArrayEquals(decrypted, testString.getBytes());
    }

}
