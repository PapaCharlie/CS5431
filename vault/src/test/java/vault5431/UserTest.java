package vault5431;

import org.junit.Test;
import vault5431.crypto.Base64String;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Tests correct instantiation of User.
 */
public class UserTest extends VaultTest {

    @Test
    public void testUserCreation() throws Exception {
        String password = PasswordGenerator.generatePassword(10);
        User user = getTempUser(password);
        assertNotNull(user);
        user.loadPrivateCryptoKey(password);
        user.loadPublicCryptoKey();
        user.loadPrivateSigningKey(password);
        user.loadPublicSigningKey();
        String log0 = "I'm a log entry!";
        Base64String log0b64 = new Base64String(log0);
        String log1 = "I'm another log entry!";
        Base64String log1b64 = new Base64String(log1);
        user.appendToLog(log0b64);
        user.appendToLog(log1b64);
        String[] loadedLog = user.loadLog(password);
        assertEquals(log0, loadedLog[0]);
        assertEquals(log1, loadedLog[1]);
    }

}
