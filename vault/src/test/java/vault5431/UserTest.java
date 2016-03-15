package vault5431;

import org.junit.Test;
import vault5431.io.Base64String;
import vault5431.logging.LogEntry;

import java.util.Arrays;

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
        user.debug("I'm a log entry!");
        user.debug("I'm another log entry!");
        LogEntry[] loadedLog = user.loadLog(password);
        System.out.println(Arrays.toString(loadedLog));
    }

}
