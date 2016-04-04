package vault5431;

import org.junit.Test;
import vault5431.crypto.exceptions.CouldNotLoadKeyException;
import vault5431.crypto.exceptions.InvalidPublicKeySignature;
import vault5431.io.Base64String;
import vault5431.io.FileUtils;
import vault5431.logging.LogEntry;
import vault5431.users.User;

import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Tests correct instantiation of User.
 */
public class UserTest extends VaultTest {

    static String username = PasswordGenerator.generatePassword(10);
    static String password = PasswordGenerator.generatePassword(10);
    static User user;

    static {
        try {
            user = getTempUser(password);
        } catch (Exception err) {
            err.printStackTrace();
            System.out.println("Could not create temp user!");
            System.exit(1);
        }
    }

    @Test
    public void testUserCreation() throws Exception {
        user.loadPrivateCryptoKey(password);
        user.loadPublicCryptoKey();
        user.loadPrivateSigningKey(password);
        user.loadPublicSigningKey();
        user.debug("I'm a log entry!");
        user.debug("I'm another log entry!");
        LogEntry[] loadedLog = user.loadLog(password);
        System.out.println(Arrays.toString(loadedLog));
    }

    @Test
    public void testLoadPasswords() throws Exception {
        Password password = new Password("Test", "www.test.com", username, "password!");
        user.addPassword(password);
        Password[] passwords = user.loadPasswords();
        assertTrue(passwords.length > 0);
        assertTrue(password.equals(passwords[0]));
    }

    @Test
    public void testPubkeySigning() throws Exception {
        User user = getTempUser("password");
        FileUtils.write(user.pubCryptoKeyFile, new Base64String("nothing!"));
        try {
            user.loadPublicCryptoKey();
            fail("Public key was loaded even though signature could not be verified.");
        } catch (InvalidPublicKeySignature | CouldNotLoadKeyException err) {
            assert (true);
        }
    }

}
