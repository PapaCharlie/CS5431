package vault5431;

import org.junit.Test;
import vault5431.auth.Token;
import vault5431.crypto.exceptions.CouldNotLoadKeyException;
import vault5431.crypto.exceptions.InvalidPublicKeySignature;
import vault5431.io.Base64String;
import vault5431.io.FileUtils;
import vault5431.logging.LogEntry;
import vault5431.users.User;
import static vault5431.Vault.adminEncryptionKey;

import javax.crypto.SecretKey;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Tests correct instantiation of User.
 */
public class UserTest extends VaultTest {

    static String username = PasswordGenerator.generatePassword(10);
    static String password = PasswordGenerator.generatePassword(10);
    static User user;
    static SecretKey key;
    static Token token;

    static {
        try {
            user = getTempUser(password);
            token = new Token(user);
        } catch (Exception err) {
            err.printStackTrace();
            System.out.println("Could not create temp user!");
            System.exit(1);
        }
    }

    @Test
    public void testUserCreation() throws Exception {
        user.loadPrivateCryptoKey(token);
        user.loadPublicCryptoKey();
        user.loadPrivateSigningKey(token);
        user.loadPublicSigningKey();
        user.info("I'm a log entry!");
        user.info("I'm another log entry!");
        LogEntry[] loadedLog = user.loadLog(token);
        System.out.println(Arrays.toString(loadedLog));
    }

//    @Test
//    public void testLoadPasswords() throws Exception {
//        Password password = new Password("Test", "www.test.com", username, "password!");
//        user.addPasswordToVault(password, token);
//        Password[] passwords = user.loadPasswords(token);
//        assertTrue(passwords.length > 0);
//        assertTrue(password.equals(passwords[0]));
//    }

    @Test
    public void testPubkeySigning() throws Exception {
        User user = getTempUser("password");
        FileUtils.write(user.pubCryptoKeyFile, new Base64String("nothing!"));
        try {
            user.loadPublicCryptoKey();
            fail("Public key was loaded even though signature could not be verified.");
        } catch (InvalidPublicKeySignature | CouldNotLoadKeyException err) {
            return;
        }
    }

}
