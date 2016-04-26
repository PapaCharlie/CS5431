package vault5431;

import org.junit.Test;
import vault5431.auth.AuthenticationHandler;
import vault5431.auth.Token;
import vault5431.io.Base64String;
import vault5431.logging.LogEntry;
import vault5431.users.User;

import javax.crypto.SecretKey;
import java.util.Arrays;

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
            token = AuthenticationHandler.acquireUnverifiedToken(user, new Base64String(password), Sys.NO_IP);
        } catch (Exception err) {
            err.printStackTrace();
            System.out.println("Could not create temp user!");
            System.exit(1);
        }
    }

    @Test
    public void testUserCreation() throws Exception {
        user.info("I'm a log entry!");
        user.info("I'm another log entry!");
        LogEntry[] loadedLog = user.loadLog(token);
        System.out.println(Arrays.toString(loadedLog));
    }

}
