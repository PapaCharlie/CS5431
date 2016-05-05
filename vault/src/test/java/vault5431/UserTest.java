package vault5431;

import org.junit.Test;
import vault5431.auth.AuthenticationHandler;
import vault5431.auth.AuthenticationHandler.Token;
import vault5431.io.Base64String;
import vault5431.logging.LogEntry;
import vault5431.users.User;

import java.util.Arrays;

/**
 * Tests correct instantiation of User.
 */
public class UserTest extends VaultTest {

    static String username = generateUsername();
    static String password = PasswordGenerator.generatePassword(10);
    static User user;
    static Token token;

    static {
        try {
            user = getTempUser(username, password);
            token = AuthenticationHandler.acquireUnverifiedToken(username, new Base64String(password), Sys.NO_IP);
        } catch (Exception err) {
            System.out.println("Could not create temp user!");
            throw new RuntimeException(err);
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
