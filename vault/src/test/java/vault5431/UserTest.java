package vault5431;

import org.junit.Test;
import vault5431.auth.AuthenticationHandler;
import vault5431.auth.AuthenticationHandler.Token;
import vault5431.io.Base64String;
import vault5431.logging.LogEntry;

import java.util.Arrays;

/**
 * Tests correct instantiation of User.
 */
public class UserTest extends VaultTest {

    static TempUser tempUser;
    static Token token;

    static {
        try {
            tempUser = getTempUser();
            token = AuthenticationHandler.acquireUnverifiedToken(tempUser.username, new Base64String(tempUser.password), Sys.NO_IP);
        } catch (Exception err) {
            System.out.println("Could not create temp user!");
            throw new RuntimeException(err);
        }
    }

    @Test
    public void testUserCreation() throws Exception {
        tempUser.user.info("I'm a log entry!");
        tempUser.user.info("I'm another log entry!");
        LogEntry[] loadedLog = tempUser.user.loadLog(token);
        System.out.println(Arrays.toString(loadedLog));
    }

}
