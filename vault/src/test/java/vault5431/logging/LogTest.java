package vault5431.logging;

import org.junit.Test;
import vault5431.Sys;
import vault5431.VaultTest;
import vault5431.auth.AuthenticationHandler;
import vault5431.auth.TwoFactorAuthHandlerTest;
import vault5431.io.Base64String;
import vault5431.io.FileUtils;
import vault5431.users.User;
import vault5431.users.exceptions.CorruptedLogException;

import java.time.LocalDateTime;

import static org.junit.Assert.*;

/**
 * Created by CYJ on 3/14/16.
 */
public class LogTest extends VaultTest {
    @Test
    public void testUserLog() throws Exception {

        User user = getTempUser("test", "test");
        AuthenticationHandler.Token token = AuthenticationHandler.acquireUnverifiedToken("test", new Base64String("test"), Sys.NO_IP);
        assertNotNull(token);

        user.info("Logged in");
        user.warning("Failed login attempt");
        user.error("Could not find log!");

        user.loadLog(token);

    }

    @Test(expected = CorruptedLogException.class)
    public void testBadLog() throws Exception {

        User user = getTempUser("test2", "test");
        AuthenticationHandler.Token token = AuthenticationHandler.acquireUnverifiedToken("test2", new Base64String("test"), Sys.NO_IP);
        assertNotNull(token);

        user.info("Logged in");
        user.warning("Failed login attempt");
        user.error("Could not find log!");

        Base64String[] log = FileUtils.read(user.logFile);

        FileUtils.empty(user.logFile);
        FileUtils.append(user.logFile, log[0]);
        FileUtils.append(user.logFile, log[2]);

        user.loadLog(token);


    }
}
