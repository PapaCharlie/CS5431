package vault5431;

import org.junit.Test;
import vault5431.auth.AuthenticationHandler;
import vault5431.io.Base64String;
import vault5431.io.FileUtils;
import vault5431.users.exceptions.CorruptedLogException;

import java.io.File;

import static org.junit.Assert.assertNotNull;
import static vault5431.Vault.home;

/**
 * Created by CYJ on 3/14/16.
 */
public class LogTest extends VaultTest {

    private static final File sysLogFile = new File(home, "log");

    @Test
    public void testUserLog() throws Exception {

        TempUser tempUser = getTempUser();
        AuthenticationHandler.Token token = AuthenticationHandler.acquireUnverifiedToken(tempUser.username, new Base64String(tempUser.password), Sys.NO_IP);
        assertNotNull(token);

        tempUser.user.info("Logged in");
        tempUser.user.warning("Failed login attempt");
        tempUser.user.error("Could not find log!");

        tempUser.user.loadLog(token);

    }

    @Test(expected = CorruptedLogException.class)
    public void testBadUserLog() throws Exception {

        TempUser tempUser = getTempUser();
        AuthenticationHandler.Token token = AuthenticationHandler.acquireUnverifiedToken(tempUser.username, new Base64String(tempUser.password), Sys.NO_IP);
        assertNotNull(token);

        tempUser.user.info("Logged in");
        tempUser.user.warning("Failed login attempt");
        tempUser.user.error("Could not find log!");

        File userLogFile = new File(new File(home, tempUser.user.hashedUsername.getB64String()), "log"); // Externally tamper with the log

        Base64String[] log = FileUtils.read(userLogFile);

        FileUtils.empty(userLogFile);
        FileUtils.append(userLogFile, log[0]);
        FileUtils.append(userLogFile, log[2]);

        tempUser.user.loadLog(token);
    }

    @Test
    public void testSysLog() throws Exception {

        FileUtils.empty(sysLogFile);

        Sys.loadLog();

        Sys.debug("debug");
        Sys.info("info");
        Sys.warning("warning");
        Sys.error("error");

        Sys.loadLog();

    }

    @Test(expected = CorruptedLogException.class)
    public void testBadSysLog() throws Exception {

        FileUtils.empty(sysLogFile);

        Sys.loadLog();

        Sys.debug("debug");
        Sys.info("info");
        Sys.warning("warning");
        Sys.error("error");

        Base64String[] log = FileUtils.read(sysLogFile);

        FileUtils.empty(sysLogFile);
        FileUtils.append(sysLogFile, log[0]);
        FileUtils.append(sysLogFile, log[3]);

        Sys.loadLog();

    }


}
