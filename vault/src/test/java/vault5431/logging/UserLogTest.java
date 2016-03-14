package vault5431.logging;

import org.junit.Test;
import java.time.LocalDateTime;

/**
 * Created by CYJ on 3/14/16.
 */
public class UserLogTest {
    @Test
    public void toStringTest() throws Exception {
        UserLog testUserInfo = new UserLog(LogType.INFO, "0.0.0.0.0", "CYJ",
                LocalDateTime.now(), "Logged In", "[PLACEHOLDER]");
        UserLog testUserDebug = new UserLog(LogType.DEBUG, "0.0.0.0.0", "CYJ",
                LocalDateTime.now(), "Vault Configuration Error", "[PLACEHOLDER]");
        UserLog testUserWarning = new UserLog(LogType.WARNING, "0.0.0.0.0", "CYJ",
                LocalDateTime.now(), "Password incorrect.", "[PLACEHOLDER]");
        UserLog testUserError = new UserLog(LogType.ERROR, "0.0.0.0.0", "CYJ",
                LocalDateTime.now(), "Vault has been locked", "[PLACEHOLDER]");
        System.out.println(testUserInfo.toString());
        System.out.println(testUserDebug.toString());
        System.out.println(testUserWarning.toString());
        System.out.println(testUserError.toString());
    }
}
