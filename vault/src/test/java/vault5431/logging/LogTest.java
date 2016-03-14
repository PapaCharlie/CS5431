package vault5431.logging;

import org.junit.Test;
import java.time.LocalDateTime;

/**
 * Created by CYJ on 3/14/16.
 */
public class LogTest {
    @Test
    public void toStringUserTest() throws Exception {
        UserLog testUserInfo = new UserLog(LogType.INFO, "0.0.0.0.0", "CYJ",
                LocalDateTime.now(), "Logged In", "[PLACEHOLDER]");
        UserLog testUserDebug = new UserLog(LogType.DEBUG, "0.0.0.0.0", "CYJ",
                LocalDateTime.now(), "Vault Configuration Error", "[PLACEHOLDER]");
        UserLog testUserWarning = new UserLog(LogType.WARNING, "0.0.0.0.0", "CYJ",
                LocalDateTime.now(), "Password incorrect.", "[PLACEHOLDER]");
        UserLog testUserError = new UserLog(LogType.ERROR, "0.0.0.0.0", "CYJ",
                LocalDateTime.now(), "Vault has been locked", "[PLACEHOLDER]");

        System.out.println("USER LOG FORMATTING");
        System.out.println(testUserInfo.toString());
        System.out.println(testUserDebug.toString());
        System.out.println(testUserWarning.toString());
        System.out.println(testUserError.toString());
    }

    @Test
    public void toStringSystemTest() throws Exception {
        SystemLog testSystemInfo = new SystemLog(LogType.INFO, "CYJ",
                LocalDateTime.now(), "Logged In", "[PLACEHOLDER]");
        SystemLog testSystemDebug = new SystemLog(LogType.DEBUG, "CYJ",
                LocalDateTime.now(), "Vault Configuration Error", "[PLACEHOLDER]");
        SystemLog testSystemWarning = new SystemLog(LogType.WARNING, "CYJ",
                LocalDateTime.now(), "Password incorrect.", "[PLACEHOLDER]");
        SystemLog testSystemError = new SystemLog(LogType.ERROR, "CYJ",
                LocalDateTime.now(), "Vault has been locked", "[PLACEHOLDER]");

        System.out.println("SYSTEM LOG FORMATTING");
        System.out.println(testSystemInfo.toString());
        System.out.println(testSystemDebug.toString());
        System.out.println(testSystemWarning.toString());
        System.out.println(testSystemError.toString());
    }
}
