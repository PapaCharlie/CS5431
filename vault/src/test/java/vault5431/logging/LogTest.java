package vault5431.logging;

import org.junit.Test;
import java.time.LocalDateTime;

/**
 * Created by CYJ on 3/14/16.
 */
public class LogTest {
    @Test
    public void toStringUserTest() throws Exception {
        UserLogEntry testUserInfo = new UserLogEntry(LogType.INFO, "0.0.0.0.0", "CYJ",
                LocalDateTime.now(), "Logged In", "[PLACEHOLDER]");
        UserLogEntry testUserDebug = new UserLogEntry(LogType.DEBUG, "0.0.0.0.0", "CYJ",
                LocalDateTime.now(), "Vault Configuration Error", "[PLACEHOLDER]");
        UserLogEntry testUserWarning = new UserLogEntry(LogType.WARNING, "0.0.0.0.0", "CYJ",
                LocalDateTime.now(), "Password incorrect.", "[PLACEHOLDER]");
        UserLogEntry testUserError = new UserLogEntry(LogType.ERROR, "0.0.0.0.0", "CYJ",
                LocalDateTime.now(), "Vault has been locked", "[PLACEHOLDER]");

        System.out.println("USER LOG FORMATTING");
        System.out.println(testUserInfo.toString());
        System.out.println(testUserDebug.toString());
        System.out.println(testUserWarning.toString());
        System.out.println(testUserError.toString());
    }

    @Test
    public void toStringSystemTest() throws Exception {
        SystemLogEntry testSystemInfo = new SystemLogEntry(LogType.INFO, "CYJ",
                LocalDateTime.now(), "Logged In", "[PLACEHOLDER]");
        SystemLogEntry testSystemDebug = new SystemLogEntry(LogType.DEBUG, "CYJ",
                LocalDateTime.now(), "Vault Configuration Error", "[PLACEHOLDER]");
        SystemLogEntry testSystemWarning = new SystemLogEntry(LogType.WARNING, "CYJ",
                LocalDateTime.now(), "Password incorrect.", "[PLACEHOLDER]");
        SystemLogEntry testSystemError = new SystemLogEntry(LogType.ERROR, "CYJ",
                LocalDateTime.now(), "Vault has been locked", "[PLACEHOLDER]");

        System.out.println("SYSTEM LOG FORMATTING");
        System.out.println(testSystemInfo.toString());
        System.out.println(testSystemDebug.toString());
        System.out.println(testSystemWarning.toString());
        System.out.println(testSystemError.toString());
    }
}
