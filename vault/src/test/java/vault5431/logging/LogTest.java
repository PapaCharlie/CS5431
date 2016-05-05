package vault5431.logging;

import org.junit.Test;
import vault5431.Sys;

import java.time.LocalDateTime;

import static org.junit.Assert.*;

/**
 * Created by CYJ on 3/14/16.
 */
public class LogTest {
    @Test
    public void toStringUserTest() throws Exception {
        UserLogEntry testUserInfo = new UserLogEntry(LogType.INFO, "0.0.0.0.0", "CYJ",
                LocalDateTime.now(), "Logged In");
        UserLogEntry testUserDebug = new UserLogEntry(LogType.DEBUG, "0.0.0.0.0", "CYJ",
                LocalDateTime.now(), "Vault Configuration Error");
        UserLogEntry testUserWarning = new UserLogEntry(LogType.WARNING, "0.0.0.0.0", "CYJ",
                LocalDateTime.now(), "Password incorrect.");
        UserLogEntry testUserError = new UserLogEntry(LogType.ERROR, "0.0.0.0.0", "CYJ",
                LocalDateTime.now(), "Vault has been locked");

        System.out.println("USER LOG FORMATTING");
        System.out.println(testUserInfo.toString());
        System.out.println(testUserDebug.toString());
        System.out.println(testUserWarning.toString());
        System.out.println(testUserError.toString());

        assertEquals(testUserDebug, UserLogEntry.fromCSV(CSVUtils.parseRecord(testUserDebug.toCSV()).getRecords().get(0)));
        assertEquals(testUserError, UserLogEntry.fromCSV(CSVUtils.parseRecord(testUserError.toCSV()).getRecords().get(0)));
        assertEquals(testUserWarning, UserLogEntry.fromCSV(CSVUtils.parseRecord(testUserWarning.toCSV()).getRecords().get(0)));
        assertEquals(testUserInfo, UserLogEntry.fromCSV(CSVUtils.parseRecord(testUserInfo.toCSV()).getRecords().get(0)));

    }

    @Test
    public void toStringSystemTest() throws Exception {
        SystemLogEntry testSystemInfo = new SystemLogEntry(LogType.INFO, Sys.NO_IP, Sys.SYS,
                LocalDateTime.now(), "Logged In", "[PLACEHOLDER]");
        SystemLogEntry testSystemDebug = new SystemLogEntry(LogType.DEBUG, Sys.NO_IP, Sys.SYS,
                LocalDateTime.now(), "Vault Configuration Error", "[PLACEHOLDER]");
        SystemLogEntry testSystemWarning = new SystemLogEntry(LogType.WARNING, Sys.NO_IP, Sys.SYS,
                LocalDateTime.now(), "Password incorrect.", "[PLACEHOLDER]");
        SystemLogEntry testSystemError = new SystemLogEntry(LogType.ERROR, Sys.NO_IP, Sys.SYS,
                LocalDateTime.now(), "Vault has been locked", "[PLACEHOLDER]");

        System.out.println("SYSTEM LOG FORMATTING");
        System.out.println(testSystemInfo.toString());
        System.out.println(testSystemDebug.toString());
        System.out.println(testSystemWarning.toString());
        System.out.println(testSystemError.toString());

        assertEquals(testSystemDebug, SystemLogEntry.fromCSV(CSVUtils.parseRecord(testSystemDebug.toCSV()).getRecords().get(0)));
        assertEquals(testSystemError, SystemLogEntry.fromCSV(CSVUtils.parseRecord(testSystemError.toCSV()).getRecords().get(0)));
        assertEquals(testSystemWarning, SystemLogEntry.fromCSV(CSVUtils.parseRecord(testSystemWarning.toCSV()).getRecords().get(0)));
        assertEquals(testSystemInfo, SystemLogEntry.fromCSV(CSVUtils.parseRecord(testSystemInfo.toCSV()).getRecords().get(0)));
    }
}
