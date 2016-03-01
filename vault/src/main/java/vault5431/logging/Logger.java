package vault5431.logging;

import vault5431.crypto.Base64String;

import java.io.File;
import java.io.IOError;
import java.security.Key;

/**
 * Abstract logger class. All loggers must extend this class. Provides basic append functionality.
 * TODO: Everything
 */
abstract class Logger {

    private File logFile;
    private Key logKey;

    private byte[] encryptEntry(Base64String message) {
        // TODO
        return null;
    }

    public Base64String[] readLog() throws IOError {
        // TODO
        return null;
    }

    public synchronized void warning(String message, String... args) throws IOError {
        // TODO
    }

    public synchronized void info(String message, String... args) throws IOError {
        // TODO
    }

    public synchronized void debug(String message, String... args) throws IOError {
        // TODO
    }

    public synchronized void error(String message, String... args) throws IOError {
        // TODO
    }

}
