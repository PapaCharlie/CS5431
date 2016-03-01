package vault5431.logging;

import java.io.File;
import java.io.IOError;
import vault5431.crypto.Key;

/**
 * Created by papacharlie on 2/29/16.
 */
abstract class Logger {

    private File logFile;
    private Key logKey;

    public synchronized void warning(String message, String... args) throws IOError {

    }

    public synchronized void info(String message, String... args) throws IOError {

    }

    public synchronized void debug(String message, String... args) throws IOError {

    }

    public synchronized void error(String message, String... args) throws IOError {

    }

}
