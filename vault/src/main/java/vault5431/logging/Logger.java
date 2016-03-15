package vault5431.logging;

import vault5431.crypto.Base64String;

import java.io.IOError;

/**
 * Abstract logger class. All loggers must extend this class. Provides basic append functionality.
 * TODO: Everything
 */
public interface Logger {

    Base64String[] readLog() throws IOError;

    void writeLog() throws IOError;

//    void warning(String message, String... args) throws IOError;
//
//    void info(String message, String... args) throws IOError;
//
//    void debug(String message, String... args) throws IOError;
//
//    void error(String message, String... args) throws IOError;

}
