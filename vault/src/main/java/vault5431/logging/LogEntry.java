package vault5431.logging;

import java.io.IOException;

/**
 * Created by CYJ on 3/14/16.
 * Placeholder in case our Sys Log and User Log begin to deviate significantly but share
 * common functions.
 */
public interface LogEntry {

    boolean checkSignature(String signature);

    String toCSV() throws IOException;

}
