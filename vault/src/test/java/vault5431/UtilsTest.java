package vault5431;

import org.apache.commons.csv.CSVRecord;
import org.junit.Test;
import vault5431.crypto.Base64String;
import vault5431.logging.CSVUtils;

import java.io.File;

import static org.junit.Assert.*;

/**
 * Created by papacharlie on 2016-02-27.
 */
public class UtilsTest extends VaultTest {

    @Test
    public void csvUtilsTest() throws Exception {
        Object[] values = new Object[]{1, 2, 3, "Hello! I\'m a bad string with \"\"quotes\'\", and commas\"."};
        String record = CSVUtils.makeRecord(values);
        assertEquals(1, CSVUtils.parseRecord(record).getRecords().size());
        CSVRecord parsedRecord = CSVUtils.parseRecord(record).getRecords().get(0);
        for (int i = 0; i < parsedRecord.size(); i++) {
            assertEquals(values[i].toString(), parsedRecord.get(i));
        }
    }

    @Test
    public void fileTest() throws Exception {
        File tmpFile = File.createTempFile("test", null);
        String line1 = "Hello! I'm a test";
        String line2 = "Hello! I'm another test";
        FileUtils.append(tmpFile, line1);
        FileUtils.append(tmpFile, "\n" + line2);
        String writtenFileContents = FileUtils.read(tmpFile).decodeString();
        String[] lines = writtenFileContents.split("\n");
        assertEquals(line1, lines[0]);
        assertEquals(line2, lines[1]);
    }

    @Test
    public void passwordTest() throws Exception {
        Password password = new Password("Testpass", "https://www.test.com/", "test", "youknowit");
        Password[] passwords = Password.fromCSV(CSVUtils.parseRecord(password.toRecord()));
        assertTrue(passwords.length > 0);
        Password deserialized = passwords[0];
        assertEquals(password.getName(), deserialized.getName());
        assertEquals(password.getWebsite(), deserialized.getWebsite());
        assertEquals(password.getUsername(), deserialized.getUsername());
        assertEquals(password.getPassword(), deserialized.getPassword());
    }

}
