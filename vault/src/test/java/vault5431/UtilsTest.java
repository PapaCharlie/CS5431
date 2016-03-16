package vault5431;

import org.apache.commons.csv.CSVRecord;
import org.junit.Test;
import vault5431.io.Base64String;
import vault5431.io.FileUtils;
import vault5431.logging.CSVUtils;

import java.io.File;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Tests utilities, among other things
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
        File tmpFile = getTempFile("test");
        String line1 = "Hello! I'm a test";
        String line2 = "Hello! I'm another test";
        FileUtils.append(tmpFile, new Base64String(line1));
        FileUtils.append(tmpFile, new Base64String(line2));
        Base64String[] lines = FileUtils.read(tmpFile);
        assertEquals(line1, lines[0].decodeString());
        assertEquals(line2, lines[1].decodeString());
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

    @Test
    public void testBase64StringSave() throws Exception {
        File tmp = getTempFile("b64");
        Base64String base64String = new Base64String("test");
        base64String.saveToFile(tmp);
        Base64String loadedb64 = Base64String.loadFromFile(tmp)[0];
        assertEquals(base64String.getB64String(), loadedb64.getB64String());
    }

    @Test
    public void b64Tests() throws Exception {
        String string = "Hello\nWorld!";
        Base64String b64String = new Base64String(string);
        assertEquals(string, b64String.decodeString());
    }

}
