package vault5431;

import org.apache.commons.csv.CSVRecord;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import vault5431.logging.CSVUtils;

import java.io.File;
import java.security.Security;

import static org.junit.Assert.*;

/**
 * Created by papacharlie on 2016-02-27.
 */
public class UtilsTest extends VaultTest {

    @Test
    public void csvUtilsTest() throws Exception {
        Object[] objects = new Object[]{1, 2, 3, "Hello! I\'m a bad string with \"\"quotes\'\", and commas\"."};
        String record = CSVUtils.makeRecord(objects);
        assertEquals(1, CSVUtils.parseRecord(record).getRecords().size());
        CSVRecord parsedRecord = CSVUtils.parseRecord(record).getRecords().get(0);
        for (int i = 0; i < parsedRecord.size(); i++) {
            assertEquals(objects[i].toString(), parsedRecord.get(i));
        }
    }

    @Test
    public void fileTest() throws Exception {
        String tmpFile = File.createTempFile("test", null).getAbsolutePath();
        String line1 = "Hello! I'm a test";
        String line2 = "Hello! I'm another test";
        FileUtils.append(tmpFile, line1.getBytes());
        FileUtils.append(tmpFile, ("\n" + line2).getBytes());
        String writtenFileContents = new String(FileUtils.read(tmpFile));
        String[] lines = writtenFileContents.split("\n");
        assertEquals(line1, lines[0]);
        assertEquals(line2, lines[1]);
    }

}
