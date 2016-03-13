package vault5431;

import org.apache.commons.csv.CSVRecord;
import org.junit.Test;
import vault5431.logging.CSVUtils;

import static org.junit.Assert.*;

/**
 * Created by papacharlie on 2016-02-27.
 */
public class UtilsTest {

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

}
