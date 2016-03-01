package vault5431;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;

import java.io.IOException;
import java.util.Arrays;

/**
 * Basic CSV utils built upon the Apache Commons CSV classes
 */
public class CSVUtils {

    public static String makeRecord(Object... args) throws IOException {
        return makeRecord(Arrays.asList(args));
    }


    public static String makeRecord(Iterable<?> args) throws IOException {
        StringBuffer record = new StringBuffer();
        CSVPrinter printer = new CSVPrinter(record, CSVFormat.DEFAULT);
        printer.printRecord(args);
        printer.flush();
        printer.close();
        return record.toString();
    }

    public static CSVParser parseRecord(String record) throws IOException {
        return CSVParser.parse(record, CSVFormat.DEFAULT);
    }

}
