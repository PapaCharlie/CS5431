package vault5431.logging;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;

import java.io.IOException;
import java.util.Arrays;

/**
 * Basic CSV utils built upon the Apache Commons CSV classes. Provides functionality to serialize and deserialize
 * arbitrary objects to and from the CSV standard.
 *
 * @author papacharlie
 */
public class CSVUtils {

    /**
     * Returns a String representing the collection in CSV format.
     *
     * @param args collection to serialize into CSV
     * @return The CSV line
     * @throws IOException If the collection cannot be serialized.
     */
    public static String makeRecord(Iterable<?> args) throws IOException {
        StringBuffer record = new StringBuffer();
        CSVPrinter printer = new CSVPrinter(record, CSVFormat.DEFAULT);
        printer.printRecord(args);
        printer.flush();
        printer.close();
        return record.toString();
    }

    /**
     * Returns a String representing the parameters in CSV format.
     * @param args parameters to serialize into one CSV line
     * @return The CSV line
     * @throws IOException If the parameters cannot be serialized.
     */
    public static String makeRecord(Object... args) throws IOException {
        return makeRecord(Arrays.asList(args));
    }

    /**
     * Parse a CSV line or lines.
     * @param record CSV data to parse
     * @return The set of CSV lines parsed from the record.
     * @throws IOException If the record cannot be parsed.
     */
    public static CSVParser parseRecord(String record) throws IOException {
        return CSVParser.parse(record, CSVFormat.DEFAULT);
    }

}
