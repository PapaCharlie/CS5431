package vault5431.io;

import java.io.*;
import java.util.LinkedList;

/**
 * Provides basic file I/O utilities.
 * WARNING: DOES NOT SYNCHRONIZE FILE ACCESS
 *
 * @author papacharlie
 */
public class FileUtils {

    /**
     * Read a collection of {@link Base64String}s from a file.
     * @param file file from which to read the Base64Strings
     * @return The collection of Base64Strings read.
     * @throws IOException If the file cannot be read.
     */
    public static Base64String[] read(File file) throws IOException {
        LinkedList<Base64String> lines = new LinkedList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                lines.add(Base64String.fromBase64(line.trim().replace("\n", "").replace("\r", "")));
            }
            while (lines.peekFirst() != null && lines.getFirst().size() == 0) {
                lines.removeFirst();
            }
            while (lines.peekFirst() != null && lines.getLast().size() == 0) {
                lines.removeLast();
            }
            return lines.toArray(new Base64String[lines.size()]);
        }
    }

    /**
     * Empty the contents of a file.
     * @param file file to empty
     * @throws IOException If the file cannot be written to.
     */
    public static void empty(File file) throws IOException {
        write(file, new byte[0], false);
    }

    /**
     * Write data to a file.
     * @param file file to write the data to
     * @param data data to write
     * @param append whether or not the data should be appended to the file, or if the file should be overwritten
     * @throws IOException If the file cannot be written to.
     */
    private static void write(File file, byte[] data, boolean append) throws IOException {
        try (FileWriter out = new FileWriter(file, append)) {
            for (byte b : data) {
                out.write(b);
            }
            out.flush();
            out.close();
        }
    }

    /**
     * Overwrite a file's data.
     * @param file file to overwrite
     * @param data data to write
     * @throws IOException If the file cannot be written to.
     */
    public static void write(File file, Base64String data) throws IOException {
        write(file, data.getB64Bytes(), false);
    }

    /**
     * Append to a file, and finish with a newline.
     * @param file file to write to
     * @param data data to append
     * @throws IOException If the file cannot be written to.
     */
    public static void append(File file, Base64String data) throws IOException {
        write(file, data.getB64Bytes(), true);
        write(file, "\n".getBytes(), true);
    }

}
