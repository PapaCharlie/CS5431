package vault5431;

import vault5431.crypto.Base64String;

import java.io.*;
import java.util.LinkedList;

/**
 *
 */
public class FileUtils {

    public static Base64String[] read(File file) throws IOException {
        LinkedList<Base64String> lines = new LinkedList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                lines.add(Base64String.fromBase64(line.trim()));
            }
            System.out.printf("Read %d lines from %s. \n", lines.size(), file.getCanonicalFile());
            while (lines.getFirst().decodeString().length() == 0) {
                lines.removeFirst();
            }
            while (lines.getLast().decodeString().length() == 0) {
                lines.removeLast();
            }
            return lines.toArray(new Base64String[lines.size()]);
        }
    }

    private static void write(File file, byte[] data, boolean append) throws IOException {
        try (FileWriter out = new FileWriter(file, append)) {
            for (byte b : data) {
                out.write(b);
            }
            System.out.printf("Wrote %d bytes to %s. \n", data.length, file.getCanonicalFile());
            out.flush();
        }
    }

    public static void write(File file, Base64String data) throws IOException {
        write(file, data.getB64Bytes(), false);
    }

    public static void append(File file, Base64String data) throws IOException {
        write(file, data.getB64Bytes(), true);
        write(file, "\n".getBytes(), true);
    }

}