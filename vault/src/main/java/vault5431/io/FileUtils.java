package vault5431.io;

import java.io.*;
import java.util.LinkedList;

/**
 * Provides basic file I/O utilities.
 * WARNING: DOES NOT SYNCHRONIZE FILE ACCESS
 */
public class FileUtils {

    public static Base64String[] read(File file) throws IOException {
        LinkedList<Base64String> lines = new LinkedList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                lines.add(Base64String.fromBase64(line.trim().replace("\n", "").replace("\r", "")));
            }
            while (lines.peekFirst() != null && lines.getFirst().length() == 0) {
                lines.removeFirst();
            }
            while (lines.peekFirst() != null && lines.getLast().length() == 0) {
                lines.removeLast();
            }
            return lines.toArray(new Base64String[lines.size()]);
        }
    }

    public static void empty(File file) throws IOException {
        write(file, new byte[0], false);
    }

    private static void write(File file, byte[] data, boolean append) throws IOException {
        try (FileWriter out = new FileWriter(file, append)) {
            for (byte b : data) {
                out.write(b);
            }
            out.flush();
            out.close();
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
