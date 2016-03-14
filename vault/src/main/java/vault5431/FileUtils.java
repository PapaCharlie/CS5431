package vault5431;

import vault5431.crypto.Base64String;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Will slowly grow to contain all files.
 */
public class FileUtils {

    public static Base64String read(File file) throws IOException {
        try (FileInputStream in = new FileInputStream(file)) {
            byte[] data = new byte[in.available()];
            in.read(data);
            return Base64String.fromBase64(data);
        }
    }

    private static void write(File file, byte[] data, boolean append) throws IOException {
        try (FileWriter out = new FileWriter(file, append)) {
            for (byte b : data) {
                out.write(b);
            }
            out.flush();
        }
    }

    public static void write(File file, byte[] data) throws IOException {
        write(file, data, false);
    }

    public static void write(File file, Base64String data) throws IOException {
        write(file, data.getB64Bytes(), false);
    }

    public static void write(File file, String data) throws IOException {
        write(file, new Base64String(data));
    }

    public static void append(File file, byte[] data) throws IOException {
        write(file, data, true);
    }

    public static void append(File file, Base64String data) throws IOException {
        append(file, data.getB64Bytes());
    }

    public static void append(File file, String data) throws IOException {
        append(file, new Base64String(data));
    }

}
