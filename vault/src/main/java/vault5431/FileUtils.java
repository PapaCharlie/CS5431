package vault5431;

import vault5431.crypto.Base64String;

import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Created by papacharlie on 2016-03-13.
 */
public class FileUtils {

    private static final Map<String, Object> map = new TreeMap<>();
    private static final ReentrantReadWriteLock rwl = new ReentrantReadWriteLock();
    private static final Lock r = rwl.readLock();
    private static final Lock w = rwl.writeLock();

    public static byte[] read(String path) throws IOException {
        RandomAccessFile file = new RandomAccessFile(path, "r");
        synchronized (file.getChannel()) {
            try {
                byte[] data = new byte[(int) file.length()];
                file.readFully(data);
                return data;
            } finally {
                file.close();
            }
        }
    }

    private static boolean write(String path, byte[] data, boolean append) throws IOException {
        RandomAccessFile file = new RandomAccessFile(path, "rwd");
        synchronized (file.getChannel()) {
            try {
                if (append) {
                    file.seek(file.length());
                }
                file.write(data);
                file.close();
                return true;
            } finally {
                file.close();
            }
        }
    }

    public static boolean write(String path, byte[] data) throws IOException {
        return write(path, data, false);
    }

    public static boolean append(String path, byte[] data) throws IOException {
        return write(path, data, true);
    }

}
