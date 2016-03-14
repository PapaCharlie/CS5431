package vault5431;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
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

    private static void addFile(String path) {
        r.unlock();
        w.lock();
        try {
            map.putIfAbsent(path, new Object());
        } finally {
            w.unlock();
            r.lock();
        }
    }

    private static void tryRemove(String path) {
        if (w.tryLock()) {
            try {
                map.remove(path);
            } finally {
                w.unlock();
            }
        }
    }

    public static byte[] read(String path) throws IOException {
        r.lock();
        try {
            while (!map.containsKey(path)) {
                addFile(path);
            }
            synchronized (map.get(path)) {
                try(FileInputStream in = new FileInputStream(new File(path))) {
                    byte[] data = new byte[in.available()];
                    in.read(data);
                    return data;
                }
            }
        } finally {
            r.unlock();
            tryRemove(path);
        }
    }

    private static void write(String path, byte[] data, boolean append) throws IOException {
        r.lock();
        try {
            while (!map.containsKey(path)) {
                addFile(path);
            }
            synchronized (map.get(path)) {
                try (FileWriter out = new FileWriter(new File(path), append)) {
                    for (byte b : data) {
                        out.write(b);
                    }
                    out.flush();
                }
            }
        } finally {
            r.unlock();
            tryRemove(path);
        }
    }

    public static void write(String path, byte[] data) throws IOException {
        write(path, data, false);
    }

    public static void append(String path, byte[] data) throws IOException {
        write(path, data, true);
    }

}
