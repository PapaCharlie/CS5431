package vault5431.io;

import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Will slowly grow to contain all files.
 */
public class FileUtils {

    private static final Map<String, LockedFile> map = new TreeMap<>();
    private static final ReentrantReadWriteLock rwl = new ReentrantReadWriteLock();
    private static final Lock r = rwl.readLock();
    private static final Lock w = rwl.writeLock();

    public static synchronized LockedFile getLockedFile(String path) {
        try {
            r.lock();
            if (map.containsKey(path)) {
                return map.get(path);
            } else {
                r.unlock();
                w.lock();
                try {
                    return map.put(path, new LockedFile(path));
                } finally {
                    w.unlock();
                }
            }
        } finally {
            r.unlock();
        }
    }
}
