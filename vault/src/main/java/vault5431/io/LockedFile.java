package vault5431.io;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Created by papacharlie on 2016-03-14.
 */
public final class LockedFile extends File {

    private final Lock lock = new ReentrantLock();

    protected LockedFile(String path) {
        super(path);
    }

    public void lock() {
        lock.lock();
    }

    public void unlock() {
        lock.unlock();
    }

    public byte[] read() throws IOException {
        lock.lock();
        try {
            try (FileInputStream in = new FileInputStream(this)) {
                byte[] data = new byte[in.available()];
                in.read(data);
                return data;
            }

        } finally {
            lock.unlock();
        }
    }

    private void write(byte[] data, boolean append) throws IOException {
        lock.lock();
        try {
            try (FileWriter out = new FileWriter(this, append)) {
                for (byte b : data) {
                    out.write(b);
                }
                out.flush();
            }
        } finally {
            lock.unlock();
        }
    }

    public void write(byte[] data) throws IOException {
        write(data, false);
    }

    public void append(byte[] data) throws IOException {
        write(data, true);
    }


}
