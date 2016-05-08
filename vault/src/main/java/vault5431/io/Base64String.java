package vault5431.io;

import org.bouncycastle.util.Arrays;

import java.io.File;
import java.io.IOException;
import java.util.Base64;


/**
 * Base64 utils class. All crypto algorithms either expect such a string, or output such a string.
 *
 * @author papacharlie
 */
public final class Base64String {

    private String b64String;

    /**
     * Create a new Base64String instance.
     *
     * @param data string to translate to Base64
     */
    public Base64String(String data) {
        this(data.getBytes());
    }

    /**
     * Create a new Base64String instance.
     *
     * @param data bytes to translate to Base64
     */
    public Base64String(byte[] data) {
        b64String = Base64.getUrlEncoder().encodeToString(data);
    }

    /**
     * Returns a new Base64String instance based on data that is already Base64 encoded.
     * WARNING: calling {@link #decodeBytes()} or {@link #decodeString()} on an instance returned from this method will
     * throw {@link IllegalArgumentException} if the provided data is not Base64.
     *
     * @param b64Bytes data from which the new instance will be created
     * @return New Base64String instance.
     */
    public static Base64String fromBase64(byte[] b64Bytes) {
        if (b64Bytes != null) {
            Base64String base64String = new Base64String(new byte[0]);
            base64String.setB64data(b64Bytes);
            return base64String;
        } else {
            return null;
        }
    }

    /**
     * Calls {@link #fromBase64(byte[])} on the string's bytes.
     *
     * @param b64String string from which the new instance will be created
     * @return New Base64String instance.
     */
    public static Base64String fromBase64(String b64String) {
        if (b64String != null) {
            return fromBase64(b64String.getBytes());
        } else {
            return null;
        }
    }

    /**
     * Returns a collection of Base64String read from each line of a file.
     * WARNING: Does not synchronize file access.
     *
     * @param file file from which to read the Base64Strings
     * @return The collection of Base64Strings loaded from disk
     * @throws IOException If the file cannot be read from.
     */
    public static Base64String[] loadFromFile(File file) throws IOException {
        return FileUtils.read(file);
    }

    /**
     * Returns whether or not the provided data is correct Base64 data.
     *
     * @param data data to check
     * @return true if the data is valid Base64 data.
     */
    public static boolean isValidBase64Data(String data) {
        return Base64String.fromBase64(data).isValidBase64Data();
    }

    /**
     * Same as {@link #isValidBase64Data(String)}.
     *
     * @param data data to check
     * @return true if the data is valid Base64 data.
     */
    public static boolean isValidBase64Data(byte[] data) {
        return Base64String.fromBase64(data).isValidBase64Data();
    }

    private void setB64data(byte[] b64data) {
        this.b64String = new String(b64data);
    }

    /**
     * Save this instance to a file. See {@link #loadFromFile(File)} for reading the result of this method.
     *
     * @param file file to save this instance to
     * @throws IOException If the file cannot be written to.
     */
    public void saveToFile(File file) throws IOException {
        FileUtils.write(file, this);
    }

    public String toString() {
        return getB64String();
    }

    public byte[] getB64Bytes() {
        return b64String.getBytes();
    }

    public String getB64String() {
        return b64String;
    }

    /**
     * Decode the Base64 data and interpret it as a string.
     *
     * @return The String contained in this instance.
     */
    public String decodeString() {
        return new String(decodeBytes());
    }

    /**
     * Decode the raw Base64 bytes.
     *
     * @return The collection of the (Base256, technically) bytes.
     */
    public byte[] decodeBytes() {
        return Base64.getUrlDecoder().decode(b64String);
    }

    /**
     * Returns whether or not the data contained in this instance is correct Base64 data.
     *
     * @return true if the data is valid Base64 data.
     */
    public boolean isValidBase64Data() {
        try {
            decodeString();
            return true;
        } catch (Exception err) {
            return false;
        }
    }

    /**
     * Returns the number of Base64 bytes contained in this instance.
     *
     * @return The number of Base64 bytes.
     */
    public int size() {
        return b64String.length();
    }

    public int hashCode() {
        return b64String.hashCode();
    }

    public boolean equals(Object obj) {
        if (obj instanceof Base64String) {
            Base64String other = (Base64String) obj;
            return b64String.equals(other.getB64String());
        } else {
            return false;
        }
    }

    public void append(Base64String other) {
        this.b64String = new Base64String(Arrays.concatenate(decodeBytes(), other.decodeBytes())).b64String;
    }
}
