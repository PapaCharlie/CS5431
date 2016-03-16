package vault5431.io;

import java.io.File;
import java.io.IOException;
import java.util.Base64;

/**
 * Base64 utils class. All crypto algorithms either expect such a string, or output such a string.
 */
public class Base64String {

    private String b64String;
//    private static String charset = "UTF-8";

    public Base64String(String data) {
        this(data.getBytes());
    }

    public Base64String(byte[] data) {
        b64String = Base64.getUrlEncoder().encodeToString(data);
    }

    public static Base64String fromBase64(byte[] b64data) {
        Base64String b46 = new Base64String(new byte[0]);
        b46.setB64data(b64data);
        return b46;
    }

    public static Base64String fromBase64(String b64data) {
        return fromBase64(b64data.getBytes());
    }

    public static Base64String[] loadFromFile(File file) throws IOException {
        return FileUtils.read(file);
    }

    public static Base64String empty() {
        return fromBase64(new byte[0]);
    }

    public byte[] getB64Bytes() {
        return b64String.getBytes();
    }

    public String getB64String() {
        return b64String;
    }

    public String decodeString() {
        return new String(Base64.getUrlDecoder().decode(b64String));
    }

    public byte[] decodeBytes() {
        return Base64.getUrlDecoder().decode(b64String);
    }

    public int length() {
        return b64String.length();
    }

    private void setB64data(byte[] b64data) {
        this.b64String = new String(b64data);
    }

    public int hashCode() {
        return b64String.hashCode();
    }

    public boolean equals(Object other) {
        if (other instanceof Base64String) {
            Base64String other64 = (Base64String) other;
            return b64String.equals(other64.getB64String());
        } else {
            return false;
        }
    }

    public void saveToFile(File file) throws IOException {
        FileUtils.write(file, this);
    }
}
