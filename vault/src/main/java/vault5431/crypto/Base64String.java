package vault5431.crypto;

import vault5431.FileUtils;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;

import static org.bouncycastle.util.Arrays.concatenate;

/**
 * Base64 utils class. All crypto algorithms either expect such a string, or output such a string.
 */
public class Base64String {

    private byte[] b64data;
//    private static String charset = "UTF-8";

    public Base64String(String data) {
        b64data = Base64.getUrlEncoder().encode(data.getBytes());
    }

    public Base64String(byte[] data) {
        b64data = Base64.getUrlEncoder().encode(data);
    }

    public byte[] getB64Bytes() {
        return b64data.clone();
    }

    public String decodeString() {
        return new String(Base64.getUrlDecoder().decode(b64data));
    }

    public byte[] decodeBytes() {
        return Base64.getUrlDecoder().decode(b64data);
    }

    public int size() {
        return b64data.length;
    }

    private void setB64data(byte[] b64data) {
        this.b64data = b64data;
    }

    public static Base64String fromBase64(byte[] b64data) {
        Base64String b46 = new Base64String(new byte[0]);
        b46.setB64data(b64data);
        return b46;
    }

    public int hashCode() {
        return Arrays.hashCode(b64data);
    }

    public boolean equals(Object other) {
        if (other instanceof Base64String) {
            Base64String other64 = (Base64String)other;
            return Arrays.equals(other64.getB64Bytes(), this.b64data);
        } else {
            return false;
        }
    }

    public Base64String append(Base64String other) {
        b64data = concatenate(b64data, other.getB64Bytes());
        return this;
    }

    /**
     * For use in filenames.
     * From: http://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
     *
     * @return
     */
    public String asHexString() {
        char[] hexArray = "0123456789abcdef".toCharArray();
        char[] hexChars = new char[b64data.length * 2];
        for (int j = 0; j < b64data.length; j++) {
            int v = b64data[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public void saveToFile(String path) throws IOException {
        FileUtils.write(path, b64data);
    }

    public static Base64String loadFromFile(String path) throws IOException {
        return Base64String.fromBase64(FileUtils.read(path));
    }

    public static Base64String empty() {
        return fromBase64(new byte[0]);
    }
}
