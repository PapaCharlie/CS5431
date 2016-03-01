package vault5431.crypto;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Base64 utils class. All crypto algorithms either expect such a string, or output such a string.
 */
public class Base64String {

    private byte[] b64data;
    private static String charset = "UTF-8";

    public Base64String(String data) throws UnsupportedEncodingException {
        b64data = Base64.getUrlEncoder().encode(data.getBytes(charset));
    }

    public Base64String(byte[] data) {
        b64data = Base64.getUrlEncoder().encode(data);
    }

    public byte[] getBytes() {
        return b64data;
    }

    public byte[] decode() {
        return Base64.getUrlDecoder().decode(b64data);
    }

    public String decodeAsString() throws UnsupportedEncodingException {
        return new String(Base64.getUrlDecoder().decode(b64data), charset);
    }

    private void setB64data(byte[] b64data) {
        this.b64data = b64data;
    }

    public static Base64String fromBase64(byte[] b64data) {
        Base64String empty = new Base64String(new byte[0]);
        empty.setB64data(b64data);
        return empty;
    }

    public boolean equals(Base64String other) {
        return Arrays.equals(other.getBytes(), this.b64data);
    }

}
