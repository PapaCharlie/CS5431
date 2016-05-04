package vault5431.crypto.sjcl;

import org.json.JSONException;
import org.json.JSONObject;
import vault5431.io.Base64String;

import java.util.HashSet;

/**
 * For verifying whether or not data received from the client is indeed of the expected format. SJCL is the client side
 * encryption library that returns JSON object containing the iv, the ciphertext, and in this case the kemtag. This
 * class is used to check if the data was indeed encrypted with ECC by SJCL.
 *
 * @author papacharlie
 */
public final class SJCLAsymmetricField extends JSONObject {

    public SJCLAsymmetricField(String field, int maxlength) throws JSONException {
        super(field);
        if (!has("iv") || !has("ct") || !has("kemtag")) {
            throw new IllegalArgumentException("All SJCL fields are required.");
        }
        new HashSet<>(keySet()).forEach((key) -> {
            if (!(key.equals("iv") || key.equals("ct") || key.equals("kemtag"))) {
                remove(key);
            }
        });
        int kemtag = new Base64String(getString("kemtag")).decodeBytes().length;
        if (kemtag != 128) {
            throw new IllegalArgumentException("kemtag is not 128 bytes long.");
        }
        int iv = new Base64String(getString("iv")).decodeBytes().length;
        if (iv != 24) {
            throw new IllegalArgumentException("iv is not 24 bytes long.");
        }
        int ct = new Base64String(getString("ct")).decodeBytes().length;
        if (ct % 4 != 0) {
            throw new IllegalArgumentException("Invalid encrypted text.");
        }
        if (ct > maxlength) {
            throw new IllegalArgumentException("Encrypted text is too long!");
        }
    }

}