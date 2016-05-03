package vault5431.crypto.sjcl;

import org.json.JSONException;
import org.json.JSONObject;
import vault5431.io.Base64String;

import java.util.HashSet;

/**
 * Created by papacharlie on 2016-05-03.
 */
public final class SJCLSymmetricField extends JSONObject {

    public SJCLSymmetricField(String field, int maxLength, boolean exact) throws JSONException {
        super(field);
        if (!has("iv") || !has("ct")) {
            throw new IllegalArgumentException("All SJCL fields are required.");
        }
        for (String key : new HashSet<>(keySet())) {
            if (!(key.equals("iv") || key.equals("ct"))) {
                remove(key);
            }
        }
        int iv = new Base64String(getString("iv")).decodeBytes().length;
        if (iv != 24) {
            throw new IllegalArgumentException("iv is not 24 bytes long.");
        }
        int ct = new Base64String(getString("ct")).decodeBytes().length;
        if (exact) {
            if (ct != maxLength) {
                throw new IllegalArgumentException("Invalid encrypted text");
            }
        } else {
            if (ct % 4 != 0) {
                throw new IllegalArgumentException("Invalid encrypted text.");
            }
            if (ct > maxLength) {
                throw new IllegalArgumentException("Encrypted text is too long!");
            }
        }
    }

    public SJCLSymmetricField(String field, int maxLength) {
        this(field, maxLength, false);
    }

}