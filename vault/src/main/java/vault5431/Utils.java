package vault5431;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Basic email and username verification methods
 */
public class Utils {

    public static boolean isValidJSON(String data) {
        try {
            new JSONObject(data);
            return true;
        } catch (JSONException err) {
            return false;
        }
    }

}
