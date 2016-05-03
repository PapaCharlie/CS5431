package vault5431.users;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import vault5431.io.Base64String;

import java.util.HashSet;
import java.util.UUID;

/**
 * Password class. Represents an entry in the password vault.
 *
 * @author papacharlie
 */
public final class Password {


    private static final class SJCLObject extends JSONObject {

        SJCLObject(String field, int maxLength) throws JSONException {
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
            if (ct % 4 != 0) {
                throw new IllegalArgumentException("Invalid encrypted text.");
            }
            if (ct > maxLength) {
                throw new IllegalArgumentException("Encrypted text is too long!");
            }
        }

    }

    private SJCLObject name;
    private SJCLObject url;
    private SJCLObject username;
    private SJCLObject password;
    private SJCLObject notes;
    private UUID id;

    /**
     * Creates a new Password instance. This constructor limits the total stored size of the instance. Used when loading
     * instances from disk.
     *
     * @param name     Website's name
     * @param url      Website's url
     * @param username Website's username
     * @param password Website's password
     * @param id       Unique id for indexing server/client side
     * @throws IllegalArgumentException When any of the fields are empty, or either exceed the max size of 750 characters.
     */
    private Password(String name, String url, String username, String password, String notes, UUID id) throws IllegalArgumentException {
        try {
            this.name = new SJCLObject(name, 150); // 100 char limit
            this.url = new SJCLObject(url, 512);
            this.username = new SJCLObject(username, 150);
            this.password = new SJCLObject(password, 150);
            this.notes = new SJCLObject(notes, 1350); // 1000 char limit
            this.id = id;
        } catch (JSONException err) {
            throw new IllegalArgumentException("All fields must be valid JSON");
        } catch (NullPointerException err) {
            throw new IllegalArgumentException("All fields required");
        }
    }

    /**
     * Parses a JSON object ideally created by {@link #toJSONObject}, otherwise simply requires all fields be present in the object.
     *
     * @param json JSONObject representing the Password
     * @return Password instance parsed from JSON.
     * @throws IllegalArgumentException Thrown by Password constructor or if JSON object does not contain all required
     *                                  fields.
     */
    public static Password fromJSON(JSONObject json) throws IllegalArgumentException {
        if (json.has("name") && json.has("url") && json.has("username") && json.has("password") && json.has("id") && json.has("notes")) {
            return new Password(
                    json.get("name").toString(),
                    json.get("url").toString(),
                    json.get("username").toString(),
                    json.get("password").toString(),
                    json.get("notes").toString(),
                    UUID.fromString(json.getString("id"))
            );
        } else {
            throw new IllegalArgumentException("All fields required");
        }
    }

    public static Password fromJSON(String json) throws IllegalArgumentException {
        try {
            return fromJSON(new JSONObject(json));
        } catch (JSONException err) {
            throw new IllegalArgumentException("Invalid JSON");
        }
    }

    public static Password fromJSON(Base64String json) {
        return fromJSON(json.decodeString());
    }

    public static Password[] fromJSON(JSONArray jsonArray) throws IllegalArgumentException {
        try {
            Password[] passwords = new Password[jsonArray.length()];
            for (int i = 0; i < passwords.length; i++) {
                passwords[i] = fromJSON(jsonArray.getJSONObject(i));
            }
            return passwords;
        } catch (JSONException | IllegalArgumentException err) {
            throw new IllegalArgumentException("All fields must be valid passwords!");
        }
    }

    /**
     * @return The JSON representation of the Password.
     */
    public JSONObject toJSONObject() {
        JSONObject json = new JSONObject();
        json.put("name", name);
        json.put("url", url);
        json.put("username", username);
        json.put("password", password);
        json.put("notes", notes);
        json.put("id", id.toString());
        return json;
    }

    public String toJSON() {
        return toJSONObject().toString();
    }

    /**
     * @return The Password's unique ID.
     */
    public UUID getID() {
        return id;
    }

    protected void newUUID() {
        id = UUID.randomUUID();
    }

    public int hashCode() {
        return id.hashCode();
    }

    public boolean equals(Object obj) {
        if (obj instanceof Password) {
            Password other = (Password) obj;
            return id.equals(other.id);
        } else {
            return false;
        }
    }

}
