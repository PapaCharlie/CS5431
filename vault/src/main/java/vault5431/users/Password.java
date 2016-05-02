package vault5431.users;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import vault5431.io.Base64String;

import java.util.UUID;

/**
 * Password class. Represents an entry in the password vault.
 */
public class Password {

    /**
     * Tested with sjcl: sjcl encrypts a 500 character string to a JSON object shorter than 750 characters.
     */
    protected static final int MAX_ENCRYPTED_LENGTH = 750;

    private JSONObject name;
    private JSONObject url;
    private JSONObject username;
    private JSONObject password;
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
    private Password(String name, String url, String username, String password, UUID id) throws IllegalArgumentException {
        try {
            if (0 < name.length() && name.length() < MAX_ENCRYPTED_LENGTH) {
                this.name = new JSONObject(name);
            } else {
                throw new IllegalArgumentException("Website name is too long.");
            }
            if (0 < url.length() && url.length() < MAX_ENCRYPTED_LENGTH) {
                this.url = new JSONObject(url);
            } else {
                throw new IllegalArgumentException("Website URL is too long.");
            }
            if (0 < username.length() && username.length() < MAX_ENCRYPTED_LENGTH) {
                this.username = new JSONObject(username);
            } else {
                throw new IllegalArgumentException("Username is too long.");
            }
            if (0 < password.length() && password.length() < MAX_ENCRYPTED_LENGTH) {
                this.password = new JSONObject(password);
            } else {
                throw new IllegalArgumentException("Password is too long.");
            }
            this.id = id;
        } catch (JSONException err) {
            throw new IllegalArgumentException("All fields must be valid JSON");
        } catch (NullPointerException err) {
            throw new IllegalArgumentException("All fields required");
        }
    }

    /**
     * To be used when creating a new password instance that will be saved to disk. Generates a new unique id.s
     *
     * @param name     Website's name
     * @param url      Website's url
     * @param username Website's username
     * @param password Website's password
     * @throws IllegalArgumentException When any of the fields are empty, or either exceed the max size of 750 characters.
     */
    public Password(String name, String url, String username, String password) throws IllegalArgumentException {
        this(name, url, username, password, UUID.randomUUID());
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
        if (json.has("name") && json.has("url") && json.has("username") && json.has("password") && json.has("id")) {
            return new Password(
                    json.get("name").toString(),
                    json.get("url").toString(),
                    json.get("username").toString(),
                    json.get("password").toString(),
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

    public int hashCode() {
        return id.hashCode();
    }

    public boolean equals(Object object) {
        if (object instanceof Password) {
            Password other = (Password) object;
            return name.equals(other.name)
                    && url.equals(other.url)
                    && username.equals(other.username)
                    && password.equals(other.password)
                    && id.equals(other.id);
        } else {
            return false;
        }
    }

}
