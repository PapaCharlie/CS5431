package vault5431;

import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.json.JSONException;
import org.json.JSONObject;
import vault5431.logging.CSVUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static vault5431.Utils.isValidJSON;

/**
 * Password class. Represents an entry in the password vault.
 */
public class Password {

    // Tested with sjcl: sjcl encrypts a 500 character string to a JSON object shorter than 750 characters.
    public static final int MAX_ENCRYPTED_LENGTH = 750;

    private JSONObject name;
    private JSONObject url;
    private JSONObject username;
    private JSONObject password;
    private UUID id;

    public Password(String name, String url, String username, String password, UUID id) throws IllegalArgumentException {
        try {
            if (0 < name.length() && name.length() < MAX_ENCRYPTED_LENGTH) {
                this.name = new JSONObject(name);
            } else {
                throw new IllegalArgumentException("Website name is too long.");
            }
            if (0 < url.length() && url.length() < MAX_ENCRYPTED_LENGTH && isValidJSON(url)) {
                this.url = new JSONObject(url);
            } else {
                throw new IllegalArgumentException("Website URL is too long.");
            }
            if (0 < username.length() && username.length() < MAX_ENCRYPTED_LENGTH && isValidJSON(username)) {
                this.username = new JSONObject(username);
            } else {
                throw new IllegalArgumentException("Username is too long.");
            }
            if (0 < password.length() && password.length() < MAX_ENCRYPTED_LENGTH && isValidJSON(password)) {
                this.password = new JSONObject(password);
            } else {
                throw new IllegalArgumentException("Password is too long.");
            }
            this.id = id;
        } catch (JSONException err) {
            throw new IllegalArgumentException("All fields must be valid JSON");
        }
    }

    public Password(String name, String url, String username, String password) throws IllegalArgumentException {
        this(name, url, username, password, UUID.randomUUID());
    }

    public String toJSON() {
        JSONObject json = new JSONObject();
        json.put("name", name);
        json.put("url", url);
        json.put("username", username);
        json.put("password", password);
        json.put("id", id.toString());
        return json.toString();
    }

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

    public int hashCode() {
        return id.hashCode();
    }

    public boolean equals(Object object) {
        if (object instanceof Password) {
            Password other = (Password) object;
            return name.equals(other.name) &&
                    url.equals(other.url) &&
                    username.equals(other.username) &&
                    password.equals(other.password) &&
                    id.equals(other.id);
        } else {
            return false;
        }
    }

    public static Password fromCSVRecord(CSVRecord entry) throws IllegalArgumentException {
        return new Password(
                entry.get(0),
                entry.get(1),
                entry.get(2),
                entry.get(3),
                UUID.fromString(entry.get(4))
        );
    }

    public static Password[] fromCSV(CSVParser entries) throws IOException {
        List<CSVRecord> records = entries.getRecords();
        Password[] passwords = new Password[records.size()];
        for (int i = 0; i < passwords.length; i++) {
            passwords[i] = fromCSVRecord(records.get(i));
        }
        return passwords;
    }

    public Map<String, String> toMap() {
        Map<String, String> hash = new HashMap<>();
        hash.put("name", name.toString());
        hash.put("url", url.toString());
        hash.put("username", username.toString());
        hash.put("password", password.toString());
        hash.put("id", id.toString());
        return hash;
    }

    public UUID getID() {
        return id;
    }

    public String toRecord() throws IOException {
        return CSVUtils.makeRecord(name, url, username, password, id.toString());
    }

}
