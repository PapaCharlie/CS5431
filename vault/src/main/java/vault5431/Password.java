package vault5431;

import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
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

    // Tested with sjcl: 500 characters dumps to a JSON string shorter than 900 characters.
    public static final int MAX_ENCRYPTED_LENGTH = 1000;

    private String name;
    private String url;
    private String username;
    private String password;
    private UUID uuid;

    public Password(String name, String url, String username, String password, UUID uuid) throws IllegalArgumentException {
        if (0 < name.length() && name.length() < MAX_ENCRYPTED_LENGTH && isValidJSON(name)) {
            this.name = name;
        } else {
            throw new IllegalArgumentException("Website name is too long.");
        }
        if (0 < url.length() && url.length() < MAX_ENCRYPTED_LENGTH && isValidJSON(url)) {
            this.url = url;
        } else {
            throw new IllegalArgumentException("Website URL is too long.");
        }
        if (0 < username.length() && username.length() < MAX_ENCRYPTED_LENGTH && isValidJSON(username)) {
            this.username = username;
        } else {
            throw new IllegalArgumentException("Username is too long.");
        }
        if (0 < password.length() && password.length() < MAX_ENCRYPTED_LENGTH && isValidJSON(password)) {
            this.password = password;
        } else {
            throw new IllegalArgumentException("Password is too long.");
        }
        this.uuid = uuid;
    }

    public Password(String name, String url, String username, String password) throws IllegalArgumentException {
        this(name, url, username, password, UUID.randomUUID());
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
        return uuid.hashCode();
    }

    public boolean equals(Object object) {
        if (object instanceof Password) {
            Password other = (Password) object;
            return name.equals(other.name) &&
                    url.equals(other.url) &&
                    username.equals(other.username) &&
                    password.equals(other.password) &&
                    uuid.equals(other.uuid);
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
        hash.put("name", name);
        hash.put("url", url);
        hash.put("username", username);
        hash.put("password", password);
        hash.put("uuid", uuid.toString());
        return hash;
    }

    public String getName() {
        return name;
    }

    public String getUrl() {
        return url;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public UUID getUUID() {
        return uuid;
    }

    public String toRecord() throws IOException {
        return CSVUtils.makeRecord(name, url, username, password, uuid.toString());
    }

}
