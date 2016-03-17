package vault5431;

import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import vault5431.logging.CSVUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Password class. Represents an entry in the password vault.
 */
public class Password {

    public static final int MAX_NAME_LENGTH = 128;
    public static final int MAX_WEBSITE_LENGTH = 512;
    public static final int MAX_USERNAME_LENGTH = 128;
    public static final int MAX_PASWORD_LENGTH = 256;

    private String name;
    private String website;
    private String username;
    private String password;
    private UUID uuid;

    Password(String name, String website, String username, String password, UUID uuid) throws IllegalArgumentException {
        if (name.length() < MAX_NAME_LENGTH) {
            this.name = name;
        } else {
            throw new IllegalArgumentException("Website name is too long.");
        }
        if (website.length() < MAX_WEBSITE_LENGTH) {
            this.website = website;
        } else {
            throw new IllegalArgumentException("Website URL is too long.");
        }
        if (username.length() < MAX_USERNAME_LENGTH) {
            this.username = username;
        } else {
            throw new IllegalArgumentException("Username is too long.");
        }
        if (password.length() < MAX_PASWORD_LENGTH) {
            this.password = password;
        } else {
            throw new IllegalArgumentException("Password is too long.");
        }
        this.uuid = uuid;
    }

    Password(String name, String website, String username, String password) {
        this(name, website, username, password, UUID.randomUUID());
    }

    public int hashCode() {
        return uuid.hashCode();
    }

    public boolean equals(Object object) {
        if (object instanceof Password) {
            Password other = (Password) object;
            return name.equals(other.name) &&
                    website.equals(other.website) &&
                    username.equals(other.username) &&
                    password.equals(other.password) &&
                    uuid.equals(other.uuid);
        } else {
            return false;
        }
    }

    public static Password fromCSV(CSVRecord entry) throws IOException {
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
            passwords[i] = fromCSV(records.get(i));
        }
        return passwords;
    }

    public Map<String, String> toMap() {
        Map<String, String> hash = new HashMap<>();
        hash.put("name", name);
        hash.put("website", website);
        hash.put("username", username);
        hash.put("password", password);
        hash.put("uuid", uuid.toString());
        return hash;
    }

    public String getName() {
        return name;
    }

    public String getWebsite() {
        return website;
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
        return CSVUtils.makeRecord(name, website, username, password, uuid.toString());
    }

}
