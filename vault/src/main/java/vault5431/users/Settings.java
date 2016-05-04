package vault5431.users;

import org.json.JSONException;
import org.json.JSONObject;
import vault5431.crypto.SymmetricUtils;
import vault5431.crypto.exceptions.BadCiphertextException;
import vault5431.io.Base64String;
import vault5431.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.util.regex.Pattern;

import static vault5431.Vault.getAdminEncryptionKey;

/**
 * User settings class. Contains misc information about the user.
 *
 * @author papacharlie
 */
public final class Settings {

    private String phoneNumber;
    private int concurrentSessions;
    private int sessionLength;

    /**
     * Create a new Settings instance.
     *
     * @param phoneNumber        the user's phone number
     * @param concurrentSessions the maximum number of allowed concurrent tokens
     * @param sessionLength      the maximum time to live for tokens
     */
    public Settings(String phoneNumber, int concurrentSessions, int sessionLength) throws IllegalArgumentException {
        if (Pattern.matches("\\d{3}-\\d{3}-\\d{4}", phoneNumber)) {
            this.phoneNumber = phoneNumber;
        } else {
            throw new IllegalArgumentException("This phone number is not valid!");
        }
        if (0 < concurrentSessions && concurrentSessions <= 20) {
            this.concurrentSessions = concurrentSessions;
        } else {
            throw new IllegalArgumentException("Number of concurrent sessions must be between 1 and 20!");
        }
        if (1 < sessionLength && sessionLength <= 60 * 24) {
            this.sessionLength = sessionLength;
        } else {
            throw new IllegalArgumentException("Session length must be between 2 minutes and 24 hours!");
        }
    }

    public Settings(String phoneNumber) {
        this(phoneNumber, 5, 60);
    }

    protected static Settings loadFromFile(File settingsFile) throws IOException, IllegalArgumentException, BadCiphertextException {
        return fromJSON(new String(SymmetricUtils.decrypt(FileUtils.read(settingsFile)[0], getAdminEncryptionKey())));
    }

    public static Settings fromJSON(JSONObject json) throws IllegalArgumentException {
        if (json.has("phoneNumber") && json.has("concurrentSessions") && json.has("sessionLength")) {
            try {
                return new Settings(
                        json.getString("phoneNumber"),
                        json.getInt("concurrentSessions"),
                        json.getInt("sessionLength")
                );
            } catch (JSONException err) {
                throw new IllegalArgumentException("All fields must be of valid type.");
            }
        } else {
            throw new IllegalArgumentException("All fields required.");
        }
    }

    public static Settings fromJSON(String json) throws IllegalArgumentException {
        try {
            return fromJSON(new JSONObject(json));
        } catch (JSONException err) {
            throw new IllegalArgumentException("Invalid JSON.");
        }
    }

    public static Settings fromJSON(Base64String json) throws IllegalArgumentException {
        return fromJSON(json.decodeString());
    }

    public int getConcurrentSessions() {
        return concurrentSessions;
    }

    public int getSessionLength() {
        return sessionLength;
    }

    public Settings withPhoneNumber(String phoneNumber) throws IllegalArgumentException {
        return new Settings(phoneNumber, this.concurrentSessions, this.sessionLength); // Let constructor validate fields
    }

    public Settings withConcurrentSessions(int concurrentSessions) throws IllegalArgumentException {
        return new Settings(this.phoneNumber, concurrentSessions, this.sessionLength); // Let constructor validate fields
    }

    public Settings withSessionLength(int sessionLength) throws IllegalArgumentException {
        return new Settings(this.phoneNumber, this.concurrentSessions, sessionLength); // Let constructor validate fields
    }

    protected void saveToFile(File settingsFile) throws IOException, BadCiphertextException {
        FileUtils.write(settingsFile, SymmetricUtils.encrypt(toJson().getBytes(), getAdminEncryptionKey()));
    }

    public JSONObject toJSONObject() {
        JSONObject json = new JSONObject();
        json.put("phoneNumber", phoneNumber);
        json.put("concurrentSessions", concurrentSessions);
        json.put("sessionLength", sessionLength);
        return json;
    }

    public String toJson() {
        return toJSONObject().toString();
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }
}
