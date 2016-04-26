package vault5431.users;

import org.json.JSONException;
import org.json.JSONObject;
import vault5431.crypto.SymmetricUtils;
import vault5431.crypto.exceptions.BadCiphertextException;
import vault5431.io.Base64String;
import vault5431.io.FileUtils;

import java.io.File;
import java.io.IOException;

import static vault5431.Vault.getAdminEncryptionKey;

/**
 * Created by papacharlie on 2016-04-26.
 */
public class Settings {

    private final int concurrentSessions;
    private final int sessionLength;

    public Settings(int concurrentSessions, int sessionLength) throws IllegalArgumentException {
        if (0 < concurrentSessions && concurrentSessions <= 20) {
            this.concurrentSessions = concurrentSessions;
        } else {
            throw new IllegalArgumentException("Number of concurrent sessions must be between 1 and 20!");
        }
        if (0 < sessionLength && sessionLength <= 60 * 24) {
            this.sessionLength = sessionLength;
        } else {
            throw new IllegalArgumentException("Session length must be between 1 minute and 24 hours!");
        }
    }

    public Settings() {
        this(5, 60);
    }

    public int getConcurrentSessions() {
        return concurrentSessions;
    }

    public int getSessionLength() {
        return sessionLength;
    }

    public void saveToFile(File settingsFile) throws IOException, BadCiphertextException {
        FileUtils.write(settingsFile, SymmetricUtils.encrypt(toJson().getBytes(), getAdminEncryptionKey()));
    }

    public static Settings loadFromFile(File settingsFile) throws IOException, IllegalArgumentException, BadCiphertextException {
        return fromJSON(new String(SymmetricUtils.decrypt(FileUtils.read(settingsFile)[0], getAdminEncryptionKey())));
    }

    public String toJson() {
        JSONObject json = new JSONObject();
        json.put("concurrentSessions", concurrentSessions);
        json.put("sessionLength", sessionLength);
        return json.toString();
    }

    public static Settings fromJSON(JSONObject json) throws IllegalArgumentException {
        if (json.has("concurrentSessions") && json.has("sessionLength")) {
            try {
                return new Settings(
                        json.getInt("concurrentSessions"),
                        json.getInt("sessionLength")
                );
            } catch (JSONException err) {
                throw new IllegalArgumentException("All fields must be integers.");
            }
        } else {
            throw new IllegalArgumentException("All fields required");
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

}
