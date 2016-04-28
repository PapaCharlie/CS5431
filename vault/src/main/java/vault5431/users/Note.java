package vault5431.users;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import vault5431.io.Base64String;

import java.util.UUID;

import static vault5431.users.Password.MAX_ENCRYPTED_LENGTH;

/**
 * Created by papacharlie on 2016-04-28.
 */
public class Note {

    private JSONObject name;
    private JSONObject note;
    private UUID id;

    private Note(String name, String note, UUID id) throws IllegalArgumentException {
        try {
            if (0 < name.length() && name.length() < MAX_ENCRYPTED_LENGTH) {
                this.name = new JSONObject(name);
            } else {
                throw new IllegalArgumentException("Website name is too long.");
            }
            if (0 < note.length() && note.length() < MAX_ENCRYPTED_LENGTH * 4) {
                this.note = new JSONObject(note);
            } else {
                throw new IllegalArgumentException("Website URL is too long.");
            }
            this.id = id;
        } catch (JSONException err) {
            throw new IllegalArgumentException("All fields must be valid JSON");
        } catch (NullPointerException err) {
            throw new IllegalArgumentException("All fields required");
        }
    }

    public Note(String name, String note) throws IllegalArgumentException {
        this(name, note, UUID.randomUUID());
    }

    /**
     * Parses a JSON object ideally created by #toJSONObject, otherwise simply requires all fields be present in the object.
     *
     * @param json JSONObject representing the Note
     * @return Password instance parsed from JSON.
     * @throws IllegalArgumentException Thrown by Note constructor or if JSON object does not contain all required
     *                                  fields.
     */
    public static Note fromJSON(JSONObject json) throws IllegalArgumentException {
        if (json.has("name") && json.has("note") && json.has("id")) {
            return new Note(
                    json.get("name").toString(),
                    json.get("url").toString(),
                    UUID.fromString(json.getString("id"))
            );
        } else {
            throw new IllegalArgumentException("All fields required");
        }
    }

    public static Note fromJSON(String json) throws IllegalArgumentException {
        try {
            return fromJSON(new JSONObject(json));
        } catch (JSONException err) {
            throw new IllegalArgumentException("Invalid JSON");
        }
    }

    public static Note fromJSON(Base64String json) {
        return fromJSON(json.decodeString());
    }

    public static Note[] fromJSON(JSONArray jsonArray) throws IllegalArgumentException {
        try {
            Note[] notes = new Note[jsonArray.length()];
            for (int i = 0; i < notes.length; i++) {
                notes[i] = fromJSON(jsonArray.getJSONObject(i));
            }
            return notes;
        } catch (JSONException | IllegalArgumentException err) {
            throw new IllegalArgumentException("All fields must be valid passwords!");
        }
    }

    /**
     * @return The JSON representation of the Note.
     */
    public JSONObject toJSONObject() {
        JSONObject json = new JSONObject();
        json.put("name", name);
        json.put("note", note);
        json.put("id", id.toString());
        return json;
    }

    public String toJSON() {
        return toJSONObject().toString();
    }

    /**
     * @return The Note's unique ID.
     */
    public UUID getID() {
        return id;
    }

    public int hashCode() {
        return id.hashCode();
    }

    public boolean equals(Object object) {
        if (object instanceof Note) {
            Note other = (Note) object;
            return name.equals(other.name)
                    && note.equals(other.note)
                    && id.equals(other.id);
        } else {
            return false;
        }
    }

}
