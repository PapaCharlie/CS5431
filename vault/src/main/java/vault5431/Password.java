package vault5431;

import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import vault5431.logging.CSVUtils;

import java.io.IOException;
import java.util.List;

/**
 * Created by papacharlie on 2/26/16.
 */
public class Password {

    private static final int MAX_NAME_LENGTH = 128;
    private static final int MAX_WEBSITE_LENGTH = 512;
    private static final int MAX_USERNAME_LENGTH = 128;
    private static final int MAX_PASWORD_LENGTH = 256;

    private String name;
    private String website;
    private String username;
    private String password;

    Password(String name, String website, String username, String password) throws IllegalArgumentException {
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

    public String toRecord() throws IOException {
        return CSVUtils.makeRecord(name, website, username, password);
    }

    private static Password fromRecord(CSVRecord entry) throws IOException {
        return new Password(
                entry.get(0),
                entry.get(1),
                entry.get(2),
                entry.get(3)
        );
    }

    public static Password[] fromCSV(CSVParser entries) throws IOException {
        List<CSVRecord> records = entries.getRecords();
        Password[] passwords = new Password[records.size()];
        for (int i = 0; i < passwords.length; i++) {
            passwords[i] = fromRecord(records.get(i));
        }
        return passwords;
    }

}
