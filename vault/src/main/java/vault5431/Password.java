package vault5431;

import vault5431.logging.CSVUtils;

import java.io.IOException;

/**
 * Created by papacharlie on 2/26/16.
 */
public class Password {

    private int maxNameLength = 128;
    private int maxWebsiteLength = 512;
    private int maxUsernameLength = 128;
    private int maxPaswordLength = 256;

    private String name;
    private String website;
    private String username;
    private String password;

    Password(String name, String website, String username, String password) {
        this.name = name;
        this.website = website;
        this.username = username;
        this.password = password;
    }

    public String toEntry() throws IOException {
        return CSVUtils.makeRecord(name, website, username, password);
    }

}
