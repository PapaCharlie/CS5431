package vault5431;

/**
 * Created by papacharlie on 2/26/16.
 */
public class Password {

    private int maxNameLength = 128;
    private int maxWebsiteLength = 512;
    private int maxUsernameLength = 128;
    private int maxPaswordLength = 256;
    private int passwordEntryLength = maxNameLength + maxPaswordLength + maxUsernameLength + maxWebsiteLength;

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

}
