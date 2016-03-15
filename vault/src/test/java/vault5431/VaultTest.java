package vault5431;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.util.LinkedList;

import static org.apache.commons.io.FileUtils.deleteDirectory;

/**
 * All test classes should extend this class.
 */
public class VaultTest {

    private static LinkedList<String> createdUsers = new LinkedList<>();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static File getTempFile(String prefix, String suffix) throws IOException {
        File tmp = File.createTempFile(prefix, suffix);
        tmp.deleteOnExit();
        return tmp;
    }

    public static File getTempFile(String prefix) throws IOException {
        File tmp = File.createTempFile(prefix, null);
        tmp.deleteOnExit();
        return tmp;
    }

    public static User getTempUser(String password) throws Exception {
        String username = PasswordGenerator.generatePassword(10);
        while (User.userExists(username)) {
            username = PasswordGenerator.generatePassword(10);
        }
        User user = User.create(username, password);
        createdUsers.push(username);
        return user;
    }

    @AfterClass
    public static void deleteCreatedUsers() throws Exception {
        for (String user : createdUsers) {
            deleteDirectory(new File(User.getHome(user)));
        }
    }

}
