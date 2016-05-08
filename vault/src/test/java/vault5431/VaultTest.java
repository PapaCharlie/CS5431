package vault5431;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import vault5431.crypto.HashUtils;
import vault5431.crypto.PasswordUtils;
import vault5431.crypto.sjcl.SJCLSymmetricField;
import vault5431.io.Base64String;
import vault5431.io.FileUtils;
import vault5431.users.User;
import vault5431.users.UserManager;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.util.LinkedList;

import static org.apache.commons.io.FileUtils.deleteDirectory;
import static vault5431.Vault.home;

/**
 * All test classes should extend this class.
 */
public class VaultTest {

    public static class TempUser {
        public final User user;
        public final String username;
        public final String password;
        TempUser(User user, String username, String password) {
            this.user = user;
            this.username = username;
            this.password = password;
        }
    }

    private static LinkedList<String> createdUsers = new LinkedList<>();

    static {
        Security.addProvider(new BouncyCastleProvider());
        assert Vault.home != null;
    }

    public static File getTempFile(String prefix) throws IOException {
        File tmp = File.createTempFile(prefix, null);
        tmp.deleteOnExit();
        return tmp;
    }

    public static String generateUsername() {
        return PasswordGenerator.generatePassword(10, true, true, true, false, false);
    }

    public static TempUser getTempUser() throws Exception {
        String username = generateUsername();
        String password = PasswordGenerator.generatePassword();
        while (UserManager.userExists(username)) {
            username = generateUsername();
        }
        SJCLSymmetricField empty = new SJCLSymmetricField("{iv: \"0000000000000000000000==\", ct: \"0000000000000000000=\"}", 100);
        UserManager.create(
                username,
                new Base64String(password),
                "123-456-6789", new Base64String(""), empty, new Base64String(""), empty
        );
        createdUsers.push(username);
        return new TempUser(UserManager.getUser(username), username, password);
    }

    @AfterClass
    public static void deleteCreatedUsers() throws Exception {
        for (String user : createdUsers) {
            deleteDirectory(UserManager.getHome(user));
        }
        FileUtils.empty(new File(home, Vault.test ? "testlog" : "log"));
    }

}
