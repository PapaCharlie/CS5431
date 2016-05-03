package vault5431;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import vault5431.crypto.HashUtils;
import vault5431.crypto.PasswordUtils;
import vault5431.crypto.sjcl.SJCLSymmetricField;
import vault5431.io.Base64String;
import vault5431.users.User;
import vault5431.users.UserManager;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.util.Base64;
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
        return getTempUser(PasswordGenerator.generatePassword(10), password);
    }

    public static User getTempUser(String username, String password) throws Exception {
        while (UserManager.userExists(username)) {
            username = PasswordGenerator.generatePassword(10);
        }
        SJCLSymmetricField empty = new SJCLSymmetricField("{iv: \"0000000000000000000000==\", ct: \"0000000000000000000=\"}", 100);
        User user = UserManager.create(username, PasswordUtils.hashPassword("auth" + HashUtils.hash256(password.getBytes()).decodeString()), "123-456-6789", new Base64String(""), empty, new Base64String(""), empty);
        createdUsers.push(username);
        return user;
    }

    @AfterClass
    public static void deleteCreatedUsers() throws Exception {
        for (String user : createdUsers) {
            deleteDirectory(UserManager.getHome(user));
        }
    }

}
