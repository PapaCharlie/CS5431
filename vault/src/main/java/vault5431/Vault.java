package vault5431;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import vault5431.crypto.PasswordUtils;
import vault5431.io.Base64String;
import vault5431.routes.Routes;
import vault5431.users.User;
import vault5431.users.UserManager;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.security.Security;

import static spark.Spark.*;


public class Vault {

    public static final File home = new File(System.getProperty("user.home"), ".vault5431");
    private static final String demoUsername = "demoUser";
    private static final String demoPassword = "password";
    public static User demoUser;
    public static SecretKey adminSigningKey;
    public static SecretKey adminEncryptionKey;

    private static void initialize() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        if (!home.exists()) {
            if (!home.mkdir()) {
                java.lang.System.err.println("Could not create ~/.vault5431 home!");
                java.lang.System.exit(2);
            }
        } else if (home.exists() && !home.isDirectory()) {
            if (!home.delete() && !home.mkdir()) {
                java.lang.System.err.println("Could not create ~/.vault5431 home!");
                java.lang.System.exit(2);
            }
        }
        if (!Sys.logFile.exists()) {
            try {
                if (!Sys.logFile.createNewFile()) {
                    java.lang.System.err.printf("Could not create system log file at %s!%n", Sys.logFile.getAbsoluteFile());
                    java.lang.System.exit(2);
                }
            } catch (IOException err) {
                err.printStackTrace();
                java.lang.System.err.printf("Could not create system log file at %s!%n", Sys.logFile.getAbsoluteFile());
                java.lang.System.exit(2);
            }
        }
        File adminSaltFile = new File(home, "admin.salt");
        if (!adminSaltFile.exists()) {
            System.out.println("Could not find the admin salt file. This either means the system was compromised, or never initialized.");
            System.out.print("Press enter to initialize.");
            System.console().readLine();
            try {
                new Base64String(PasswordUtils.generateSalt()).saveToFile(adminSaltFile);
            } catch (IOException err) {
                err.printStackTrace();
                System.exit(1);
            }
        }
        try {
            byte[] adminSalt = Base64String.loadFromFile(adminSaltFile)[0].decodeBytes();
            System.out.print("Please enter the admin password: ");
            String adminPassword = "debug";
            adminSigningKey = PasswordUtils.deriveKey(adminPassword + "signing", adminSalt);
            adminEncryptionKey = PasswordUtils.deriveKey(adminPassword + "encryption", adminSalt);
        } catch (IOException err) {
            err.printStackTrace();
            System.err.println("Could not load admin salt from file, or could not derive keys from admin password!");
            System.exit(1);
        }
        UserManager.initialize();
        if (!UserManager.userExists(demoUsername)) {
            try {
                UserManager.create(demoUsername);
            } catch (Exception err) {
                err.printStackTrace();
                System.err.println("Could not create demo user!");
                System.exit(1);
            }
        }
        demoUser = UserManager.getUser(demoUsername);
    }

    public static void main(String[] args) throws Exception {
        initialize();
        port(5431);

        System.out.print("Please enter the SSL certificate password:");
        secure("./keystore.jks", "vault5431", null, null);

        Routes.initialize();
        awaitInitialization();

        System.out.println("Hosting at: https://localhost:5431");
    }

}
