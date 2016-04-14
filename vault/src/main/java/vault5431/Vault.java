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

    protected static final class AdminKeys {
        protected final SecretKey encryptionKey;
        protected final SecretKey signingKey;

        protected AdminKeys(SecretKey encryptionKey, SecretKey signingKey) {
            this.encryptionKey = encryptionKey;
            this.signingKey = signingKey;
        }
    }

    public static final File home = new File(System.getProperty("user.home"), ".vault5431");
    private static final File adminSaltFile = new File(home, "admin.salt");
    private static final String demoUsername = "demoUser";
    private static final String demoPassword = "password";
    private static final String demoPhonenumber = "+16109455656";
    private static final AdminKeys adminKeys = readAdminKeys();
    private static final User demoUser = loadDemoUser();
    private static boolean initialized = false;

    private static AdminKeys readAdminKeys() {
        initialize();
        AdminKeys keys = null;
        try {
            byte[] adminSalt = Base64String.loadFromFile(adminSaltFile)[0].decodeBytes();
            System.out.print("Please enter the admin password: ");
            String adminPassword = new String(System.console().readPassword());
            SecretKey adminSigningKey = PasswordUtils.deriveKey(adminPassword + "signing", adminSalt);
            SecretKey adminEncryptionKey = PasswordUtils.deriveKey(adminPassword + "encryption", adminSalt);
            keys = new AdminKeys(adminEncryptionKey, adminSigningKey);
        } catch (IOException err) {
            err.printStackTrace();
            System.err.println("Could not load admin salt from file, or could not derive keys from admin password!");
            System.exit(1);
        }
        return keys;
    }

    private static User loadDemoUser() {
        initialize();
        if (!UserManager.userExists(demoUsername)) {
            try {
                UserManager.create(demoUsername, PasswordUtils.hashPassword(demoPassword), demoPhonenumber);
            } catch (Exception err) {
                err.printStackTrace();
                System.err.println("Could not create demo user!");
                System.exit(1);
            }
        }
        return UserManager.getUser(demoUsername);
    }


    private synchronized static void initialize() {
        if(initialized) {
            return;
        } else {
            initialized = true;
        }
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

        if (!adminSaltFile.exists()) {
            System.out.println("Could not find the admin salt file. This either means the system was compromised, or never initialized.");
            System.out.print("Press enter to initialize.");
            try {
                new Base64String(PasswordUtils.generateSalt()).saveToFile(adminSaltFile);
            } catch (IOException err) {
                err.printStackTrace();
                System.exit(1);
            }
        }

        UserManager.initialize();
    }

    public static User getDemoUser() {
        return demoUser;
    }

    public static SecretKey getAdminSigningKey() {
        return adminKeys.signingKey;
    }

    public static SecretKey getAdminEncryptionKey() {
        return adminKeys.encryptionKey;
    }

    public static void main(String[] args) throws Exception {
        port(443);
        
        secure("./keystore.jks", new String(System.console().readPassword("Please enter the SSL certificate password:")), "./truststore.jks", new String(System.console().readPassword("Please enter the truststore password:")));

        Routes.initialize();
        awaitInitialization();

        System.out.println("Hosting at: https://localhost:5431");
    }

}
