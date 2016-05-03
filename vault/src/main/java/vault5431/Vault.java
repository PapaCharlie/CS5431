package vault5431;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import vault5431.crypto.HashUtils;
import vault5431.crypto.PasswordUtils;
import vault5431.io.Base64String;
import vault5431.routes.Routes;
import vault5431.users.UserManager;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.security.Security;

import static spark.Spark.*;


public class Vault {

    public static final File home = new File(System.getProperty("user.home"), ".vault5431");
    public static final boolean test = true;

    private static final File adminSaltFile = new File(home, "admin.salt");

    private static boolean initialized = false;
    private static final SecretKey adminEncryptionKey;
    private static final SecretKey adminSigningKey;
    private static final SecretKey adminLoggingKey;
//    private static final byte[] adminSalt;

    static {
        initialize();
        byte[] adminSalt;
        // This line changed at deploy time to prompt SysAdmin for admin password
        String adminPassword = "debug";
        try {
            adminSalt = Base64String.loadFromFile(adminSaltFile)[0].decodeBytes();
        } catch (IOException err) {
            err.printStackTrace();
            System.err.println("Could not load admin salt from file!");
            throw new RuntimeException(err);
        }
        adminSigningKey = PasswordUtils.deriveKey(adminPassword + "signing", adminSalt);
        adminEncryptionKey = PasswordUtils.deriveKey(adminPassword + "encryption", adminSalt);
        adminLoggingKey = PasswordUtils.deriveKey(adminPassword + "logging", adminSalt);
    }

    /**
     * Creates ~/.vault5431 directory and starts the user manager.
     */
    private synchronized static void initialize() {
        if (initialized) {
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
    }

    /**
     * Returns the admin signing key derived from the SysAdmin password.
     */
    public static SecretKey getAdminEncryptionKey() {
        return adminEncryptionKey;
    }

    /**
     * Returns the admin encryption key derived from the SysAdmin password.
     */
    public static SecretKey getAdminSigningKey() {
        return adminSigningKey;
    }

    /**
     * Returns the admin logging key derived from the SysAdmin password and iterated i times.
     */
    public static SecretKey getAdminLoggingKey(int i) {
//        System.out.println("ORIGINAL KEY : " + new String(adminLoggingKey.getEncoded()));
        if (i == 0) {
            return adminLoggingKey;
        } else {
            try {
                String newKey = adminLoggingKey.getFormat();
                byte[] adminSalt = Base64String.loadFromFile(adminSaltFile)[0].decodeBytes();
                SecretKey datKey =  PasswordUtils.deriveKey(HashUtils.hash512(newKey.getBytes(), i).toString(), adminSalt);
//                System.out.println("DAT KEY: " + new String(datKey.getEncoded()));
                return datKey;
            } catch (IOException err){
                err.printStackTrace();
                System.err.println("Could not load admin salt from file!");
                throw new RuntimeException(err);
            }
        }
    }

    public static SecretKey getAdminLoggingKey() {
        return adminLoggingKey;
    }

    public static void main(String[] args) throws Exception {
        port(5431);

        // This line changed at deploy time to prompt SysAdmin for certificate password and truststore password.
        secure("./keystore.jks", "vault5431", null, null);

        Routes.initialize();
        awaitInitialization();

        System.out.println("Hosting at: https://localhost:5431");
    }

}
