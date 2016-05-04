package vault5431;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import vault5431.crypto.HashUtils;
import vault5431.crypto.PasswordUtils;
import vault5431.io.Base64String;
import vault5431.routes.Routes;

import javax.crypto.SecretKey;
import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.Security;

import static spark.Spark.*;


/**
 * Main class.
 *
 * @author papacharlie
 */
public class Vault {

    public static final File home = new File(System.getProperty("user.home"), ".vault5431");
    /**
     * This becomes set to false at deployment.
     */
    public static final boolean test = true;
    private static boolean initialized = false;

    private static final File adminSaltFile = new File(home, "admin.salt");
    private static final SecretKey adminEncryptionKey;
    private static final SecretKey adminSigningKey;
    private static final SecretKey adminLoggingKey;

    static {
        initialize();
        byte[] adminSalt;
        try {
            adminSalt = Base64String.loadFromFile(adminSaltFile)[0].decodeBytes();
        } catch (IOException err) {
            err.printStackTrace();
            System.err.println("Could not load admin salt from file!");
            throw new RuntimeException(err);
        }
        char[] adminPassword;
        if (test) {
            adminPassword = "debug".toCharArray();
        } else {
            Console cons;
            if ((cons = System.console()) != null) {
                adminPassword = cons.readPassword("[%s]", "Please enter the admin password:");
            } else {
                throw new RuntimeException("Cannot read admin password!");
            }
        }

        for (int i = 0; i < adminPassword.length; i++) {
            adminPassword[i] = (char) (adminPassword[i] ^ 'e'); // e for encryption
        }
        adminEncryptionKey = PasswordUtils.deriveKey(adminPassword, adminSalt);
        for (int i = 0; i < adminPassword.length; i++) {
            adminPassword[i] = (char) (adminPassword[i] ^ 'e'); // back to original password
            adminPassword[i] = (char) (adminPassword[i] ^ 's'); // s for signing
        }
        adminSigningKey = PasswordUtils.deriveKey(adminPassword, adminSalt);
        for (int i = 0; i < adminPassword.length; i++) {
            adminPassword[i] = (char) (adminPassword[i] ^ 's'); // back to original password
            adminPassword[i] = (char) (adminPassword[i] ^ 'l'); // l for logging
        }
        adminLoggingKey = PasswordUtils.deriveKey(adminPassword, adminSalt);
        java.util.Arrays.fill(adminPassword, ' ');
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
     * Returns the admin encryption key derived from the SysAdmin password.
     */
    public static SecretKey getAdminEncryptionKey() {
        return adminEncryptionKey;
    }

    /**
     * Returns the admin signing key derived from the SysAdmin password.
     */
    public static SecretKey getAdminSigningKey() {
        return adminSigningKey;
    }

    /**
     * Returns the admin logging key derived from the SysAdmin password.
     */
    public static SecretKey getAdminLoggingKey() {
        return adminLoggingKey;
    }

    public static void main(String[] args) throws Exception {
        if (test) {
            port(5431);
            secure("./keystore.jks", "vault5431", null, null);
            System.out.println("Hosting at: https://localhost:5431");
        } else {
            port(443);
            secure(
                    "./keystore.jks",
                    new String(System.console().readPassword("Please enter the SSL certificate password: ")),
                    "./truststore.jks",
                    new String(System.console().readPassword("Please enter the truststore password: "))
            );
        }
        Routes.initialize();
        awaitInitialization();
    }

}
