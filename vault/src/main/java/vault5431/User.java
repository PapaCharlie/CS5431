package vault5431;

import java.io.File;
import java.io.FilenameFilter;

import vault5431.crypto.Base64String;

import static vault5431.Vault.home;

/**
 * User class.
 * TODO: Provide enc and dec methods
 */
public class User {

    private String firstName;
    private String lastName;
    private String email;
    private String username;

    private static final String log = "log";
    private static final String privCryptoKey = "id_rsa.crypto";
    private static final String pubCryptoKey = privCryptoKey + ".pub";
    private static final String privSigningKey = "id_rsa.signing";
    private static final String pubSigningKey = privSigningKey + ".pub";
    private static final String passwordVault = "vault";
//    private static final String secureNotes = "notes";

    User(String username, String firstName, String lastName, String email) {
        this.username = username;
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
    }

    private static File findUserHome(String username) {
        String userHome = new Base64String(username).asHexString();
        FilenameFilter filter = (dir, name) -> dir.isDirectory() && name.equals(userHome);
        File[] dirs = home.listFiles(filter);
        if (dirs.length == 0){
            return null;
        } else {
            return dirs[0];
        }
    }

    private static File getFile(String username, String file) {
        File userHome = findUserHome(username);
        if (userHome != null) {
            File someFile = new File(userHome + File.separator + file);
            if (someFile.exists()) {
                return someFile;
            } else {
                return null;
            }
        } else {
            return null;
        }
    }

    public static File getLogFile(String username) {
        return getFile(username, log);
    }

    public static File getPublicSigningKeyFile(String username) {
        return getFile(username, pubSigningKey);
    }

    public static File getPrivateSigningKeyFile(String username) {
        return getFile(username, privSigningKey);
    }

    public static File getPublicEncryptionKeyFile(String username) {
        return getFile(username, pubCryptoKey);
    }

    public static File getPrivateEncryptionKeyFile(String username) {
        return getFile(username, privCryptoKey);
    }

    public static File getPasswordVaultFile(String username) {
        return getFile(username, passwordVault);
    }

}
