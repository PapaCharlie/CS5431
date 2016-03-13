package vault5431;

import vault5431.crypto.Base64String;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.security.KeyPair;

import static vault5431.Vault.home;
import static vault5431.crypto.AsymmetricUtils.getNewKeyPair;
import static vault5431.crypto.HashUtils.hash512;

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

    private static String getHomeName(String username) {
        return hash512(new Base64String(username)).asHexString();
    }

    private static File findUserHome(String username) {
        String userHome = getHomeName(username);
        FilenameFilter filter = (dir, name) -> dir.isDirectory() && name.equals(userHome);
        File[] dirs = home.listFiles(filter);
        if (dirs.length == 0) {
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

    public boolean create(String password) throws IOException {

        if (findUserHome(username) == null) {
            File userHome = new File(home + File.separator + getHomeName(username));
            if (userHome.mkdir()) {
                if (getLogFile(username).createNewFile() && getPasswordVaultFile(username).createNewFile()) {
                    KeyPair encryptionKeys = getNewKeyPair();
                    KeyPair signingKeys = getNewKeyPair();
                    
                }
            }
        }
        return false;
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
