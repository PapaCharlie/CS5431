package vault5431;

import vault5431.crypto.Base64String;
import vault5431.io.FileUtils;
import vault5431.io.LockedFile;

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

    public final String logPath = getHome() + "log";
    public final String privCryptoKeyPath = getHome() + "id_rsa.crypto";
    public final String pubCryptoKeyPath = getHome() + privCryptoKeyPath + ".pub";
    public final String privSigningKeyPath = getHome() + "id_rsa.signing";
    public final String pubSigningKeyPath = getHome() + privSigningKeyPath + ".pub";
    public final String passwordVaultPath = getHome() + "vault";

    User(String username, String firstName, String lastName, String email) {
        this.username = username;
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
    }

    User(String username) {
        this.username = username;
        firstName = "";
        lastName = "";
        email = "";
    }

    private String getHome() {
        return home + File.separator + hash512(new Base64String(username)).asHexString();
    }

    public boolean create(String password) throws IOException {
        LockedFile userHome = FileUtils.getLockedFile(getHome());
        userHome.lock();
        try {
            if (!userHome.exists()) {
                if (userHome.mkdir()) {
                    if (getLogFile(username).createNewFile() && getPasswordVaultFile(username).createNewFile()) {
                        KeyPair encryptionKeys = getNewKeyPair();
                        KeyPair signingKeys = getNewKeyPair();

                    }
                }
            }
            return false;
        } finally {
            userHome.unlock();
        }
    }

}
