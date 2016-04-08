package vault5431.users;

import vault5431.Sys;
import vault5431.crypto.AsymmetricUtils;
import vault5431.crypto.HashUtils;
import vault5431.crypto.PasswordUtils;
import vault5431.crypto.SigningUtils;
import vault5431.crypto.exceptions.BadCiphertextException;
import vault5431.crypto.exceptions.CouldNotSaveKeyException;
import vault5431.io.Base64String;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

import static vault5431.Vault.adminEncryptionKey;
import static vault5431.Vault.home;

/**
 * User manager. The goal of this class is to ensure that all user creation is done properly, and to manage file access
 * in a synchronous manner. As long as all User instances are acquired through this class, there should be no race
 * conditions.
 */
public class UserManager {

    private static final Object mapLock = new Object();
    private static final Map<Base64String, User> users = new HashMap<>();
    private static boolean initialized = false;

    public static void initialize() {
        if (!initialized) {
            initialized = true;
            synchronized (mapLock) {
                addUser(new User(Sys.SYS));
                for (String dirname : home.list((dir, name) -> new File(dir, name).isDirectory())) {
                    Base64String hash = Base64String.fromBase64(dirname);
                    User user = new User(hash);
                    Sys.debug("Loaded user from disk.", user);
                    addUser(user);
                }
            }
        }
    }

    private static User addUser(User user) {
        synchronized (mapLock) {
            return users.put(user.hash, user);
        }
    }

    public static Base64String hashUsername(String username) {
        return HashUtils.hash256(username.getBytes());
    }

    public static boolean userExists(String username) {
        synchronized (mapLock) {
            return users.containsKey(hashUsername(username));
        }
    }

    public static User getUser(Base64String hash) {
        synchronized (mapLock) {
            return users.get(hash);
        }
    }

    public static User getUser(String username) {
        return getUser(hashUsername(username));
    }

    public static File getHome(String username) {
        return new File(home, hashUsername(username).getB64String());
    }

    public synchronized static User create(String username)
            throws IOException, CouldNotSaveKeyException, BadCiphertextException {
        User user;
        synchronized (mapLock) {
            if (userExists(username)) {
                return null;
            } else {
                user = new User(username);
            }
        }
        Sys.debug("Creating user home directory.", user);
        File homedir = user.getHome();
        if (homedir.mkdir()) {
            Sys.debug("Created user home directory.", user);
            if (!user.vaultFile.createNewFile()) {
                Sys.error("Could not create vault file!.", user);
                return null;
            } else {
                Sys.info("Created vault file.", user);
            }
//            PasswordUtils.savePassword(user.passwordHashFile, password);
            byte[] vaultSalt = PasswordUtils.generateSalt();
            byte[] passwordSalt = PasswordUtils.generateSalt();
            new Base64String(vaultSalt).saveToFile(user.vaultSaltFile);
            new Base64String(passwordSalt).saveToFile(user.passwordSaltFile);

            Sys.info("Generating signing keypair.", user);
            KeyPair signingKeys = AsymmetricUtils.getNewKeyPair();
            AsymmetricUtils.savePrivateKey(user.privSigningKeyFile, signingKeys.getPrivate(), adminEncryptionKey);
            Sys.info("Saving public signing key.", user);
            AsymmetricUtils.savePublicKey(user.pubSigningKeyFile, signingKeys.getPublic());
            Sys.info("Signing public signing key", user);
            SigningUtils.signPublicKey(signingKeys.getPublic()).saveToFile(user.pubSigningSigFile);
            Sys.info("Generating encryption keypair.", user);
            KeyPair cryptoKeys = AsymmetricUtils.getNewKeyPair();
            Sys.info("Saving private encryption key encrypted under password.", user);
            AsymmetricUtils.savePrivateKey(user.privCryptoKeyfile, cryptoKeys.getPrivate(), adminEncryptionKey);
            Sys.info("Saving public encryption key.", user);
            AsymmetricUtils.savePublicKey(user.pubCryptoKeyFile, cryptoKeys.getPublic());
            Sys.info("Signing public encryption key", user);
            SigningUtils.signPublicKey(cryptoKeys.getPublic()).saveToFile(user.pubCryptoSigFile);

            Sys.info("Successfully created user.", user);
            addUser(user);
            return user;
        } else {
            Sys.error("Could not create directory! Not adding to user map.", user);
            return null;
        }
    }

}
