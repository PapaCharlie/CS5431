package vault5431.users;

import org.apache.commons.io.FileUtils;
import vault5431.Sys;
import vault5431.crypto.HashUtils;
import vault5431.crypto.PasswordUtils;
import vault5431.crypto.SymmetricUtils;
import vault5431.crypto.exceptions.BadCiphertextException;
import vault5431.crypto.exceptions.CouldNotSaveKeyException;
import vault5431.crypto.sjcl.SJCLSymmetricField;
import vault5431.io.Base64String;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Pattern;

import static vault5431.Vault.getAdminEncryptionKey;
import static vault5431.Vault.home;

/**
 * User manager. The goal of this class is to ensure that all user creation is done properly, and to manage file access
 * in a synchronous manner. As long as all User instances are acquired through this class, there should be no race
 * conditions.
 */
public class UserManager {

    private static final Map<Base64String, User> users = new HashMap<>();
    private static final ReentrantReadWriteLock userMapLock = new ReentrantReadWriteLock();
    static {
        userMapLock.writeLock().lock();
        try {
            addUser(new User(Sys.SYS));
            for (String dirname : home.list((dir, name) ->
                    new File(dir, name).isDirectory())) {
                Base64String hash = Base64String.fromBase64(dirname);
                User user = new User(hash);
                addUser(user);
            }
        } finally {
            userMapLock.writeLock().unlock();
        }
    }

    private static User addUser(User user) {
        userMapLock.writeLock().lock();
        try {
            return users.put(user.hash, user);
        } finally {
            userMapLock.writeLock().unlock();
        }
    }

    public static Base64String hashUsername(String username) {
        return HashUtils.hash256(username.getBytes());
    }

    public static boolean userExists(String username) {
        userMapLock.readLock().lock();
        try {
            return users.containsKey(hashUsername(username));
        } finally {
            userMapLock.readLock().unlock();
        }
    }

    public static User getUser(Base64String hash) {
        userMapLock.readLock().lock();
        try {
            return users.get(hash);
        } finally {
            userMapLock.readLock().unlock();
        }
    }

    public static boolean isValidUsername(String username) {
        return Pattern.matches("\\w+", username);
    }

    public static User getUser(String username) {
        return getUser(hashUsername(username));
    }

    public static File getHome(String username) {
        return new File(home, hashUsername(username).getB64String());
    }

    public synchronized static User create(String username, Base64String hashedPassword, String phoneNumber, Base64String pubCryptoKey, SJCLSymmetricField privCryptoKey, Base64String pubSigningKey, SJCLSymmetricField privSigningKey)
            throws IOException, CouldNotSaveKeyException, BadCiphertextException {
        if (!isValidUsername(username)) {
            throw new IllegalArgumentException("Username is not valid!");
        }
        User user;
        userMapLock.readLock().lock();
        try {
            if (userExists(username)) {
                return getUser(username);
            } else {
                user = new User(username);
            }
        } finally {
            userMapLock.readLock().unlock();
        }
        userMapLock.writeLock().lock();
        try {
            if (!userExists(username)) { // Write lock may have been acquired between r.unlock and w.lock.
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
                    if (!user.sharedPasswordsFile.createNewFile()) {
                        Sys.error("Could not create shared passwords file!.", user);
                        return null;
                    } else {
                        Sys.info("Created vault file.", user);
                    }
                    PasswordUtils.savePassword(user.passwordHashFile, hashedPassword);
                    new Settings(phoneNumber).saveToFile(user.settingsFile);

                    user.saveAndSignPublicEncryptionKey(pubCryptoKey);
                    user.saveAndSignPublicSigningKey(pubSigningKey);
                    new Base64String(privCryptoKey.toString()).saveToFile(user.privCryptoKeyFile);
                    new Base64String(privSigningKey.toString()).saveToFile(user.privSigningKeyFile);

                    byte[] salt = PasswordUtils.generateSalt();
                    SymmetricUtils.encrypt(salt, getAdminEncryptionKey()).saveToFile(user.vaultSaltFile);

                    Sys.info("Successfully created user.", user);
                    addUser(user);
                    return user;
                } else {
                    Sys.error("Could not create directory! Not adding to user map.", user);
                    FileUtils.deleteDirectory(homedir);
                    return null;
                }
            } else {
                return getUser(username);
            }
        } catch (Exception err) {
            err.printStackTrace();
            FileUtils.deleteDirectory(user.getHome());
            throw err;
        } finally {
            userMapLock.writeLock().unlock();
        }
    }

}
