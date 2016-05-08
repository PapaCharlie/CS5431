package vault5431.users;

import com.twilio.sdk.TwilioRestException;
import org.apache.commons.io.FileUtils;
import vault5431.Sys;
import vault5431.auth.AuthenticationHandler;
import vault5431.auth.TwoFactorAuthHandler;
import vault5431.crypto.HashUtils;
import vault5431.crypto.PasswordUtils;
import vault5431.crypto.SymmetricUtils;
import vault5431.crypto.exceptions.BadCiphertextException;
import vault5431.crypto.exceptions.CouldNotSaveKeyException;
import vault5431.crypto.sjcl.SJCLSymmetricField;
import vault5431.io.Base64String;
import vault5431.users.exceptions.CouldNotLoadSettingsException;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Pattern;

import static vault5431.Vault.home;

/**
 * User manager. The goal of this class is to ensure that all user creation is done properly, and to manage file access
 * in a synchronous manner. As long as all User instances are acquired through this class, there should be no race
 * conditions.
 *
 * @author papacharlie
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
                user.loadLog();
                addUser(user);
            }
        } catch (Exception err) {
            throw new RuntimeException(err);
        } finally {
            userMapLock.writeLock().unlock();
        }
    }

    private static User addUser(User user) {
        userMapLock.writeLock().lock();
        try {
            return users.put(user.hashedUsername, user);
        } finally {
            userMapLock.writeLock().unlock();
        }
    }

    public static void deleteUser(Base64String hashedUsername) {
        userMapLock.writeLock().lock();
        try {
            if (userExists(hashedUsername)) {
                FileUtils.deleteDirectory(getUser(hashedUsername).getHome());
                users.remove(hashedUsername);
            }
        } catch (IOException err) {
            //
        } finally {
            userMapLock.writeLock().unlock();
        }
    }

    public static Base64String hashUsername(String username) {
        return HashUtils.hash256(username.getBytes());
    }

    public static boolean userExists(Base64String hashedUsername) {
        userMapLock.readLock().lock();
        try {
            return users.containsKey(hashedUsername);
        } finally {
            userMapLock.readLock().unlock();
        }
    }

    public static boolean userExists(String username) {
        return userExists(hashUsername(username));
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

    public synchronized static int create(
            String username,
            Base64String hashedPassword,
            String phoneNumber,
            Base64String pubCryptoKey,
            SJCLSymmetricField privCryptoKey,
            Base64String pubSigningKey,
            SJCLSymmetricField privSigningKey)
            throws IOException, CouldNotSaveKeyException, BadCiphertextException, TwilioRestException, CouldNotLoadSettingsException {
        if (!isValidUsername(username)) {
            throw new IllegalArgumentException("Username is not valid!");
        }
        User user;
        userMapLock.readLock().lock();
        try {
            if (userExists(username)) {
                throw new IllegalArgumentException("This username is already taken");
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
                        throw new IOException("Could not create vault file!");
                    } else {
                        Sys.info("Created vault file.", user);
                    }
                    if (!user.sharedPasswordsFile.createNewFile()) {
                        throw new IOException("Could not create shared passwords file!.");
                    } else {
                        Sys.info("Created vault file.", user);
                    }
                    PasswordUtils.hashAndSavePassword(user.passwordHashFile, hashedPassword);
                    new Settings(phoneNumber).saveToFile(user.settingsFile, user.getUserEncryptionKey());

                    user.saveAndSignPublicEncryptionKey(pubCryptoKey);
                    user.saveAndSignPublicSigningKey(pubSigningKey);
                    new Base64String(privCryptoKey.toString()).saveToFile(user.privCryptoKeyFile);
                    new Base64String(privSigningKey.toString()).saveToFile(user.privSigningKeyFile);

                    byte[] salt = PasswordUtils.generateSalt();
                    SymmetricUtils.encrypt(salt, user.getUserEncryptionKey()).saveToFile(user.vaultSaltFile);

                    Sys.info("Successfully created user.", user);
                    user.info("Your account was successfully created!");
                    addUser(user);
                    user.info("Sending phone number verification code.");
                    return TwoFactorAuthHandler.sendVerificationMessage(user);
                } else {
                    FileUtils.deleteDirectory(homedir);
                    throw new IOException("Could not create directory!");
                }
            } else {
                throw new IllegalArgumentException("This username is already taken");
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
