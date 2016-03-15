package vault5431;

import org.apache.commons.csv.CSVRecord;
import vault5431.crypto.AsymmetricUtils;
import vault5431.crypto.PasswordUtils;
import vault5431.crypto.SymmetricUtils;
import vault5431.io.Base64String;
import vault5431.io.FileUtils;
import vault5431.logging.CSVUtils;
import vault5431.logging.LogType;
import vault5431.logging.UserLogEntry;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOError;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import static vault5431.Sys.NO_IP;
import static vault5431.Sys.SYS;
import static vault5431.Vault.home;
import static vault5431.crypto.HashUtils.hash256;

/**
 * User class.
 * TODO: Provide enc and dec methods
 */
public final class User {

    public static final String NO_USER = "NOUSER";
    private static final Object mapLock = new Object();
    private static Map<Base64String, User> users = new HashMap<>();

    static {
        for (String dirname : home.list((dir, name) -> dir.isDirectory())) {
            Base64String hash = Base64String.fromBase64(dirname);
            addUser(new User(hash));
        }
    }

    public final File logFile;
    public final File privCryptoKeyfile;
    public final File privCryptoIVFile;
    public final File pubCryptoKeyFile;
    public final File privSigningKeyFile;
    public final File privSigningIVFile;
    public final File pubSigningKeyFile;
    public final File passwordVaultFile;
    public final File passwordHashFile;
    public final File signingKeyFile;
    public final File cryptoKeyFile;
    private final Base64String hash;

    private User(String username) {
        this(hashUsername(username));
    }

    private User(Base64String hash) {
        this.hash = hash;
        logFile = new File(getHome() + File.separator + "log");
        privCryptoKeyfile = new File(getHome() + File.separator + "id_rsa.crypto");
        privCryptoIVFile = new File(getHome() + File.separator + "iv.crypto");
        pubCryptoKeyFile = new File(privCryptoKeyfile + ".pub");
        privSigningKeyFile = new File(getHome() + File.separator + "id_rsa.signing");
        privSigningIVFile = new File(getHome() + File.separator + "iv.signing");
        pubSigningKeyFile = new File(privSigningKeyFile + ".pub");
        passwordVaultFile = new File(getHome() + File.separator + "vault");
        passwordHashFile = new File(getHome() + File.separator + "password.hash");
        signingKeyFile = new File(getHome() + File.separator + "signing.key");
        cryptoKeyFile = new File(getHome() + File.separator + "crypto.key");
    }

    private static User addUser(User user) {
        synchronized (mapLock) {
            return users.put(user.hash, user);
        }
    }

    private static Base64String hashUsername(String username) {
        return hash256(username.getBytes());
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

    public static String getHome(String username) {
        return home + File.separator + hashUsername(username).getB64String();
    }

    public synchronized static User create(String username, String password)
            throws IOException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        User user;
        synchronized (mapLock) {
            if (userExists(username)) {
                return null;
            } else {
                user = new User(username);
                addUser(user);
            }
        }
        File homedir = new File(user.getHome());
        if (homedir.mkdir()) {
            PasswordUtils.savePassword(user.passwordHashFile, password);

            KeyPair signingKeys = AsymmetricUtils.getNewKeyPair();
            AsymmetricUtils.savePrivateKey(user.privSigningKeyFile, user.privSigningIVFile, signingKeys.getPrivate(), password);
            AsymmetricUtils.savePublicKey(user.pubSigningKeyFile, signingKeys.getPublic());
            KeyPair cryptoKeys = AsymmetricUtils.getNewKeyPair();
            AsymmetricUtils.savePrivateKey(user.privCryptoKeyfile, user.privCryptoIVFile, cryptoKeys.getPrivate(), password);
            AsymmetricUtils.savePublicKey(user.pubCryptoKeyFile, cryptoKeys.getPublic());

            SecretKey signingKey = SymmetricUtils.getNewKey();
            SymmetricUtils.saveSecretKey(user.signingKeyFile, signingKey, cryptoKeys.getPublic());
            SecretKey cryptoKey = SymmetricUtils.getNewKey();
            SymmetricUtils.saveSecretKey(user.cryptoKeyFile, cryptoKey, cryptoKeys.getPublic());

            return user;
        } else {
            return null;
        }
    }

    public String getHome() {
        return home + File.separator + hash.getB64String();
    }

    public PublicKey loadPublicSigningKey() throws IOException, InvalidKeySpecException {
        return AsymmetricUtils.loadPublicKey(pubSigningKeyFile);
    }

    public PrivateKey loadPrivateSigningKey(String password)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOError, IOException, InvalidKeySpecException {
        synchronized (privSigningKeyFile) {
            return AsymmetricUtils.loadPrivateKey(privSigningKeyFile, privSigningIVFile, password, passwordHashFile);
        }
    }

    public PublicKey loadPublicCryptoKey() throws IOException, InvalidKeySpecException {
        return AsymmetricUtils.loadPublicKey(pubCryptoKeyFile);
    }

    public PrivateKey loadPrivateCryptoKey(String password)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOError, IOException, InvalidKeySpecException {
        synchronized (privCryptoKeyfile) {
            return AsymmetricUtils.loadPrivateKey(privCryptoKeyfile, privCryptoIVFile, password, passwordHashFile);
        }
    }

    public void appendToLog(UserLogEntry entry)
            throws IOException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        synchronized (logFile) {
            FileUtils.append(logFile, new Base64String(entry.toCSV()));
        }
    }

    public void error(String ip, String affectedUser, String message)
            throws IOException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        appendToLog(new UserLogEntry(LogType.ERROR, ip, affectedUser, LocalDateTime.now(), message, ""));
    }

    public void error(String ip, String message)
            throws IOException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        appendToLog(new UserLogEntry(LogType.ERROR, ip, NO_USER, LocalDateTime.now(), message, ""));
    }

    public void error(String message)
            throws IOException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        appendToLog(new UserLogEntry(LogType.ERROR, NO_IP, NO_USER, LocalDateTime.now(), message, ""));
    }

    public void warning(String ip, String affectedUser, String message)
            throws IOException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        appendToLog(new UserLogEntry(LogType.WARNING, ip, affectedUser, LocalDateTime.now(), message, ""));
    }

    public void warning(String ip, String message)
            throws IOException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        appendToLog(new UserLogEntry(LogType.WARNING, ip, NO_USER, LocalDateTime.now(), message, ""));
    }

    public void warning(String message)
            throws IOException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        appendToLog(new UserLogEntry(LogType.WARNING, NO_IP, NO_USER, LocalDateTime.now(), message, ""));
    }

    public void info(String ip, String affectedUser, String message)
            throws IOException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        appendToLog(new UserLogEntry(LogType.INFO, ip, affectedUser, LocalDateTime.now(), message, ""));
    }

    public void info(String ip, String message)
            throws IOException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        appendToLog(new UserLogEntry(LogType.INFO, ip, NO_USER, LocalDateTime.now(), message, ""));
    }

    public void info(String message)
            throws IOException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        appendToLog(new UserLogEntry(LogType.INFO, NO_IP, NO_USER, LocalDateTime.now(), message, ""));
    }

    public void debug(String ip, String affectedUser, String message)
            throws IOException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        appendToLog(new UserLogEntry(LogType.DEBUG, ip, affectedUser, LocalDateTime.now(), message, ""));
    }

    public void debug(String ip, String message)
            throws IOException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        appendToLog(new UserLogEntry(LogType.DEBUG, ip, NO_USER, LocalDateTime.now(), message, ""));
    }

    public void debug(String message)
            throws IOException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        appendToLog(new UserLogEntry(LogType.DEBUG, NO_IP, NO_USER, LocalDateTime.now(), message, ""));
    }

    public UserLogEntry[] loadLog() throws IOException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        synchronized (logFile) {
            Base64String[] encryptedEntries = FileUtils.read(logFile);
            UserLogEntry[] decryptedEntries = new UserLogEntry[encryptedEntries.length];
            for (int i = 0; i < encryptedEntries.length; i++) {
                CSVRecord record = CSVUtils.parseRecord(encryptedEntries[i].decodeString()).getRecords().get(0);
                decryptedEntries[i] = UserLogEntry.fromCSV(record);
            }
            return decryptedEntries;
        }
    }

    public UserLogEntry[] loadLog(String password) throws IOException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
//        PrivateKey privateKey = loadPrivateCryptoKey(password);
//        synchronized (logFile) {
//            Base64String[] encryptedEntries = FileUtils.read(logFile);
//            String[] decryptedEntries = new String[encryptedEntries.length];
//            for (int i = 0; i < encryptedEntries.length; i ++) {
//                decryptedEntries[i] = new String(AsymmetricUtils.decrypt(encryptedEntries[i], privateKey));
//            }
//            return decryptedEntries;
//        }
        return loadLog();
    }

}
