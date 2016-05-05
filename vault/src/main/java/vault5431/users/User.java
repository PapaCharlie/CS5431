package vault5431.users;

import org.apache.commons.csv.CSVRecord;
import org.json.JSONException;
import vault5431.Sys;
import vault5431.auth.AuthenticationHandler;
import vault5431.auth.AuthenticationHandler.Token;
import vault5431.auth.exceptions.NoSuchUserException;
import vault5431.auth.exceptions.TooManyConcurrentSessionsException;
import vault5431.auth.exceptions.TooManyFailedLogins;
import vault5431.crypto.PasswordUtils;
import vault5431.crypto.SigningUtils;
import vault5431.crypto.SymmetricUtils;
import vault5431.crypto.exceptions.BadCiphertextException;
import vault5431.crypto.exceptions.CouldNotLoadKeyException;
import vault5431.crypto.exceptions.InvalidPublicKeySignature;
import vault5431.crypto.sjcl.SJCLSymmetricField;
import vault5431.io.Base64String;
import vault5431.io.FileUtils;
import vault5431.logging.CSVUtils;
import vault5431.logging.LogType;
import vault5431.logging.UserLogEntry;
import vault5431.users.exceptions.CorruptedLogException;
import vault5431.users.exceptions.CouldNotLoadSettingsException;
import vault5431.users.exceptions.IllegalTokenException;
import vault5431.users.exceptions.VaultNotFoundException;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashSet;
import java.util.UUID;

import static vault5431.Sys.NO_IP;
import static vault5431.Vault.*;

/**
 * User class. Because an instance of User can only be acquired through the UserManager, and the UserManager always
 * hands out the same User instance when {@link UserManager#getUser} is called, synchronizing on dynamic fields
 * has meaning since each thread is sharing the same instance for a given User.
 *
 * @author papacharlie
 */
public final class User {

    public static final String NO_USER = "NOUSER";

    public final Base64String hash;
    public final File logFile;
    public final File vaultFile;
    public final File vaultSaltFile;
    public final File sharedPasswordsFile;
    public final File settingsFile;
    public final File passwordHashFile;
    public final File pubCryptoKeyFile;
    public final File privCryptoKeyFile;
    public final File pubSigningKeyFile;
    public final File privSigningKeyFile;

    private final SecretKey userEncryptionKey;
    private final SecretKey userSigningKey;
    private final SecretKey firstUserLoggingKey;
    private final Object currentUserLoggingKeyLock = new Object();
    private SecretKey currentUserLoggingKey;

    protected User(String username) {
        this(UserManager.hashUsername(username));
    }

    protected User(Base64String hash) {
        this.hash = hash;
        logFile = new File(getHome(), "log");
        vaultFile = new File(getHome(), "vault");
        vaultSaltFile = new File(getHome(), "vault.salt");
        sharedPasswordsFile = new File(getHome(), "shared");
        passwordHashFile = new File(getHome(), "password.hash");
        settingsFile = new File(getHome(), "settings");
        pubCryptoKeyFile = new File(getHome(), "crypto.pub");
        privCryptoKeyFile = new File(getHome(), "crypto.priv");
        pubSigningKeyFile = new File(getHome(), "signing.pub");
        privSigningKeyFile = new File(getHome(), "signing.priv");

        userEncryptionKey = SymmetricUtils.combine(getAdminEncryptionKey(), hash);
        userSigningKey = SymmetricUtils.combine(getAdminSigningKey(), hash);
        firstUserLoggingKey = SymmetricUtils.combine(getAdminLoggingKey(), hash);
        currentUserLoggingKey = firstUserLoggingKey;
    }

    private void iterateLoggingKey() {
        synchronized (currentUserLoggingKeyLock) {
            currentUserLoggingKey = SymmetricUtils.hashIterateKey(currentUserLoggingKey);
        }
    }

    private SecretKey deriveLogEncryptionKey() {
        synchronized (currentUserLoggingKeyLock) {
            return SymmetricUtils.combine(currentUserLoggingKey, "encryption".getBytes());
        }
    }

    private SecretKey deriveLogSigningKey() {
        synchronized (currentUserLoggingKeyLock) {
            return SymmetricUtils.combine(currentUserLoggingKey, "signing".getBytes());
        }
    }

    private void verifyToken(Token token) throws IllegalTokenException {
        if (!this.hash.equals(token.getUser().hash))
            throw new IllegalTokenException();
    }

    protected SecretKey getUserEncryptionKey() {
        return userEncryptionKey;
    }

    protected SecretKey getUserSigningKey() {
        return userSigningKey;
    }

    protected SecretKey getFirstUserLoggingKey() {
        return firstUserLoggingKey;
    }

    public int hashCode() {
        return hash.hashCode();
    }

    public String getShortHash() {
        return hash.getB64String().substring(0, Integer.min(hash.size(), 10));
    }

    public File getHome() {
        return new File(home, hash.getB64String());
    }

    private void saveAndSignPublicKey(File file, Base64String pubKey) throws IOException {
        FileUtils.empty(file);
        FileUtils.append(file, pubKey);
        FileUtils.append(file, SigningUtils.sign(pubKey.decodeBytes(), userSigningKey));
    }

    private String loadAndVerifyPublicKey(File file) throws IOException, InvalidPublicKeySignature {
        Base64String[] data = FileUtils.read(file);
        if (SigningUtils.verify(data[0].decodeBytes(), data[1], userSigningKey)) {
            return data[0].getB64String();
        } else {
            throw new InvalidPublicKeySignature();
        }
    }

    protected void saveAndSignPublicEncryptionKey(Base64String pubCryptoKey) throws IOException {
        synchronized (pubCryptoKeyFile) {
            saveAndSignPublicKey(pubCryptoKeyFile, pubCryptoKey);
        }
    }

    protected void saveAndSignPublicSigningKey(Base64String pubCryptoKey) throws IOException {
        synchronized (pubSigningKeyFile) {
            saveAndSignPublicKey(pubSigningKeyFile, pubCryptoKey);
        }
    }

    public String loadAndVerifyPublicEncryptionKey() throws InvalidPublicKeySignature, IOException {
        synchronized (pubCryptoKeyFile) {
            return loadAndVerifyPublicKey(pubCryptoKeyFile);
        }
    }

    public String loadAndVerifyPublicSigningKey() throws InvalidPublicKeySignature, IOException {
        synchronized (pubSigningKeyFile) {
            return loadAndVerifyPublicKey(pubSigningKeyFile);
        }
    }

    public String loadPrivateEncryptionKey(Token token) throws IOException, IllegalTokenException {
        synchronized (privCryptoKeyFile) {
            verifyToken(token);
            Sys.debug("Loading private encryption key.", token);
            return FileUtils.read(privCryptoKeyFile)[0].decodeString();
        }
    }

    public String loadPrivateSigningKey(Token token) throws IOException, IllegalTokenException {
        synchronized (privSigningKeyFile) {
            verifyToken(token);
            Sys.debug("Loading private signing key.", token);
            return FileUtils.read(privSigningKeyFile)[0].decodeString();
        }
    }

    private void changePrivateEncryptionKey(SJCLSymmetricField newKey, Token token) throws IOException, IllegalTokenException {
        synchronized (privCryptoKeyFile) {
            verifyToken(token);
            Sys.debug("Changing private encryption key", token);
            FileUtils.write(privCryptoKeyFile, new Base64String(newKey.toString()));
        }
    }

    private void changePrivateSigningKey(SJCLSymmetricField newKey, Token token) throws IOException, IllegalTokenException {
        synchronized (privSigningKeyFile) {
            verifyToken(token);
            Sys.debug("Changing private signing key", token);
            FileUtils.write(privSigningKeyFile, new Base64String(newKey.toString()));
        }
    }

    public Token changeMasterPassword(Base64String oldPassword, Base64String newPassword,
                                      Password[] reEncryptedPasswords, SJCLSymmetricField newPrivateEncryptionKey,
                                      SJCLSymmetricField newPrivateSigningKey, Token token)
            throws TooManyConcurrentSessionsException, TooManyFailedLogins, CouldNotLoadSettingsException, IOException, NoSuchUserException, IllegalTokenException {
        synchronized (passwordHashFile) {
            // Flag suspicious activity if oldPassword is incorrect. Will behave as if failed login and throw respective errors.
            verifyToken(token);
            Token successToken = AuthenticationHandler.acquireUnverifiedToken(token.getUsername(), oldPassword, token.getIp());
            if (successToken != null) {
                warning("Changing master password!", token.getIp());
                PasswordUtils.hashAndSavePassword(passwordHashFile, newPassword);
                warning("Saving newly encrypted vault!", token.getIp());
                savePasswords(new HashSet<>(Arrays.asList(reEncryptedPasswords)));
                changePrivateEncryptionKey(newPrivateEncryptionKey, token);
                changePrivateSigningKey(newPrivateSigningKey, token);
                info("Master password change successful.", token.getIp());
            }
            return successToken;
        }
    }

    public void changeSettings(Settings settings, Token token) throws IOException, BadCiphertextException, IllegalTokenException {
        synchronized (settingsFile) {
            verifyToken(token);
            settings.saveToFile(settingsFile, userEncryptionKey);
        }
    }

    public Settings loadSettings() throws CouldNotLoadSettingsException {
        synchronized (settingsFile) {
            try {
                return Settings.loadFromFile(settingsFile, userEncryptionKey);
            } catch (IOException | BadCiphertextException | IllegalArgumentException err) {
                throw new CouldNotLoadSettingsException();
            }
        }
    }

    private void saveSharedPasswords(HashSet<SharedPassword> sharedPasswords) throws IOException {
        synchronized (sharedPasswordsFile) {
            FileUtils.empty(sharedPasswordsFile);
            for (SharedPassword password : sharedPasswords) {
                FileUtils.append(sharedPasswordsFile, new Base64String(password.toJSON()));
            }
        }
    }

    public SharedPassword deleteSharedPassword(UUID uuid, Token token) throws IOException, VaultNotFoundException, IllegalTokenException {
        synchronized (sharedPasswordsFile) {
            verifyToken(token);
            HashSet<SharedPassword> passwords = loadSharedPasswords(token);
            HashSet<SharedPassword> filteredPasswords = new HashSet<>();
            SharedPassword deleted = null;
            for (SharedPassword sharedPassword : passwords) {
                if (sharedPassword.getID().equals(uuid)) {
                    deleted = sharedPassword;
                } else {
                    filteredPasswords.add(sharedPassword);
                }
            }
            if (deleted != null) {
                saveSharedPasswords(filteredPasswords);
                info("Deleted shared password.", token.getIp());
            }
            return deleted;
        }
    }

    public int numSharedPasswords(Token token) throws IOException, IllegalTokenException {
        synchronized (sharedPasswordsFile) {
            verifyToken(token);
            return FileUtils.read(sharedPasswordsFile).length;
        }
    }

    public HashSet<SharedPassword> loadSharedPasswords(Token token) throws IOException, VaultNotFoundException, IllegalTokenException {
        synchronized (sharedPasswordsFile) {
            verifyToken(token);
            return loadSharedPasswords();
        }
    }

    private HashSet<SharedPassword> loadSharedPasswords() throws IOException, VaultNotFoundException {
        synchronized (sharedPasswordsFile) {
            info("Loading shared passwords.");
            if (!sharedPasswordsFile.exists()) {
                Sys.error("User's shared passwords file could not be found.", this);
                throw new VaultNotFoundException();
            }
            HashSet<SharedPassword> sharedPasswords = new HashSet<>();
            try {
                for (Base64String base64String : Base64String.loadFromFile(sharedPasswordsFile)) {
                    try {
                        sharedPasswords.add(SharedPassword.fromJSON(base64String));
                    } catch (IllegalArgumentException | JSONException err) {
                        err.printStackTrace();
                        error("Shared password was corrupted! Loading remaining passwords.");
                    }
                }
            } catch (IOException err) {
                err.printStackTrace();
                error("Could not find vault!");
                throw new VaultNotFoundException();
            }
            return sharedPasswords;
        }
    }

    public void addSharedPassword(SharedPassword sharedPassword, Token token) throws IOException, VaultNotFoundException {
        synchronized (sharedPasswordsFile) {
            info(String.format("%s has shared a password with you.", token.getUsername()));
            HashSet<SharedPassword> sharedPasswords = loadSharedPasswords();
            boolean validUUID = false;
            while (!validUUID) {
                if (sharedPasswords.stream().filter((other) -> other.getID().equals(sharedPassword.getID())).count() > 0) {
                    sharedPassword.newUUID();
                } else {
                    validUUID = true;
                }
            }
            FileUtils.append(sharedPasswordsFile, new Base64String(sharedPassword.toJSONObject().toString()));
        }
    }

    public void savePassword(Password password, Token token) throws IOException, VaultNotFoundException, IllegalTokenException {
        synchronized (vaultFile) {
            verifyToken(token);
            info("Added password.", token.getIp());
            HashSet<Password> passwords = loadPasswords(token);
            boolean validUUID = false;
            while (!validUUID) {
                if (passwords.stream().filter((other) -> other.getID().equals(password.getID())).count() > 0) {
                    password.newUUID();
                } else {
                    validUUID = true;
                }
            }
            FileUtils.append(vaultFile, new Base64String(password.toJSON()));
        }
    }

    public void changePassword(Password password, Token token) throws IOException, VaultNotFoundException, IllegalTokenException {
        synchronized (vaultFile) {
            verifyToken(token);
            HashSet<Password> passwords = loadPasswords(token);
            if (passwords.removeIf((pass) -> pass.getID().equals(password.getID()))) {
                passwords.add(password);
            }
            savePasswords(passwords);
            info("Edited password.", token.getIp());
        }
    }

    public Password deletePassword(UUID uuid, Token token) throws IOException, VaultNotFoundException, IllegalTokenException {
        synchronized (vaultFile) {
            verifyToken(token);
            HashSet<Password> passwords = loadPasswords(token);
            HashSet<Password> filteredPasswords = new HashSet<>();
            Password deleted = null;
            for (Password password : passwords) {
                if (password.getID().equals(uuid)) {
                    deleted = password;
                } else {
                    filteredPasswords.add(password);
                }
            }
            if (deleted != null) {
                savePasswords(filteredPasswords);
                info("Deleted password.", token.getIp());
            }
            return deleted;
        }
    }

    private void savePasswords(HashSet<Password> passwords) throws IOException {
        synchronized (vaultFile) {
            FileUtils.empty(vaultFile);
            for (Password password : passwords) {
                FileUtils.append(vaultFile, new Base64String(password.toJSON()));
            }
        }
    }

    public HashSet<Password> loadPasswords(Token token) throws VaultNotFoundException, IllegalTokenException {
        synchronized (vaultFile) {
            verifyToken(token);
            info("Loading passwords.", token.getIp());
            if (!vaultFile.exists()) {
                Sys.error("User's vault file could not be found.", this);
                throw new VaultNotFoundException();
            }
            HashSet<Password> passwords = new HashSet<>();
            try {
                for (Base64String base64String : Base64String.loadFromFile(vaultFile)) {
                    try {
                        passwords.add(Password.fromJSON(base64String));
                    } catch (IllegalArgumentException | JSONException err) {
                        err.printStackTrace();
                        error("Password was corrupted! Loading remaining passwords.", token.getIp());
                    }
                }
            } catch (IOException err) {
                err.printStackTrace();
                error("Could not find vault!", token.getIp());
                throw new VaultNotFoundException();
            }
            return passwords;
        }
    }

    public boolean verifyMasterPassword(Base64String hashedPassword) throws IOException {
        synchronized (passwordHashFile) {
            return PasswordUtils.verifyPasswordInFile(passwordHashFile, hashedPassword);
        }
    }

    public Base64String loadVaultSalt(Token token) throws IOException, BadCiphertextException, IllegalTokenException {
        synchronized (vaultSaltFile) {
            verifyToken(token);
            return new Base64String(SymmetricUtils.decrypt(Base64String.loadFromFile(vaultSaltFile)[0], userEncryptionKey));
        }
    }

    private void appendToLog(UserLogEntry entry) {
        synchronized (logFile) {
            try {
                FileUtils.append(logFile, SymmetricUtils.encrypt(entry.toCSV().getBytes(), currentUserLoggingKey));
                iterateLoggingKey();
                System.out.println("[" + getShortHash() + "] " + entry.toString());
            } catch (IOException err) {
                err.printStackTrace();
                warning("Failed to log for user! Continuing (not recommended).", this);
                System.err.printf("[WARNING] Failed to log as user %s! Continuing (not recommended).%n", getShortHash());
            } catch (BadCiphertextException err) {
                err.printStackTrace();
                Sys.error("Serialization of log entry was too long, or unencryptable.", this);
            }
        }
    }

    public UserLogEntry[] loadLog(Token token) throws IOException, CouldNotLoadKeyException, CorruptedLogException {
        synchronized (logFile) {
            Sys.debug("Loading log.", token);
            Base64String[] encryptedEntries = FileUtils.read(logFile);
            UserLogEntry[] decryptedEntries = new UserLogEntry[encryptedEntries.length];
            SecretKey decryptIteratingKey = firstUserLoggingKey;
            for (int i = 0; i < encryptedEntries.length; i++) {
                try {
                    String entry = new String(SymmetricUtils.decrypt(encryptedEntries[i], decryptIteratingKey));
                    CSVRecord unverifiedRecord = CSVUtils.parseRecord(entry).getRecords().get(0);
                    UserLogEntry signedEntry = UserLogEntry.fromCSV(unverifiedRecord);
                    // Verifying Signature step
                    String[] splitEntry = entry.split(",");
                    LocalDateTime timestamp = LocalDateTime.parse(splitEntry[3]);
                    UserLogEntry testEntry = new UserLogEntry(LogType.fromString(splitEntry[0]),
                            splitEntry[1],splitEntry[2], timestamp, splitEntry[4]);
                    testEntry.signUserLog(userSigningKey);
                    boolean valid = signedEntry.checkSignature(testEntry);
                    System.out.println(valid);
                    UserLogEntry verifiedEntry = null;
                    if (valid) {
                        verifiedEntry = signedEntry;
                    } else {
                        UserLogEntry invalidEntry = new UserLogEntry(LogType.ERROR, NO_IP,
                                "USER", LocalDateTime.now(), "THIS LOG ENTRY IS INVALID");
                        invalidEntry.signUserLog(userSigningKey);
                        verifiedEntry = invalidEntry;
                    }
                    decryptedEntries[i] = verifiedEntry;
                    decryptIteratingKey = SymmetricUtils.hashIterateKey(decryptIteratingKey);
                } catch (BadCiphertextException err) {
                    throw new CorruptedLogException();
                }
            }
            return decryptedEntries;
        }
    }

    public void error(String message, User affectedUser, String ip) {
        UserLogEntry entry = new UserLogEntry(LogType.ERROR, ip, affectedUser, LocalDateTime.now(), message);
        entry.signUserLog(userSigningKey);
        appendToLog(entry);
    }

    public void error(String message, User affectedUser) {
        UserLogEntry entry = new UserLogEntry(LogType.ERROR, NO_IP, affectedUser, LocalDateTime.now(), message);
        entry.signUserLog(userSigningKey);
        appendToLog(entry);
    }

    public void error(String message, String ip) {
        UserLogEntry entry = new UserLogEntry(LogType.ERROR, ip, NO_USER, LocalDateTime.now(), message);
        entry.signUserLog(userSigningKey);
        appendToLog(entry);
    }

    public void error(String message) {
        UserLogEntry entry = new UserLogEntry(LogType.ERROR, NO_IP, NO_USER, LocalDateTime.now(), message);
        entry.signUserLog(userSigningKey);
        appendToLog(entry);
    }

    public void warning(String message, User affectedUser, String ip) {
        UserLogEntry entry = new UserLogEntry(LogType.WARNING, ip, affectedUser, LocalDateTime.now(), message);
        entry.signUserLog(userSigningKey);
        appendToLog(entry);
    }

    public void warning(String message, String ip) {
        UserLogEntry entry = new UserLogEntry(LogType.WARNING, ip, NO_USER, LocalDateTime.now(), message);
        entry.signUserLog(userSigningKey);
        appendToLog(entry);
    }

    public void warning(String message, User affectedUser) {
        UserLogEntry entry = new UserLogEntry(LogType.WARNING, NO_IP, affectedUser, LocalDateTime.now(), message);
        entry.signUserLog(userSigningKey);
        appendToLog(entry);
    }

    public void warning(String message) {
        UserLogEntry entry = new UserLogEntry(LogType.WARNING, NO_IP, NO_USER, LocalDateTime.now(), message);
        entry.signUserLog(userSigningKey);
        appendToLog(entry);
    }

    public void info(String message, User affectedUser, String ip) {
        UserLogEntry entry = new UserLogEntry(LogType.INFO, ip, affectedUser, LocalDateTime.now(), message);
        entry.signUserLog(userSigningKey);
        appendToLog(entry);
    }

    public void info(String message, String ip) {
        UserLogEntry entry = new UserLogEntry(LogType.INFO, ip, NO_USER, LocalDateTime.now(), message);
        entry.signUserLog(userSigningKey);
        appendToLog(entry);
    }

    public void info(String message, User affectedUser) {
        UserLogEntry entry = new UserLogEntry(LogType.INFO, NO_IP, affectedUser, LocalDateTime.now(), message);
        entry.signUserLog(userSigningKey);
        appendToLog(entry);
    }

    public void info(String message) {
        UserLogEntry entry = new UserLogEntry(LogType.INFO, NO_IP, NO_USER, LocalDateTime.now(), message);
        entry.signUserLog(userSigningKey);
        appendToLog(entry);
    }
}