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

    public final Base64String hashedUsername;
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

    protected User(Base64String hashedUsername) {
        this.hashedUsername = hashedUsername;
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

        userEncryptionKey = SymmetricUtils.combine(getAdminEncryptionKey(), hashedUsername);
        userSigningKey = SymmetricUtils.combine(getAdminSigningKey(), hashedUsername);
        firstUserLoggingKey = SymmetricUtils.combine(getAdminLoggingKey(), hashedUsername);
        currentUserLoggingKey = firstUserLoggingKey;
    }

    private void verifyToken(Token token) throws IllegalTokenException {
        if (!this.hashedUsername.equals(token.getUser().hashedUsername) || (!test && !token.isVerified()))
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
        return hashedUsername.hashCode();
    }

    public String getShortHash() {
        return hashedUsername.getB64String().substring(0, Integer.min(hashedUsername.size(), 10));
    }

    public File getHome() {
        return new File(home, hashedUsername.getB64String());
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

    protected UserLogEntry[] loadLog() throws IOException, CouldNotLoadKeyException, CorruptedLogException {
        synchronized (logFile) {
            synchronized (currentUserLoggingKeyLock) {
                Base64String[] encryptedEntries = FileUtils.read(logFile);
                UserLogEntry[] decryptedEntries = new UserLogEntry[encryptedEntries.length];
                currentUserLoggingKey = firstUserLoggingKey;
                for (int i = 0; i < encryptedEntries.length; i++) {
                    try {
                        SecretKey encryptionKey = deriveLogEncryptionKey();
                        SecretKey signingKey = deriveLogSigningKey();
                        String entry = new String(SymmetricUtils.decrypt(encryptedEntries[i], encryptionKey));
                        CSVRecord unverifiedRecord = CSVUtils.parseRecord(entry).getRecords().get(0);
                        decryptedEntries[i] = UserLogEntry.fromCSV(unverifiedRecord, signingKey);
                        iterateLoggingKey();
                    } catch (BadCiphertextException | IllegalArgumentException err) {
                        throw new CorruptedLogException();
                    }
                }
                return decryptedEntries;
            }
        }
    }

    public UserLogEntry[] loadLog(Token token) throws IOException, CouldNotLoadKeyException, CorruptedLogException, IllegalTokenException {
        verifyToken(token);
        Sys.debug("Loading log.", token);
        return loadLog();
    }

    private void appendToLog(LogType logType, String message, String affectedUser, String ip) {
        synchronized (logFile) {
            synchronized (currentUserLoggingKeyLock) {
                try {
                    SecretKey encryptionKey = deriveLogEncryptionKey();
                    SecretKey signingKey = deriveLogSigningKey();
                    UserLogEntry entry = new UserLogEntry(logType, ip, affectedUser, LocalDateTime.now(), message, signingKey);
                    FileUtils.append(logFile, SymmetricUtils.encrypt(entry.toCSV().getBytes(), encryptionKey));
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

    public void error(String message, User affectedUser, String ip) {
        appendToLog(LogType.ERROR, message, affectedUser.getShortHash(), ip);
    }

    public void error(String message, User affectedUser) {
        appendToLog(LogType.ERROR, message, affectedUser.getShortHash(), NO_IP);
    }

    public void error(String message, String ip) {
        appendToLog(LogType.ERROR, message, NO_USER, ip);
    }

    public void error(String message) {
        appendToLog(LogType.ERROR, message, NO_USER, NO_IP);
    }

    public void warning(String message, User affectedUser, String ip) {
        appendToLog(LogType.WARNING, message, affectedUser.getShortHash(), ip);
    }

    public void warning(String message, String ip) {
        appendToLog(LogType.WARNING, message, NO_USER, ip);
    }

    public void warning(String message, User affectedUser) {
        appendToLog(LogType.WARNING, message, affectedUser.getShortHash(), NO_IP);
    }

    public void warning(String message) {
        appendToLog(LogType.WARNING, message, NO_USER, NO_IP);
    }

    public void info(String message, User affectedUser, String ip) {
        appendToLog(LogType.INFO, message, affectedUser.getShortHash(), ip);
    }

    public void info(String message, String ip) {
        appendToLog(LogType.INFO, message, NO_USER, ip);
    }

    public void info(String message, User affectedUser) {
        appendToLog(LogType.INFO, message, affectedUser.getShortHash(), NO_IP);
    }

    public void info(String message) {
        appendToLog(LogType.INFO, message, NO_USER, NO_IP);
    }
}
