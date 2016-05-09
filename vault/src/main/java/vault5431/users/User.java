package vault5431.users;

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
import vault5431.crypto.exceptions.InvalidSignatureException;
import vault5431.crypto.sjcl.SJCLSymmetricField;
import vault5431.io.Base64String;
import vault5431.io.FileUtils;
import vault5431.logging.CSVUtils;
import vault5431.logging.LogType;
import vault5431.logging.UserLogEntry;
import vault5431.users.exceptions.*;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashSet;
import java.util.UUID;

import static org.bouncycastle.util.Arrays.concatenate;
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
    private final File logFile;
    private final File vaultFile;
    private final File vaultSaltFile;
    private final File sharedPasswordsFile;
    private final File settingsFile;
    private final File passwordHashFile;
    private final File pubCryptoKeyFile;
    private final File privCryptoKeyFile;
    private final File pubSigningKeyFile;
    private final File privSigningKeyFile;

    private final SecretKey userEncryptionKey;
    private final SecretKey userSigningKey;
    private final SecretKey firstUserLoggingKey;
    private SecretKey currentUserLoggingKey;

    protected User(String username) {
        this(UserManager.hashUsername(username));
    }

    protected User(Base64String hashedUsername) {
        this.hashedUsername = hashedUsername;
        File home = getHome();
        logFile = new File(home, "log");
        vaultFile = new File(home, "vault");
        vaultSaltFile = new File(home, "vault.salt");
        sharedPasswordsFile = new File(home, "shared");
        passwordHashFile = new File(home, "password.hash");
        settingsFile = new File(home, "settings");
        pubCryptoKeyFile = new File(home, "crypto.pub");
        privCryptoKeyFile = new File(home, "crypto.priv");
        pubSigningKeyFile = new File(home, "signing.pub");
        privSigningKeyFile = new File(home, "signing.priv");

        userEncryptionKey = SymmetricUtils.combine(getAdminEncryptionKey(), hashedUsername);
        userSigningKey = SymmetricUtils.combine(getAdminSigningKey(), hashedUsername);
        firstUserLoggingKey = SymmetricUtils.combine(getAdminLoggingKey(), hashedUsername);
        currentUserLoggingKey = firstUserLoggingKey;
    }

    /**
     * Initialize the User. This means creating all the required files.
     *
     * @param hashedPassword
     * @param phoneNumber
     * @param pubCryptoKey
     * @param privCryptoKey
     * @param pubSigningKey
     * @param privSigningKey
     * @throws CouldNotCreateUserException
     */
    protected void initialize(Base64String hashedPassword,
                              String phoneNumber,
                              Base64String pubCryptoKey,
                              SJCLSymmetricField privCryptoKey,
                              Base64String pubSigningKey,
                              SJCLSymmetricField privSigningKey) throws CouldNotCreateUserException {
        try {
            Sys.debug("Creating user home directory.", this);
            File homedir = getHome();
            if (homedir.mkdir()) {
                Sys.debug("Created user home directory.", this);
                if (!vaultFile.createNewFile()) {
                    Sys.error("Could not create vault file!.", this);
                    throw new CouldNotCreateUserException();
                } else {
                    Sys.info("Created vault file.", this);
                }
                if (!sharedPasswordsFile.createNewFile()) {
                    Sys.error("Could not create shared passwords file!.", this);
                    throw new CouldNotCreateUserException();
                } else {
                    Sys.info("Created vault file.", this);
                }
                PasswordUtils.hashAndSavePassword(passwordHashFile, hashedPassword);
                saveSettings(new Settings(phoneNumber));
                saveAndSignPublicEncryptionKey(pubCryptoKey);
                saveAndSignPublicSigningKey(pubSigningKey);
                new Base64String(privCryptoKey.toString()).saveToFile(privCryptoKeyFile);
                new Base64String(privSigningKey.toString()).saveToFile(privSigningKeyFile);
                generateNewVaultSalt();


                Sys.info("Successfully created user.", this);
                info("Your account was successfully created!");
            } else {
                Sys.error("Could not create directory! Not adding to user map.", this);
                org.apache.commons.io.FileUtils.deleteDirectory(getHome());
            }
        } catch (Exception err) {
            try {
                org.apache.commons.io.FileUtils.deleteDirectory(getHome());
            } catch (Exception ex) {
                throw new CouldNotCreateUserException(ex);
            }
            throw new CouldNotCreateUserException(err);
        }
    }

    private void verifyToken(Token token) throws IllegalTokenException {
        if (
                (!this.hashedUsername.equals(token.getUser().hashedUsername)
                        || (!test && !token.isVerified())
                ) && !token.isExpired())
            throw new IllegalTokenException();
    }

    public int hashCode() {
        return hashedUsername.hashCode();
    }

    public String getShortHash() {
        return hashedUsername.getB64String().substring(0, Integer.min(hashedUsername.size(), 10));
    }

    private File getHome() {
        return new File(home, hashedUsername.getB64String());
    }

    private void saveAndSignPublicKey(File file, Base64String pubKey) throws IOException {
        FileUtils.empty(file);
        FileUtils.append(file, pubKey);
        FileUtils.append(file, SigningUtils.sign(concatenate(hashedUsername.decodeBytes(), pubKey.decodeBytes()), userSigningKey));
    }

    private String loadAndVerifyPublicKey(File file) throws IOException, InvalidPublicKeySignature {
        Base64String[] data = FileUtils.read(file);
        if (SigningUtils.verify(concatenate(hashedUsername.decodeBytes(), data[0].decodeBytes()), data[1], userSigningKey)) {
            return data[0].getB64String();
        } else {
            throw new InvalidPublicKeySignature();
        }
    }

    protected void generateNewVaultSalt() throws IOException, BadCiphertextException {
        synchronized (vaultSaltFile) {
            SymmetricUtils.authEnc(
                    PasswordUtils.generateSalt(),
                    userEncryptionKey,
                    userSigningKey
            ).saveToFile(vaultSaltFile);
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
            Token successToken = AuthenticationHandler.changeMasterPassword(token, oldPassword);
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

    protected void saveSettings(Settings settings) throws IOException, BadCiphertextException {
        synchronized (settingsFile) {
            settings.saveToFile(settingsFile, userEncryptionKey, userSigningKey);
        }
    }

    public void changeSettings(Settings settings, Token token) throws IOException, BadCiphertextException, IllegalTokenException {
        synchronized (settingsFile) {
            verifyToken(token);
            settings.saveToFile(settingsFile, userEncryptionKey, userSigningKey);
        }
    }

    public Settings loadSettings() throws CouldNotLoadSettingsException {
        synchronized (settingsFile) {
            try {
                return Settings.loadFromFile(settingsFile, userEncryptionKey, userSigningKey);
            } catch (IOException | InvalidSignatureException | IllegalArgumentException err) {
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

    private HashSet<SharedPassword> loadSharedPasswords() throws VaultNotFoundException {
        synchronized (sharedPasswordsFile) {
            info("Loading shared passwords.");
            if (!sharedPasswordsFile.exists()) {
                Sys.error("User's shared passwords file could not be found.", this);
                throw new VaultNotFoundException();
            }
            Base64String[] loadedPasswords;
            try {
                loadedPasswords = Base64String.loadFromFile(sharedPasswordsFile);
            } catch (IOException err) {
                err.printStackTrace();
                error("Could not find vault!");
                throw new VaultNotFoundException();
            }
            HashSet<SharedPassword> sharedPasswords = new HashSet<>(loadedPasswords.length);
            for (Base64String base64String : loadedPasswords) {
                try {
                    sharedPasswords.add(SharedPassword.fromJSON(base64String));
                } catch (IllegalArgumentException | JSONException err) {
                    err.printStackTrace();
                    error("Shared password was corrupted! Loading remaining passwords.");
                }
            }

            return sharedPasswords;
        }
    }

    public void addSharedPassword(SharedPassword sharedPassword, Token token) throws IOException, VaultNotFoundException, AlreadySharingPasswordException {
        synchronized (sharedPasswordsFile) {
            info(String.format("%s has shared a password with you.", token.getUsername()));
            HashSet<SharedPassword> sharedPasswords = loadSharedPasswords();
            if (sharedPasswords.stream().anyMatch((other) -> other.getSharer().equals(token.getUsername()))) {
                throw new AlreadySharingPasswordException();
            }
            boolean validUUID = false;
            while (!validUUID) {
                if (sharedPasswords.stream().anyMatch((other) -> other.getID().equals(sharedPassword.getID()))) {
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
            HashSet<Password> filteredPasswords = new HashSet<>(passwords.size());
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

    public Base64String loadVaultSalt(Token token) throws IOException, InvalidSignatureException, IllegalTokenException {
        synchronized (vaultSaltFile) {
            verifyToken(token);
            return new Base64String(SymmetricUtils.authDec(Base64String.loadFromFile(vaultSaltFile)[0], userEncryptionKey, userSigningKey));
        }
    }

    protected UserLogEntry[] loadLog() throws IOException, CouldNotLoadKeyException, CorruptedLogException {
        synchronized (logFile) {
            synchronized (firstUserLoggingKey) {
                Base64String[] encryptedEntries = FileUtils.read(logFile);
                UserLogEntry[] decryptedEntries = new UserLogEntry[encryptedEntries.length];
                currentUserLoggingKey = firstUserLoggingKey;
                for (int i = 0; i < encryptedEntries.length; i++) {
                    try {
                        SecretKey encryptionKey = deriveLogEncryptionKey();
                        SecretKey signingKey = deriveLogSigningKey();
                        String entry = new String(SymmetricUtils.authDec(encryptedEntries[i], encryptionKey, signingKey));
                        decryptedEntries[i] = UserLogEntry.fromCSV(CSVUtils.parseRecord(entry).getRecords().get(0));
                        iterateLoggingKey();
                    } catch (IllegalArgumentException | InvalidSignatureException err) {
                        throw new CorruptedLogException(err);
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
            synchronized (firstUserLoggingKey) {
                try {
                    SecretKey encryptionKey = deriveLogEncryptionKey();
                    SecretKey signingKey = deriveLogSigningKey();
                    UserLogEntry entry = new UserLogEntry(logType, ip, affectedUser, LocalDateTime.now(), message);
                    FileUtils.append(logFile, SymmetricUtils.authEnc(entry.toCSV().getBytes(), encryptionKey, signingKey));
                    iterateLoggingKey();
                    System.out.println("[" + getShortHash() + "] " + entry.toString());
                } catch (IOException | BadCiphertextException err) {
                    throw new RuntimeException(err);
                }
            }
        }
    }

    private void iterateLoggingKey() {
        synchronized (firstUserLoggingKey) {
            currentUserLoggingKey = SymmetricUtils.hashIterateKey(currentUserLoggingKey);
        }
    }

    private SecretKey deriveLogEncryptionKey() {
        synchronized (firstUserLoggingKey) {
            return SymmetricUtils.combine(currentUserLoggingKey, "encryption".getBytes());
        }
    }

    private SecretKey deriveLogSigningKey() {
        synchronized (firstUserLoggingKey) {
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
