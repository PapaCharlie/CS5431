package vault5431.users;

import org.apache.commons.csv.CSVRecord;
import org.json.JSONException;
import vault5431.Password;
import vault5431.Sys;
import vault5431.auth.AuthenticationHandler;
import vault5431.auth.Token;
import vault5431.auth.exceptions.TooManyConcurrentSessionsException;
import vault5431.auth.exceptions.TooManyFailedLogins;
import vault5431.crypto.PasswordUtils;
import vault5431.crypto.SymmetricUtils;
import vault5431.crypto.exceptions.BadCiphertextException;
import vault5431.crypto.exceptions.CouldNotLoadKeyException;
import vault5431.io.Base64String;
import vault5431.io.FileUtils;
import vault5431.logging.CSVUtils;
import vault5431.logging.LogType;
import vault5431.logging.UserLogEntry;
import vault5431.users.exceptions.*;

import java.io.File;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.UUID;

import static vault5431.Sys.NO_IP;
import static vault5431.Vault.getAdminEncryptionKey;
import static vault5431.Vault.home;

/**
 * User class.
 */
public final class User {

    public static final String NO_USER = "NOUSER";

    public final Base64String hash;
    public final File logFile;
    public final File vaultFile;
    public final File vaultSaltFile;
    public final File phoneNumberFile;
    public final File settingsFile;
    public final File passwordHashFile;

    protected User(String username) {
        this(UserManager.hashUsername(username));
    }

    protected User(Base64String hash) {
        this.hash = hash;
        logFile = new File(getHome(), "log");
        vaultFile = new File(getHome(), "vault");
        vaultSaltFile = new File(getHome(), "vault.salt");
        passwordHashFile = new File(getHome(), "password.hash");
        settingsFile = new File(getHome(), "settings");
        phoneNumberFile = new File(getHome(), "phone.number");
    }

    public int hashCode() {
        return hash.hashCode();
    }

    public String getShortHash() {
        return hash.getB64String().substring(0, Integer.min(hash.length(), 10));
    }

    public File getHome() {
        return new File(home, hash.getB64String());
    }

    public String getPhoneNumber() throws IOException, CouldNotLoadPhoneNumberException {
        synchronized (phoneNumberFile) {
            Sys.debug("Loading phone number.", this);
            try {
                return new String(SymmetricUtils.decrypt(Base64String.loadFromFile(phoneNumberFile)[0], getAdminEncryptionKey()));
            } catch (BadCiphertextException err) {
                err.printStackTrace();
                throw new CouldNotLoadPhoneNumberException();
            }
        }
    }

    public Token changeMasterPassword(Base64String oldPassword, Base64String newPassword, Password[] reEncryptedPasswords, Token token)
            throws TooManyConcurrentSessionsException, TooManyFailedLogins, CouldNotLoadSettingsException, IOException {
        synchronized (passwordHashFile) {
            // Flag suspicious activity if oldPassword is incorrect. Will behave as if failed login and throw respective errors.
            Token successToken = AuthenticationHandler.acquireUnverifiedToken(this, oldPassword, token.getIp());
            if (successToken != null) {
                warning("Changing master password!", token.getIp());
                PasswordUtils.savePassword(passwordHashFile, newPassword);
                warning("Saving newly encrypted vault!", token.getIp());
                savePasswords(new LinkedList<>(Arrays.asList(reEncryptedPasswords)));
                info("Master password change succesful.", token.getIp());
            }
            return successToken;
        }
    }

    public void changeSettings(Settings settings) throws IOException, BadCiphertextException {
        synchronized (settingsFile) {
            SymmetricUtils.encrypt(settings.toJson().getBytes(), getAdminEncryptionKey()).saveToFile(settingsFile);
        }
    }

    public Settings loadSettings() throws CouldNotLoadSettingsException {
        synchronized (settingsFile) {
            try {
                return Settings.loadFromFile(settingsFile);
            } catch (IOException | BadCiphertextException | IllegalArgumentException err) {
                throw new CouldNotLoadSettingsException();
            }
        }
    }

    public void addPasswordToVault(Password password, Token token) throws IOException {
        synchronized (vaultFile) {
            info("Added password.", token.getIp());
            FileUtils.append(vaultFile, new Base64String(password.toJSON()));
        }
    }

    public void changePassword(Password password, Token token) throws IOException, VaultNotFoundException {
        synchronized (vaultFile) {
            LinkedList<Password> passwords = loadPasswords(token);
            if (passwords.removeIf((pass) -> pass.getID().equals(password.getID()))) {
                passwords.add(password);
            }
            savePasswords(passwords);
            info("Edited password.", token.getIp());
        }
    }

    public void deletePassword(UUID uuid, Token token) throws IOException, VaultNotFoundException, CorruptedVaultException {
        synchronized (vaultFile) {
            LinkedList<Password> passwords = loadPasswords(token);
            if (passwords.removeIf((pass) -> pass.getID().equals(uuid))) {
                savePasswords(passwords);
                info("Deleted password.", token.getIp());
            }
        }
    }

    private void savePasswords(LinkedList<Password> passwords) throws IOException {
        synchronized (vaultFile) {
            FileUtils.empty(vaultFile);
            for (Password password : passwords) {
                FileUtils.append(vaultFile, new Base64String(password.toJSON()));
            }
        }
    }

    public LinkedList<Password> loadPasswords(Token token) throws VaultNotFoundException {
        synchronized (vaultFile) {
            info("Loading passwords.", token.getIp());
            if (!vaultFile.exists()) {
                Sys.error("User's vault file could not be found.", this);
                throw new VaultNotFoundException();
            }
            LinkedList<Password> passwords = new LinkedList<>();
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

    public boolean verifyPassword(Base64String hashedPassword) throws IOException {
        synchronized (passwordHashFile) {
            return PasswordUtils.verifyPasswordInFile(passwordHashFile, hashedPassword);
        }
    }

    public Base64String loadVaultSalt() throws IOException, BadCiphertextException {
        synchronized (vaultSaltFile) {
            return new Base64String(SymmetricUtils.decrypt(Base64String.loadFromFile(vaultSaltFile)[0], getAdminEncryptionKey()));
        }
    }

    public void appendToLog(UserLogEntry entry) {
        synchronized (logFile) {
            try {
                FileUtils.append(logFile, SymmetricUtils.encrypt(entry.toCSV().getBytes(), getAdminEncryptionKey()));
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

    public void error(String message, User affectedUser, String ip) {
        appendToLog(new UserLogEntry(LogType.ERROR, ip, affectedUser, LocalDateTime.now(), message, ""));
    }

    public void error(String message, User affectedUser) {
        appendToLog(new UserLogEntry(LogType.ERROR, NO_IP, affectedUser, LocalDateTime.now(), message, ""));
    }

    public void error(String message, String ip) {
        appendToLog(new UserLogEntry(LogType.ERROR, ip, NO_USER, LocalDateTime.now(), message, ""));
    }

    public void error(String message) {
        appendToLog(new UserLogEntry(LogType.ERROR, NO_IP, NO_USER, LocalDateTime.now(), message, ""));
    }

    public void warning(String message, User affectedUser, String ip) {
        appendToLog(new UserLogEntry(LogType.WARNING, ip, affectedUser, LocalDateTime.now(), message, ""));
    }

    public void warning(String message, String ip) {
        appendToLog(new UserLogEntry(LogType.WARNING, ip, NO_USER, LocalDateTime.now(), message, ""));
    }

    public void warning(String message, User affectedUser) {
        appendToLog(new UserLogEntry(LogType.WARNING, NO_IP, affectedUser, LocalDateTime.now(), message, ""));
    }

    public void warning(String message) {
        appendToLog(new UserLogEntry(LogType.WARNING, NO_IP, NO_USER, LocalDateTime.now(), message, ""));
    }

    public void info(String message, User affectedUser, String ip) {
        appendToLog(new UserLogEntry(LogType.INFO, ip, affectedUser, LocalDateTime.now(), message, ""));
    }

    public void info(String message, String ip) {
        appendToLog(new UserLogEntry(LogType.INFO, ip, NO_USER, LocalDateTime.now(), message, ""));
    }

    public void info(String message, User affectedUser) {
        appendToLog(new UserLogEntry(LogType.INFO, NO_IP, affectedUser, LocalDateTime.now(), message, ""));
    }

    public void info(String message) {
        appendToLog(new UserLogEntry(LogType.INFO, NO_IP, NO_USER, LocalDateTime.now(), message, ""));
    }

    public UserLogEntry[] loadLog(Token token) throws IOException, CouldNotLoadKeyException, CorruptedLogException {
        synchronized (logFile) {
            Sys.debug("Loading log.", this, token.getIp());
            Base64String[] encryptedEntries = FileUtils.read(logFile);
            UserLogEntry[] decryptedEntries = new UserLogEntry[encryptedEntries.length];
//            PrivateKey privKey = loadPrivateCryptoKey(token);
            for (int i = 0; i < encryptedEntries.length; i++) {
                try {
                    String decryptedEntry = new String(SymmetricUtils.decrypt(encryptedEntries[i], getAdminEncryptionKey()));
                    CSVRecord record = CSVUtils.parseRecord(decryptedEntry).getRecords().get(0);
                    decryptedEntries[i] = UserLogEntry.fromCSV(record);
                } catch (BadCiphertextException err) {
                    throw new CorruptedLogException();
                }
            }
            return decryptedEntries;
        }
    }
}
