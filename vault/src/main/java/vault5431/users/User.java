package vault5431.users;

import org.apache.commons.csv.CSVRecord;
import vault5431.Password;
import vault5431.Sys;
import vault5431.auth.Token;
import vault5431.crypto.AsymmetricUtils;
import vault5431.crypto.PasswordUtils;
import vault5431.crypto.SigningUtils;
import vault5431.crypto.SymmetricUtils;
import vault5431.crypto.exceptions.BadCiphertextException;
import vault5431.crypto.exceptions.CouldNotLoadKeyException;
import vault5431.crypto.exceptions.InvalidPublicKeySignature;
import vault5431.io.Base64String;
import vault5431.io.FileUtils;
import vault5431.logging.CSVUtils;
import vault5431.logging.LogType;
import vault5431.logging.UserLogEntry;
import vault5431.users.exceptions.CorruptedLogException;
import vault5431.users.exceptions.CorruptedVaultException;
import vault5431.users.exceptions.CouldNotLoadPhoneNumberException;
import vault5431.users.exceptions.VaultNotFoundException;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;

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
    public final File privCryptoKeyfile;
    public final File privSigningKeyFile;
    public final File vaultFile;
    public final File phoneNumber;
    public final File vaultSaltFile;
    public final File passwordHashFile;
    public final File pubCryptoKeyFile;
    public final File pubCryptoSigFile;
    public final File pubSigningKeyFile;
    public final File pubSigningSigFile;

    protected User(String username) {
        this(UserManager.hashUsername(username));
    }

    protected User(Base64String hash) {
        this.hash = hash;
        logFile = new File(getHome(), "log");
        privCryptoKeyfile = new File(getHome(), "id_rsa.crypto");
        privSigningKeyFile = new File(getHome(), "id_rsa.signing");
        vaultFile = new File(getHome(), "vault");
        vaultSaltFile = new File(getHome(), "vault.salt");
        passwordHashFile = new File(getHome(), "password.hash");
        phoneNumber = new File(getHome(), "phone.number");
        pubCryptoKeyFile = new File(privCryptoKeyfile + ".pub");
        pubCryptoSigFile = new File(pubCryptoKeyFile + ".sig");
        pubSigningKeyFile = new File(privSigningKeyFile + ".pub");
        pubSigningSigFile = new File(pubSigningKeyFile + ".sig");
    }


    public String getShortHash() {
        return hash.getB64String().substring(0, Integer.min(hash.length(), 10));
    }

    public File getHome() {
        return new File(home, hash.getB64String());
    }

    public String getPhoneNumber() throws IOException, CouldNotLoadPhoneNumberException {
        synchronized (phoneNumber) {
            Sys.debug("Loading phone number.", this);
            try {
                return new String(SymmetricUtils.decrypt(Base64String.loadFromFile(phoneNumber)[0], getAdminEncryptionKey()));
            } catch (BadCiphertextException err) {
                err.printStackTrace();
                throw new CouldNotLoadPhoneNumberException();
            }
        }
    }

    public PublicKey loadPublicSigningKey() throws IOException, InvalidPublicKeySignature, CouldNotLoadKeyException {
        Sys.debug("Loading public signing key.", this);
        PublicKey key = AsymmetricUtils.loadPublicKey(pubSigningKeyFile);
        if (!SigningUtils.verifyPublicKeySignature(key, Base64String.loadFromFile(pubSigningSigFile)[0])) {
            throw new InvalidPublicKeySignature();
        } else {
            return key;
        }
    }

    public PrivateKey loadPrivateSigningKey(Token token) throws IOException, CouldNotLoadKeyException {
        synchronized (privSigningKeyFile) {
            Sys.debug("Loading private signing key", this);
            return AsymmetricUtils.loadPrivateKey(privSigningKeyFile, getAdminEncryptionKey());
        }
    }

    public PublicKey loadPublicCryptoKey() throws IOException, InvalidPublicKeySignature, CouldNotLoadKeyException {
        Sys.debug("Loading public crypto key", this);
        PublicKey key = AsymmetricUtils.loadPublicKey(pubCryptoKeyFile);
        if (!SigningUtils.verifyPublicKeySignature(key, Base64String.loadFromFile(pubCryptoSigFile)[0])) {
            throw new InvalidPublicKeySignature();
        } else {
            return key;
        }
    }

    public PrivateKey loadPrivateCryptoKey(Token token) throws IOException, CouldNotLoadKeyException {
        synchronized (privCryptoKeyfile) {
            Sys.debug("Loading private signing key", this, token.getIp());
            return AsymmetricUtils.loadPrivateKey(privCryptoKeyfile, getAdminEncryptionKey());
        }
    }

    public void addPasswordToVault(Base64String password, Token token) throws IOException {
        synchronized (vaultFile) {
            info("Added password.", token.getIp());
            FileUtils.append(vaultFile, password);
        }
    }

    public void changePassword(String id, Base64String password, Token token) throws IOException, VaultNotFoundException {
        synchronized (vaultFile) {
            Base64String[] passwords = loadPasswords(token);
            for (int i = 0; i < passwords.length; i++) {
                String decoded = passwords[i].decodeString();
                if (decoded.replace(" ", "").contains("\"id\":\"" + id + "\"")) {
                    passwords[i] = password;
                }
            }
            savePasswords(passwords);
            info("Edited password", token.getIp());
        }
    }

    public void deletePassword(String id, Token token) throws IOException, VaultNotFoundException {
        synchronized (vaultFile) {
            Base64String[] passwords = loadPasswords(token);
            ArrayList<Base64String> removed = new ArrayList<>(passwords.length - 1);
            for (Base64String password : passwords) {
                String decoded = password.decodeString();
                if (!decoded.replace(" ", "").contains("\"id\":\"" + id + "\"")) {
                    removed.add(password);
                }
            }
            savePasswords(removed.toArray(new Base64String[removed.size()]));
            info("Deleted password", token.getIp());
        }
    }

    private void savePasswords(Base64String[] passwords) throws IOException {
        synchronized (vaultFile) {
            FileUtils.empty(vaultFile);
            for (Base64String password : passwords) {
                FileUtils.append(vaultFile, password);
            }
        }
    }

    public Base64String[] loadPasswords(Token token) throws VaultNotFoundException {
        synchronized (vaultFile) {
            info("Loading passwords.", token.getIp());
            if (!vaultFile.exists()) {
                Sys.error("User's vault file could not be found.", this);
                throw new VaultNotFoundException();
            }
            Base64String[] passwords = null;
            try {
                passwords = Base64String.loadFromFile(vaultFile);
            } catch (IOException err) {
                err.printStackTrace();
                error("Could not find vault!");
                throw new VaultNotFoundException();
            }
            return passwords;
        }
    }

    public boolean verifyPassword(Base64String hashedPassword) throws IOException {
        synchronized (passwordHashFile) {
            if (PasswordUtils.verifyPasswordInFile(passwordHashFile, hashedPassword.decodeString())) {
                return true;
            } else {
                warning("Failed password verification attempt.");
                return false;
            }
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
                PublicKey pubKey = loadPublicCryptoKey();
                FileUtils.append(logFile, AsymmetricUtils.encrypt(entry.toCSV().getBytes(), pubKey));
                System.out.println(entry.toString());
            } catch (IOException err) {
                err.printStackTrace();
                warning("Failed to log for user! Continuing (not recommended).", this);
                System.err.printf("[WARNING] Failed to log as user %s! Continuing (not recommended).%n", getShortHash());
            } catch (BadCiphertextException err) {
                err.printStackTrace();
                Sys.error("Serialization of log entry was too long, or unencryptable.", this);
            } catch (InvalidPublicKeySignature err) {
                Sys.error("User's public key does not match the signature! Halting.", this);
                throw new RuntimeException("Invalid public key signature.");
            } catch (CouldNotLoadKeyException err) {
                Sys.error("Key could not be loaded from disk. Requires immediate attention.", this);
                throw new RuntimeException("Cannot load key from disk.");
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
            PrivateKey privKey = loadPrivateCryptoKey(token);
            for (int i = 0; i < encryptedEntries.length; i++) {
                try {
                    String decryptedEntry = new String(AsymmetricUtils.decrypt(encryptedEntries[i], privKey));
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
