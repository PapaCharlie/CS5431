package vault5431.users;

import org.apache.commons.csv.CSVRecord;
import vault5431.Password;
import vault5431.Sys;
import vault5431.auth.ExecutionContext;
import vault5431.auth.Token;
import vault5431.crypto.AsymmetricUtils;
import vault5431.crypto.PasswordUtils;
import vault5431.crypto.SigningUtils;
import vault5431.crypto.exceptions.CouldNotLoadKeyException;
import vault5431.crypto.exceptions.InvalidMasterPasswordException;
import vault5431.crypto.exceptions.InvalidPublicKeySignature;
import vault5431.io.Base64String;
import vault5431.io.FileUtils;
import vault5431.logging.CSVUtils;
import vault5431.logging.LogType;
import vault5431.logging.UserLogEntry;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;

import static vault5431.Sys.NO_IP;
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
    public final File passwordHashFile;
    public final File passwordSaltFile;
    public final File pubCryptoKeyFile;
    public final File pubCryptoSigFile;
    public final File pubSigningKeyFile;
    public final File pubSigningSigFile;
    public final File signingKeyFile;
    public final File cryptoKeyFile;

    protected User(String username) {
        this(UserManager.hashUsername(username));
    }

    protected User(Base64String hash) {
        this.hash = hash;
        logFile = new File(getHome(), "log");
        privCryptoKeyfile = new File(getHome(), "id_rsa.crypto");
        privSigningKeyFile = new File(getHome(), "id_rsa.signing");
        vaultFile = new File(getHome(), "vault");
        passwordHashFile = new File(getHome(), "password.hash");
        passwordSaltFile = new File(getHome(), "salt");

        pubCryptoKeyFile = new File(privCryptoKeyfile + ".pub");
        pubCryptoSigFile = new File(pubCryptoKeyFile + ".sig");
        pubSigningKeyFile = new File(privSigningKeyFile + ".pub");
        pubSigningSigFile = new File(pubSigningKeyFile + ".sig");
        signingKeyFile = new File(getHome(), "signing.key");
        cryptoKeyFile = new File(getHome(), "crypto.key");
    }

    public String getShortHash() {
        return hash.getB64String().substring(0, Integer.min(hash.length(), 10));
    }

    public File getHome() {
        return new File(home, hash.getB64String());
    }

    public PublicKey loadPublicSigningKey(Token token) throws IOException, InvalidPublicKeySignature, CouldNotLoadKeyException, InvalidKeyException {
        debug("Loading public signing key.", token.getIp());
        PublicKey key = AsymmetricUtils.loadPublicKey(pubSigningKeyFile);
        if (!SigningUtils.verifyPublicKeySignature(key, Base64String.loadFromFile(pubSigningSigFile)[0])) {
            throw new InvalidPublicKeySignature();
        } else {
            return key;
        }
    }

    public PrivateKey loadPrivateSigningKey(Token token) throws IOException, InvalidKeyException, CouldNotLoadKeyException, InvalidMasterPasswordException {
        synchronized (privSigningKeyFile) {
            debug("Loading private signing key", token.getIp());
            return AsymmetricUtils.loadPrivateKey(privSigningKeyFile, token.getKey());
        }
    }

    public PublicKey loadPublicCryptoKey(Token token) throws IOException, InvalidPublicKeySignature, CouldNotLoadKeyException {
        debug("Loading public crypto key", token.getIp());
        PublicKey key = AsymmetricUtils.loadPublicKey(pubCryptoKeyFile);
        if (!SigningUtils.verifyPublicKeySignature(key, Base64String.loadFromFile(pubCryptoSigFile)[0])) {
            throw new InvalidPublicKeySignature();
        } else {
            return key;
        }
    }

    public PrivateKey loadPrivateCryptoKey(Token token)
            throws IOException, InvalidKeyException, CouldNotLoadKeyException, InvalidMasterPasswordException {
        synchronized (privCryptoKeyfile) {
            debug("Loading private signing key", token.getIp());
            return AsymmetricUtils.loadPrivateKey(privCryptoKeyfile, token.getKey());
        }
    }

    public void addPasswordToVault(Password password, Token token) throws IOException {
        synchronized (vaultFile) {
            info(String.format("Adding password: %s.", password.getName()), token.getIp());
            FileUtils.append(vaultFile, new Base64String(password.toRecord()));
        }
    }

    public boolean verifyPassword(String password) throws IOException {
        synchronized (passwordHashFile) {
            try {
                if (PasswordUtils.verifyPasswordInFile(passwordHashFile, password)) {
                    return true;
                } else {
                    warning("Failed password verification attempt.");
                    return false;
                }
            } catch (InvalidKeyException err) {
                warning("Failed password verification attempt.");
                return false;
            }
        }
    }

    public Password[] loadPasswords(Token token) throws IOException {
        synchronized (vaultFile) {
            debug("Loading passwords.", token.getIp());
            if (!vaultFile.exists()) {
                Sys.error("User's vault file could not be found.", this);
                return new Password[0];
            }
            try {
                Base64String[] encodedPasswords = FileUtils.read(vaultFile);
                Password[] passwords = new Password[encodedPasswords.length];
                for (int i = 0; i < encodedPasswords.length; i++) {
                    passwords[i] = Password.fromCSVRecord(CSVUtils.parseRecord(encodedPasswords[i].decodeString()).getRecords().get(0));
                }
                return passwords;
            } catch (IOException err) {
                error("Could not load or parse passwords!");
                throw err;
            }
        }
    }

    public void appendToLog(UserLogEntry entry) {
        synchronized (logFile) {
            try {
                System.out.println(entry.toString());
                FileUtils.append(logFile, new Base64String(entry.toCSV()));
            } catch (IOException err) {
                err.printStackTrace();
                warning("Failed to log for user! Continuing (not recommended).", this);
                System.err.printf("[WARNING] Failed to log as user %s! Continuing (not recommended).%n", hash.getB64String().substring(10));
//            } catch (InvalidKeySpecException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException err) {
//                err.printStackTrace();
//                Sys.error("Could not append to user log.", this);
            }
        }
    }

    private byte[] loadSalt() throws IOException {
        synchronized (passwordSaltFile) {
            return Base64String.loadFromFile(passwordSaltFile)[0].decodeBytes();
        }
    }

    public SecretKey deriveSecretKey(String password) throws IOException {
        return PasswordUtils.deriveKey(password, loadSalt());
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

    public void debug(String message, User affectedUser, String ip) {
        appendToLog(new UserLogEntry(LogType.DEBUG, ip, affectedUser, LocalDateTime.now(), message, ""));
    }

    public void debug(String message, String ip) {
        appendToLog(new UserLogEntry(LogType.DEBUG, ip, NO_USER, LocalDateTime.now(), message, ""));
    }

    public void debug(String message, User affectedUser) {
        appendToLog(new UserLogEntry(LogType.DEBUG, NO_IP, affectedUser, LocalDateTime.now(), message, ""));
    }

    public void debug(String message) {
        appendToLog(new UserLogEntry(LogType.DEBUG, NO_IP, NO_USER, LocalDateTime.now(), message, ""));
    }

    public UserLogEntry[] loadLog(Token token) throws IOException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        synchronized (logFile) {
            debug("Loading log.", token.getIp());
            Base64String[] encryptedEntries = FileUtils.read(logFile);
            UserLogEntry[] decryptedEntries = new UserLogEntry[encryptedEntries.length];
            for (int i = 0; i < encryptedEntries.length; i++) {
                CSVRecord record = CSVUtils.parseRecord(encryptedEntries[i].decodeString()).getRecords().get(0);
                decryptedEntries[i] = UserLogEntry.fromCSV(record);
            }
            return decryptedEntries;
        }
    }
}
