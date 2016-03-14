package vault5431;

import vault5431.crypto.AsymmetricUtils;
import vault5431.crypto.Base64String;
import vault5431.crypto.PasswordUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.File;
import java.io.IOError;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import static vault5431.Vault.home;
import static vault5431.crypto.HashUtils.hash512;

/**
 * User class.
 * TODO: Provide enc and dec methods
 */
public class User {

    private final Base64String hash;

    public final String logPath = getHome() + File.separator + "log";
    public final String privCryptoKeyPath = getHome() + File.separator + "id_rsa.crypto";
    public final String pubCryptoKeyPath = getHome() + File.separator + privCryptoKeyPath + ".pub";
    public final String privSigningKeyPath = getHome() + File.separator + "id_rsa.signing";
    public final String pubSigningKeyPath = getHome() + File.separator + privSigningKeyPath + ".pub";
    public final String passwordVaultPath = getHome() + File.separator + "vault";
    public final String passwordFile = getHome() + File.separator + "password";

    private static final Object mapLock = new Object();
    private static Map<Base64String, User> users = new HashMap<>();

    static {
        for (String dirname : home.list((dir, name) -> dir.isDirectory())) {
            Base64String hash = Base64String.fromHexString(dirname);
            addUser(hash);
        }
    }

    private User(String username) {
        hash = hash512(new Base64String(username));
    }

    private User(Base64String hash) {
        this.hash = hash;
    }

    private static User addUser(Base64String hash) {
        synchronized (mapLock) {
            return users.put(hash, new User(hash));
        }
    }

    private static User addUser(String username) {
        return addUser(hash512(new Base64String(username)));
    }

    public static boolean userExists(String username) {
        synchronized (mapLock) {
            return users.containsKey(hash512(new Base64String(username)));
        }
    }

    public static User getUser(Base64String hash) {
        synchronized (mapLock) {
            return users.get(hash);
        }
    }

    public static User getUser(String username) {
        return getUser(hash512(new Base64String(username)));
    }

    private String getHome() {
        return home + File.separator + hash.asHexString();
    }

    public synchronized static User create(String username, String password)
            throws IOException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        User user = null;
        synchronized (mapLock) {
            if (userExists(username)) {
                return null;
            } else {
                user = addUser(username);
            }
        }
        File homedir = new File(user.getHome());
        if (homedir.mkdir()) {
            KeyPair signingKeys = AsymmetricUtils.getNewKeyPair();
            AsymmetricUtils.savePrivateKey(user.privSigningKeyPath, signingKeys.getPrivate(), password);
            AsymmetricUtils.savePublicKey(user.pubSigningKeyPath, signingKeys.getPublic());
            KeyPair cryptoKeys = AsymmetricUtils.getNewKeyPair();
            AsymmetricUtils.savePrivateKey(user.privCryptoKeyPath, cryptoKeys.getPrivate(), password);
            AsymmetricUtils.savePublicKey(user.pubCryptoKeyPath, cryptoKeys.getPublic());
            PasswordUtils.savePassword(user.passwordFile, password);
            return user;
        } else {
            return null;
        }
    }

    public PublicKey loadPublicSigningKey() throws IOException, InvalidKeySpecException {
        return AsymmetricUtils.loadPublicKey(pubSigningKeyPath);
    }

    public PrivateKey loadPrivateSigningKey(String password)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOError, IOException, InvalidKeySpecException {
        return AsymmetricUtils.loadPrivateKey(privSigningKeyPath, password, passwordFile);
    }

    public PublicKey loadPublicCryptoKey() throws IOException, InvalidKeySpecException {
        return AsymmetricUtils.loadPublicKey(pubCryptoKeyPath);
    }

    public PrivateKey loadPrivateCryptoKey(String password)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOError, IOException, InvalidKeySpecException {
        return AsymmetricUtils.loadPrivateKey(privCryptoKeyPath, password, passwordFile);
    }

    public synchronized void appendToLog(Base64String data, boolean encrypt)
            throws IOException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Base64String toWrite = data;
        if (encrypt) {
            AsymmetricUtils.encrypt(data, loadPublicCryptoKey());
        }
        FileUtils.append(new File(logPath), toWrite);
    }

    public void appendToLog(String data) throws IOException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        appendToLog(new Base64String(data), true);
    }

//    public Base64String readLog(String password) {
//        loadPrivateCryptoKey(password);
//    }

}
