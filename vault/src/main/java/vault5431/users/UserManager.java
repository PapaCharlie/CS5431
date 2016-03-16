package vault5431.users;

import vault5431.crypto.AsymmetricUtils;
import vault5431.crypto.PasswordUtils;
import vault5431.crypto.SymmetricUtils;
import vault5431.io.Base64String;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

import static vault5431.Vault.home;
import static vault5431.crypto.HashUtils.hash256;

/**
 * Created by papacharlie on 3/15/16.
 */
public class UserManager {

    private static final Object mapLock = new Object();
    private static Map<Base64String, User> users = new HashMap<>();

    static {
        for (String dirname : home.list((dir, name) -> dir.isDirectory())) {
            Base64String hash = Base64String.fromBase64(dirname);
            addUser(new User(hash));
        }
    }

    private static User addUser(User user) {
        synchronized (mapLock) {
            return users.put(user.hash, user);
        }
    }

    public static Base64String hashUsername(String username) {
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

}