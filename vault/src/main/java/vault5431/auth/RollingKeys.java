package vault5431.auth;

import vault5431.crypto.SigningUtils;
import vault5431.crypto.SymmetricUtils;
import vault5431.crypto.exceptions.BadCiphertextException;
import vault5431.io.Base64String;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import java.time.LocalDateTime;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static java.time.temporal.ChronoUnit.MILLIS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

/**
 * Used to sign and encrypt tokens. RollingKeys roll every 24 hours at midnight.
 */
public class RollingKeys {

    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private static final Object lock = new Object();
    private static SecretKey encryptionKey = SymmetricUtils.getNewKey();
    private static SecretKey signingKey = SymmetricUtils.getNewKey();

    // Roll keys every day at midnight
    static {
        final Runnable keyRoller = () -> {
            synchronized (lock) {
                try {
                    encryptionKey.destroy();
                    signingKey.destroy();
                    encryptionKey = SymmetricUtils.getNewKey();
                    signingKey = SymmetricUtils.getNewKey();
                } catch (DestroyFailedException err) {
                    // As it turns out, .destroy() is not implemented and always throws this error.
                    // See https://bugs.openjdk.java.net/browse/JDK-8008795
                    err.printStackTrace();
                    System.err.println("Cannot destroy rolling keys.");
                }
            }
        };

        scheduler.scheduleAtFixedRate(
                keyRoller,
                LocalDateTime.now().until(getEndOfCurrentWindow(), MILLIS),
                24 * 60 * 60 * 1000,
                MILLISECONDS
        );
    }

    /**
     * Sign some arbitrary content using the current rolling key
     * @param content content to sign
     * @return content's signature
     */
    public static Base64String sign(byte[] content) {
        synchronized (lock) {
            return SigningUtils.getSignature(content, signingKey);
        }
    }

    /**
     * Verify a signature based on the current rolling key
     * @param content content to verify
     * @param signature signature to verify against
     * @return true iff signature matches content
     */
    public static boolean verifySignature(byte[] content, Base64String signature) {
        synchronized (lock) {
            return SigningUtils.verifySignature(content, signature, signingKey);
        }
    }

    /**
     * Encrypt some arbitrary content using the current rolling key
     * @param content content to encrypt
     * @return encrypted content (first 16 bytes are iv)
     */
    public static Base64String encrypt(byte[] content) {
        synchronized (lock) {
            Base64String encryptedContent = null;
            try {
                encryptedContent = SymmetricUtils.encrypt(content, encryptionKey);
            } catch (BadCiphertextException err) {
                err.printStackTrace();
                System.err.println("Current rolling key is invalid. Halting.");
                System.exit(1);
            }
            return encryptedContent;
        }
    }

    /**
     * Decrypt content encrypted by {@link #encrypt(byte[])}.
     * @param ciphertext encrypted content
     * @return decrypted content
     */
    public static byte[] decrypt(Base64String ciphertext) {
        synchronized (lock) {
            byte[] content = null;
            try {
                content = SymmetricUtils.decrypt(ciphertext, encryptionKey);
            } catch (BadCiphertextException err) {
                err.printStackTrace();
                System.err.println("Current rolling key is invalid. Halting.");
                System.exit(1);
            }
            return content;
        }
    }

    /**
     * Finds the nearest midnight LocalDateTime.
     * @return next midnight
     */
    public static LocalDateTime getEndOfCurrentWindow() {
        return LocalDateTime.now().plusDays(1).withHour(0).withMinute(0).withSecond(0).withNano(0);
    }

}
