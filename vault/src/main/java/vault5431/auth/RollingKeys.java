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
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static java.time.temporal.ChronoUnit.MILLIS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

/**
 * Used to sign and encrypt tokens. RollingKeys roll every 24 hours at midnight.
 *
 * @author papacharlie
 */
final class RollingKeys {

    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private static final ReentrantReadWriteLock keyLock = new ReentrantReadWriteLock();
    private static SecretKey encryptionKey = SymmetricUtils.getNewKey();
    private static SecretKey signingKey = SymmetricUtils.getNewKey();

    // Roll keys every day at midnight
    static {
        final Runnable keyRoller = () -> {
            keyLock.writeLock().lock();
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
            } finally {
                keyLock.writeLock().unlock();
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
     * Sign some arbitrary content using the current rolling key.
     *
     * @param content content to sign
     * @return content's signature
     */
    public static Base64String sign(byte[] content) {
        keyLock.readLock().lock();
        try {
            return SigningUtils.getSignature(content, signingKey);
        } finally {
            keyLock.readLock().unlock();
        }
    }

    /**
     * Verify a signature based on the current rolling key.
     *
     * @param content   content to verify
     * @param signature signature to verify against
     * @return true iff signature matches content
     */
    public static boolean verifySignature(byte[] content, Base64String signature) {
        keyLock.readLock().lock();
        try {
            return SigningUtils.verifySignature(content, signature, signingKey);
        } finally {
            keyLock.readLock().unlock();
        }
    }

    /**
     * Encrypt some arbitrary content using the current rolling key.
     *
     * @param content content to encrypt
     * @return encrypted content (first 16 bytes are iv)
     */
    public static Base64String encrypt(byte[] content) {
        keyLock.readLock().lock();
        try {
            return SymmetricUtils.encrypt(content, encryptionKey);
        } catch (BadCiphertextException err) {
            err.printStackTrace();
            System.err.println("Current rolling key is invalid. Halting.");
            throw new RuntimeException(err);
        } finally {
            keyLock.readLock().unlock();
        }
    }

    /**
     * Decrypt content encrypted by {@link #encrypt(byte[])}.
     *
     * @param ciphertext encrypted content
     * @return decrypted content
     */
    public static byte[] decrypt(Base64String ciphertext) {
        keyLock.readLock().lock();
        try {
            return SymmetricUtils.decrypt(ciphertext, encryptionKey);
        } catch (BadCiphertextException err) {
            err.printStackTrace();
            System.err.println("Current rolling key is invalid. Halting.");
            throw new RuntimeException(err);
        } finally {
            keyLock.readLock().unlock();
        }
    }

    /**
     * Finds the nearest midnight LocalDateTime.
     *
     * @return next midnight
     */
    public static LocalDateTime getEndOfCurrentWindow() {
        return LocalDateTime.now().plusDays(1).withHour(0).withMinute(0).withSecond(0).withNano(0);
    }

}
