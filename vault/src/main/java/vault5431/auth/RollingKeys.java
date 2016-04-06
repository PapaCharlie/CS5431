package vault5431.auth;

import vault5431.crypto.SigningUtils;
import vault5431.crypto.SymmetricUtils;
import vault5431.crypto.exceptions.BadCiphertextException;
import vault5431.io.Base64String;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import java.security.InvalidKeyException;
import java.time.LocalDateTime;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static java.time.temporal.ChronoUnit.MILLIS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;


/**
 * Created by papacharlie on 4/5/16.
 */
public class RollingKeys {

    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private static final Object lock = new Object();
    private static SecretKey encryptionKey = SymmetricUtils.getNewKey();
    private static SecretKey signingKey = SymmetricUtils.getNewKey();

    static {

        final Runnable keyRoller = () -> {
            synchronized (lock) {
                try {
                    encryptionKey.destroy();
                    signingKey.destroy();
                    encryptionKey = SymmetricUtils.getNewKey();
                    signingKey = SymmetricUtils.getNewKey();
                } catch (DestroyFailedException err) {
                    err.printStackTrace();
                    System.err.println("Could not destroy rolling keys!!! Halting.");
                    System.exit(1);
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

    public static boolean verifySignature(byte[] content, Base64String signature) {
        synchronized (lock) {
            boolean verified = false;
            try {
                verified = SigningUtils.verifySignature(content, signature, signingKey);
            } catch (InvalidKeyException err) {
                err.printStackTrace();
                System.err.println("Current rolling key is invalid. Halting.");
                System.exit(1);
            }
            return verified;
        }
    }

    public static Base64String sign(byte[] content) {
        synchronized (lock) {
            Base64String signature = null;
            try {
                signature = SigningUtils.getSignature(content, signingKey);
            } catch (InvalidKeyException err) {
                err.printStackTrace();
                System.err.println("Current rolling key is invalid. Halting.");
                System.exit(1);
            }
            return signature;
        }
    }

    public static Base64String encrypt(byte[] content) {
        synchronized (lock) {
            Base64String encryptedContent = null;
            try {
                encryptedContent = SymmetricUtils.encrypt(content, encryptionKey);
            } catch (InvalidKeyException | BadCiphertextException err) {
                err.printStackTrace();
                System.err.println("Current rolling key is invalid. Halting.");
                System.exit(1);
            }
            return encryptedContent;
        }
    }

    public static byte[] decrypt(Base64String ciphertext) {
        synchronized (lock) {
            byte[] content = null;
            try {
                content = SymmetricUtils.decrypt(ciphertext, encryptionKey);
            } catch (InvalidKeyException | BadCiphertextException err) {
                err.printStackTrace();
                System.err.println("Current rolling key is invalid. Halting.");
                System.exit(1);
            }
            return content;
        }
    }

    public static LocalDateTime getEndOfCurrentWindow() {
        return LocalDateTime.now().plusDays(1).withHour(0).withMinute(0).withSecond(0).withNano(0);
    }

}
