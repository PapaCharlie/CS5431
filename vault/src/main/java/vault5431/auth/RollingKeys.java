package vault5431.auth;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static java.util.concurrent.TimeUnit.HOURS;
import static vault5431.crypto.SymmetricUtils.getNewKey;


/**
 * Created by papacharlie on 4/5/16.
 */
public class RollingKeys {

    public static final int WINDOW_LENGTH = 24;

    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    private static SecretKey encryptionKey;
    private static SecretKey signingKey;

    static {

        final Runnable refresher = () -> {
            encryptionKey = getNewKey();
            signingKey = getNewKey();
        };

        scheduler.scheduleAtFixedRate(refresher, 0, WINDOW_LENGTH, HOURS);

    }

    public static SecretKey getEncryptionKey() {
        return encryptionKey;
    }

    public static SecretKey getSigningKey() {
        return signingKey;
    }

    public static LocalDateTime getEndOfCurrentWindow() {
        return null;
    }

}
