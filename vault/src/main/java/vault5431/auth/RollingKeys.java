package vault5431.auth;

import vault5431.crypto.SymmetricUtils;

import javax.crypto.SecretKey;
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

    private static SecretKey encryptionKey = SymmetricUtils.getNewKey();
    private static SecretKey signingKey = SymmetricUtils.getNewKey();

    static {

        final Runnable keyRoller = () -> {
            encryptionKey = SymmetricUtils.getNewKey();
            signingKey = SymmetricUtils.getNewKey();
        };

        scheduler.scheduleAtFixedRate(
                keyRoller,
                LocalDateTime.now().until(getEndOfCurrentWindow(), MILLIS),
                24 * 60 * 60 * 1000,
                MILLISECONDS
        );

    }

    public static SecretKey getEncryptionKey() {
        return encryptionKey;
    }

    public static SecretKey getSigningKey() {
        return signingKey;
    }

    public static LocalDateTime getEndOfCurrentWindow() {
        return LocalDateTime.now().plusDays(1).withHour(0).withMinute(0).withSecond(0).withNano(0);
    }

}
