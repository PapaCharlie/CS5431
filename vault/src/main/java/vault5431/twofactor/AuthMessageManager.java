package vault5431.twofactor;

import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static java.time.temporal.ChronoUnit.MILLIS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

/**
 * Created by cyj on 4/9/16.
 */
public class AuthMessageManager {
    protected static ConcurrentHashMap<String, AuthMessage> authCodeManager = new ConcurrentHashMap<String, AuthMessage>();
    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private static final Object lock = new Object();


    protected static void addToManager(String username, AuthMessage m) {
        authCodeManager.put(username, m);
        Runnable removeCode = () -> {
            synchronized (lock) {
                authCodeManager.remove(username);
            }
        };

        scheduler.schedule(
                removeCode, LocalDateTime.now().until(LocalDateTime.now()
                        .plusDays(0).withHour(0).withMinute(3).withSecond(0)
                        .withNano(0), MILLIS), MILLISECONDS);
    }
}
