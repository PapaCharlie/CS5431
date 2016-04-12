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
    private static final int TIME_TO_EXPIRE = 60000;


    protected static void addToManager(String username, AuthMessage m) {
        authCodeManager.put(username, m);
        Runnable removeCode = () -> {
                authCodeManager.remove(username);
                System.out.println("test runnable: " + authCodeManager.size());
        };
//        System.out.println("in addToManager function: " + authCodeManager.size());
        scheduler.schedule(
                removeCode, TIME_TO_EXPIRE, MILLISECONDS);
//        System.out.println("After scheduler set: " + authCodeManager.size());
    }
}
