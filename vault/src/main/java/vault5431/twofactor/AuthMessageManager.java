package vault5431.twofactor;

import vault5431.users.User;

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
    private static final ConcurrentHashMap<String, AuthMessage> authCodeManager = new ConcurrentHashMap<String, AuthMessage>();
    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private static final int TIME_TO_EXPIRE = 60000;


    protected static void addToManager(User user, AuthMessage m) {
        authCodeManager.put(user.hash.toString(), m);
        Runnable removeCode = () -> {
                authCodeManager.remove(user.hash.toString());
                System.out.println("test runnable: " + authCodeManager.size());
        };
//        System.out.println("in addToManager function: " + authCodeManager.size());
        scheduler.schedule(
                removeCode, TIME_TO_EXPIRE, MILLISECONDS);
//        System.out.println("After scheduler set: " + authCodeManager.size());
    }

    public static boolean verifyAuthMessage(User user, int code) {
        if (authCodeManager.contains(user.hash.toString())) {
            AuthMessage message = authCodeManager.get(user.hash.toString());
            return message.authCode == code;
        } else {
            return false;
        }
    }

}
