package vault5431.twofactor;

import com.twilio.sdk.TwilioRestClient;
import com.twilio.sdk.TwilioRestException;
import com.twilio.sdk.resource.factory.MessageFactory;
import com.twilio.sdk.resource.instance.Message;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import vault5431.Sys;
import vault5431.io.Base64String;
import vault5431.users.User;
import vault5431.users.exceptions.CouldNotLoadPhoneNumberException;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static java.time.temporal.ChronoUnit.MILLIS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

/**
 * Created by cyj on 4/9/16.
 */
public class AuthMessageManager {
    private static final HashMap<Base64String, AuthMessage> authCodeManager = new HashMap<>();
    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private static final int TIME_TO_EXPIRE = 60000;
    private static final String ACCOUNT_SID = "AC0fde3a15c4eb806040031e5994a6f987";
    private static final String AUTH_TOKEN = "a8113b81179e3832fc3b780590a29b4e";

    public static int sendAuthMessage(User user) throws IOException, CouldNotLoadPhoneNumberException {
        if (!isWaiting(user)) {
            TwilioRestClient client = new TwilioRestClient(ACCOUNT_SID, AUTH_TOKEN);
            AuthMessage auth = new AuthMessage();

            List<NameValuePair> params = new ArrayList<>();
            params.add(new BasicNameValuePair("To", user.getPhoneNumber()));
            params.add(new BasicNameValuePair("From", "+14848689228"));
            params.add(new BasicNameValuePair("Body", auth.toString()));

            MessageFactory msgFactory = client.getAccount().getMessageFactory();
            Message sms = null;
            try {
                sms = msgFactory.create(params);
                addToManager(user, auth);
            } catch (TwilioRestException t) {
                System.out.println("Error creating message: " + t.getErrorMessage());
                System.out.println("Additional Info: " + t.getMoreInfo());
                return 0;
            }
            return auth.authCode;
        } else {
            return authCodeManager.get(user.hash).authCode;
        }
    }

    private static void addToManager(User user, AuthMessage m) {
        synchronized (authCodeManager) {
            authCodeManager.put(user.hash, m);
        }
        Runnable removeCode = () -> {
            synchronized (authCodeManager) {
                authCodeManager.remove(user.hash);
            }
            Sys.debug("AuthMessage timed out.", user);
        };
        scheduler.schedule(removeCode, TIME_TO_EXPIRE, MILLISECONDS);
    }

    public static boolean verifyAuthMessage(User user, int code) {
        synchronized (authCodeManager) {
            if (isWaiting(user)) {
                AuthMessage message = authCodeManager.get(user.hash);
                return message.authCode == code;
            } else {
                System.out.println(user.getShortHash() + " is not waiting.");
                return false;
            }
        }
    }

    public static boolean isWaiting(User user) {
        synchronized (authCodeManager) {
            return authCodeManager.containsKey(user.hash);
        }
    }

}
