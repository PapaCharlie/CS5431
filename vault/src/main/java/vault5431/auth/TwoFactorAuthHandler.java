package vault5431.auth;

import com.twilio.sdk.TwilioRestClient;
import com.twilio.sdk.TwilioRestException;
import com.twilio.sdk.resource.factory.MessageFactory;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import vault5431.Sys;
import vault5431.auth.exceptions.TooMany2FAAttemptsException;
import vault5431.users.User;
import vault5431.users.exceptions.CouldNotDecryptPhoneNumberException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static java.util.concurrent.TimeUnit.MILLISECONDS;

/**
 * Created by cyj on 4/9/16.
 */
class TwoFactorAuthHandler {

    private static final int MAX_2FA_ATTEMPTS = 10;

    private static final HashMap<User, AuthMessage> authCodeMap = new HashMap<>();
    private static final HashMap<User, Integer> attemptsMap = new HashMap<>();

    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private static final int TIME_TO_EXPIRE = 60000;
    private static final String ACCOUNT_SID = "AC0fde3a15c4eb806040031e5994a6f987";
    private static final String AUTH_TOKEN = "a8113b81179e3832fc3b780590a29b4e";
    private static final String ADMIN_PHONE_NUMBER = "+16072755431";

    public static int sendAuthMessage(User user) throws IOException, CouldNotDecryptPhoneNumberException, TwilioRestException {
        if (!isWaiting(user)) {
            TwilioRestClient client = new TwilioRestClient(ACCOUNT_SID, AUTH_TOKEN);
            AuthMessage auth = new AuthMessage();

            List<NameValuePair> params = new ArrayList<>();
            params.add(new BasicNameValuePair("To", user.getPhoneNumber()));
            params.add(new BasicNameValuePair("From", ADMIN_PHONE_NUMBER));
            params.add(new BasicNameValuePair("Body", auth.toString()));

            MessageFactory msgFactory = client.getAccount().getMessageFactory();

            if (false) { // set to false for testing
                msgFactory.create(params);
                addToManager(user, auth);
            } else {
                addToManager(user, auth);
                System.out.println(auth.toString());
            }
            return auth.authCode;
        } else {
            synchronized (authCodeMap) {
                return authCodeMap.get(user).authCode;
            }
        }
    }

    protected static void removeUser(User user) {
        synchronized (authCodeMap) {
            authCodeMap.remove(user);
            attemptsMap.remove(user);
        }
    }

    private static void addToManager(User user, AuthMessage m) {
        synchronized (authCodeMap) {
            authCodeMap.putIfAbsent(user, m);
            attemptsMap.putIfAbsent(user, 0);
            scheduler.schedule(() -> {
                synchronized (authCodeMap) {
                    authCodeMap.remove(user);
                    attemptsMap.remove(user);
                }
                Sys.debug("AuthMessage timed out.", user);
            }, TIME_TO_EXPIRE, MILLISECONDS);
        }
    }

    public static boolean verifyAuthMessage(User user, int code) throws TooMany2FAAttemptsException {
        synchronized (authCodeMap) {
            if (isWaiting(user)) {
                if (!attemptsMap.containsKey(user)) {
                    attemptsMap.put(user, 0);
                }
                if (attemptsMap.get(user) < MAX_2FA_ATTEMPTS) {
                    if (authCodeMap.get(user).authCode == code) {
                        return true;
                    } else {
                        attemptsMap.replace(user, attemptsMap.get(user) + 1);
                        return false;
                    }
                } else {
                    throw new TooMany2FAAttemptsException();
                }
            } else {
                return false;
            }
        }
    }

    public static boolean isWaiting(User user) {
        synchronized (authCodeMap) {
            return authCodeMap.containsKey(user);
        }
    }

}
