package vault5431.auth;

import com.twilio.sdk.TwilioRestClient;
import com.twilio.sdk.TwilioRestException;
import com.twilio.sdk.resource.factory.MessageFactory;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import vault5431.Sys;
import vault5431.auth.exceptions.PhoneNumberNotVerified;
import vault5431.auth.exceptions.TooMany2FAAttemptsException;
import vault5431.io.Base64String;
import vault5431.users.Settings;
import vault5431.users.User;
import vault5431.users.UserManager;
import vault5431.users.exceptions.CouldNotLoadSettingsException;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static vault5431.Vault.test;

/**
 * The two-factor authentication handler. Responsible for maintaining user, authentication code pairs currently in use.
 * Two-factor authentication is necessary for a client to receive a verified token, and thus access their vault.
 * In short, the client must pass through this handler at least once.
 *
 * @author papacharlie and cyj
 */
public class TwoFactorAuthHandler {

    private static final SecureRandom random = new SecureRandom();

    private static String zeroPad(int number, int digits) {
        return String.format("%0" + digits + "d", number);
    }

    private static class UserCodePair {
        public final User user;
        public final int code;

        public UserCodePair(User user, int code) {
            this.user = user;
            this.code = code;
        }

    }

    private static final int MAX_2FA_ATTEMPTS = 10;

    private static final HashMap<User, Integer> authCodeMap = new HashMap<>();
    private static final HashMap<User, Integer> attemptsMap = new HashMap<>();
    private static final HashMap<Base64String, UserCodePair> verificationCodeMap = new HashMap<>();

    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private static final int TIME_TO_EXPIRE = 60000;
    private static final String ACCOUNT_SID = "AC0fde3a15c4eb806040031e5994a6f987";
    private static final String AUTH_TOKEN = "a8113b81179e3832fc3b780590a29b4e";
    private static final TwilioRestClient client = new TwilioRestClient(ACCOUNT_SID, AUTH_TOKEN);
    private static final String ADMIN_PHONE_NUMBER = "+16072755431";

    private static void sendSMS(String to, String body) throws TwilioRestException {
        List<NameValuePair> params = new ArrayList<>(3);
        params.add(new BasicNameValuePair("To", to));
        params.add(new BasicNameValuePair("From", ADMIN_PHONE_NUMBER));
        params.add(new BasicNameValuePair("Body", body));

        MessageFactory msgFactory = client.getAccount().getMessageFactory();
        msgFactory.create(params);
    }

    /**
     * @param user user to which authentication code will be sent
     * @return the authentication code sent to the user
     * @throws IOException
     * @throws TwilioRestException
     */
    static int sendAuthMessage(User user) throws IOException, CouldNotLoadSettingsException, TwilioRestException, PhoneNumberNotVerified {
        if (!isWaiting(user)) {
            Settings settings = user.loadSettings();
            if (!settings.isPhoneNumberVerified()) {
                throw new PhoneNumberNotVerified();
            }
            Sys.debug("Sending 2FA code.", user);
            int code = random.nextInt((int) 1e6);
            String message = "Please enter the following authentication code: " + zeroPad(code, 6);
            addToManager(user, code);
            if (!test) {
                sendSMS(settings.getPhoneNumber(), message);
            } else {
                System.out.println(message);
            }
            return code;
        } else {
            synchronized (authCodeMap) {
                return authCodeMap.get(user);
            }
        }
    }

    /**
     * Completely remove user from the two-factor authentication handler.
     *
     * @param user user to be removed
     */
    static void removeUser(User user) {
        synchronized (authCodeMap) {
            authCodeMap.remove(user);
            attemptsMap.remove(user);
        }
    }

    /**
     * Add the user to the authentication handler, pending 2FA authorization.
     *
     * @param user user to be added to authentication handler
     * @param m    authentication message sent to user
     */
    private static void addToManager(User user, int m) {
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

    /**
     * Verify the user inputted code with with the authentication handler. If too many failed attempts are
     * done, an exception will be thrown.
     *
     * @param user user to be authorized
     * @param code inputted user code to be verified
     * @return true if the code matches code in map. false otherwise.
     * @throws TooMany2FAAttemptsException
     */
    static boolean verifyAuthMessage(User user, int code) throws TooMany2FAAttemptsException {
        synchronized (authCodeMap) {
            if (isWaiting(user)) {
                if (!attemptsMap.containsKey(user)) {
                    attemptsMap.put(user, 0);
                }
                if (attemptsMap.get(user) < MAX_2FA_ATTEMPTS) {
                    if (authCodeMap.get(user) == code) {
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

    /**
     * Checks to see if the system is waiting for an user inputted code.
     *
     * @param user
     * @return true if still waiting. false otherwise.
     */
    static boolean isWaiting(User user) {
        synchronized (authCodeMap) {
            return authCodeMap.containsKey(user);
        }
    }

    public static int sendVerificationMessage(User user) throws CouldNotLoadSettingsException, TwilioRestException {
        synchronized (verificationCodeMap) {
            byte[] bytes = new byte[8];
            random.nextBytes(bytes);
            Base64String url = new Base64String(bytes);
            int code = random.nextInt((int) 1e6);
            String message = String.format("Please visit https://%s/verifyPhoneNumber/%s and enter the code given at signup.", test ? "localhost:5431" : "vault5431.com", url.getB64String());
            verificationCodeMap.put(url, new UserCodePair(user, code));
            scheduler.schedule(() -> {
                synchronized (verificationCodeMap) {
                    verificationCodeMap.remove(url);
                    UserManager.deleteUser(user.hashedUsername);
                }
            }, 30, MINUTES);
            if (!test) {
                sendSMS(user.loadSettings().getPhoneNumber(), message);
            } else {
                System.out.println(message);
            }
            return code;
        }
    }

    public static boolean verifyPhoneNumber(Base64String url, int code) throws CouldNotLoadSettingsException {
        synchronized (verificationCodeMap) {
            if (verificationCodeMap.containsKey(url)) {
                if (verificationCodeMap.get(url).code == code) {
                    verificationCodeMap.get(url).user.verifyPhoneNumber();
                    verificationCodeMap.remove(url);
                    return true;
                } else {
                    UserManager.deleteUser(verificationCodeMap.get(url).user.hashedUsername);
                }
            }
            return false;
        }
    }

    public static boolean isValidVerificationUrl(Base64String url) {
        synchronized (verificationCodeMap) {
            return verificationCodeMap.containsKey(url);
        }
    }

}
