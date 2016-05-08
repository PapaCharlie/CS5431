package vault5431.auth;

import com.twilio.sdk.TwilioRestException;
import vault5431.Sys;
import vault5431.auth.exceptions.TooMany2FAAttemptsException;
import vault5431.users.User;
import vault5431.users.exceptions.CouldNotLoadSettingsException;

import java.io.IOException;
import java.util.HashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static java.util.concurrent.TimeUnit.MILLISECONDS;

/**
 * The two-factor authentication handler. Responsible for maintaining user, authentication code pairs currently in use.
 * Two-factor authentication is necessary for a client to receive a verified token, and thus access their vault.
 * In short, the client must pass through this handler at least once.
 *
 * @author papacharlie and cyj
 */
class TwoFactorAuthHandler {

    private static final int MAX_2FA_ATTEMPTS = 10;

    private static final HashMap<User, AuthMessage> authCodeMap = new HashMap<>();
    private static final HashMap<User, Integer> attemptsMap = new HashMap<>();

    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private static final int TIME_TO_EXPIRE = 60000;


    /**
     * @param user user to which authentication code will be sent
     * @return the authentication code sent to the user
     */
    public static int sendAuthMessage(User user) throws IOException, CouldNotLoadSettingsException, TwilioRestException {
        if (!isWaiting(user)) {
            AuthMessage auth = new AuthMessage();
            SMSHandler.sendSms(user.loadSettings().getPhoneNumber(), auth.toString());
            Sys.debug("Sending 2FA code.", user);
            addToManager(user, auth);
            return auth.authCode;
        } else {
            synchronized (authCodeMap) {
                return authCodeMap.get(user).authCode;
            }
        }
    }

    /**
     * Completely remove user from the two-factor authentication handler.
     *
     * @param user user to be removed
     */
    protected static void removeUser(User user) {
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

    /**
     * Verify the user inputted code with with the authentication handler. If too many failed attempts are
     * done, an exception will be thrown.
     *
     * @param user user to be authorized
     * @param code inputted user code to be verified
     * @return true if the code matches code in map. false otherwise.
     * @throws TooMany2FAAttemptsException
     */
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

    /**
     * Checks to see if the system is waiting for an user inputted code.
     *
     * @param user
     * @return true if still waiting. false otherwise.
     */
    public static boolean isWaiting(User user) {
        synchronized (authCodeMap) {
            return authCodeMap.containsKey(user);
        }
    }

}
