package vault5431.auth;

import com.twilio.sdk.TwilioRestException;
import vault5431.Sys;
import vault5431.auth.exceptions.*;
import vault5431.io.Base64String;
import vault5431.users.Settings;
import vault5431.users.User;
import vault5431.users.UserManager;
import vault5431.users.exceptions.CouldNotLoadSettingsException;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Reference monitor for {@link Token} distribution. The only way to acquire a Token instance is through this class. In
 * other words, in order for a request to become authorized to do anything, it must pass through this class at least once.
 *
 * @author papacharlie
 */
public class AuthenticationHandler {

    private static final int MAX_FAILED_LOGINS = 2;
    private static final int BAN_LENGTH = 60 * 60; // One hour

    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private static final HashMap<User, HashSet<UUID>> tokenCache = new HashMap<>();
    private static final HashMap<User, Integer> failedLogins = new HashMap<>();
    private static final HashSet<User> bannedUsers = new HashSet<>();

    /**
     * Returns a Token instance parsed from the cookie of a request.
     *
     * @param cookie the request's cookie
     * @param ip     string representing the request's IP
     * @return A Token instance, null if the Token was never assigned by this reference monitor.
     * @throws CouldNotParseTokenException If the token's body was invalid.
     * @throws InvalidTokenException       If the Token's signature does not match, or if the current time does not fall in its
     *                                     date range.
     */
    public static Token parseFromCookie(String cookie, String ip) throws CouldNotParseTokenException, InvalidTokenException {
        Token token = Token.parseCookie(cookie.trim(), ip);
        if (token != null && tokenCache.containsKey(token.getUser()) && tokenCache.get(token.getUser()).contains(token.getId())) {
            return token;
        } else {
            return null;
        }
    }

    /**
     * Remove all instances of a Token from this monitor.
     *
     * @param token token to remove
     */
    public static void logout(Token token) {
        synchronized (tokenCache) {
            tokenCache.get(token.getUser()).remove(token.getId());
            TwoFactorAuthHandler.removeUser(token.getUser());
        }
    }

    /**
     * Send a text message for two factor authentication to the user.
     *
     * @param token token presented with request for 2FA code
     * @throws IOException                   If the phone number could not be loaded from disk.
     * @throws CouldNotLoadSettingsException If the user's settings, which contain the phone number, could not be loaded, i.e. disk was corrupted.
     * @throws TwilioRestException           If Twilio cannot send the requested text message to the user, i.e. the phone number
     *                                       is invalid.
     */
    public static void send2FACode(Token token) throws IOException, CouldNotLoadSettingsException, TwilioRestException {
        if (token != null && !token.isVerified()) {
            TwoFactorAuthHandler.sendAuthMessage(token.getUser());
        }
    }

    /**
     * Flags this user as being malignant. Prevents the user from logging in for {@link #BAN_LENGTH} minutes.
     *
     * @param user user to ban
     * @param ip   ip causing the ban
     */
    private static void banUser(User user, String ip) {
        synchronized (tokenCache) {
            bannedUsers.add(user);
            Sys.warning("Banned.", user, ip);
            scheduler.schedule(() -> {
                synchronized (tokenCache) {
                    Sys.info("Unbanned.", user);
                    bannedUsers.remove(user);
                    failedLogins.remove(user);
                }
            }, BAN_LENGTH, SECONDS);
        }
    }

    /**
     * Returns a new Token for the user. This monitor keeps track of all of the tokens it has assigned, and therefore
     * throws the respective errors when a user is illegally trying to acquire a new token. Tokens returned by this
     * method are unverified, i.e. user must still go through two factor authentication before acquiring verified
     * tokens.
     *
     * @param username user for which to create a Token
     * @param password password against which to check
     * @param ip       ip requesting the token
     * @return A new Token instance, null if provided password was incorrect.
     * @throws TooManyConcurrentSessionsException When assigning a new Token would mean violating the user's maximum
     *                                            concurrent sessions policy (see {@see Settings} for more information).
     * @throws TooManyFailedLogins                When a user has been banned for having too many failed login attempts.
     * @throws CouldNotLoadSettingsException      When the user's settings could not be found on disk, or were corrupted.
     * @throws IOException                        When the user's hashed password cannot be loaded from disk.
     * @throws NoSuchUserException                When the provided username does not exist.
     */
    public static Token acquireUnverifiedToken(String username, Base64String password, String ip)
            throws TooManyConcurrentSessionsException, TooManyFailedLogins, CouldNotLoadSettingsException, IOException, NoSuchUserException {
        synchronized (tokenCache) {
            if (!UserManager.userExists(username)) {
                throw new NoSuchUserException();
            }
            User user = UserManager.getUser(username);
            if (!bannedUsers.contains(user)) {
                if (!failedLogins.containsKey(user)) {
                    failedLogins.put(user, 0);
                }
                if (failedLogins.get(user) > MAX_FAILED_LOGINS) {
                    banUser(user, ip);
                    Sys.debug("Banning user because too many failed logins.", user, ip);
                    throw new TooManyFailedLogins();
                }
                if (user.verifyMasterPassword(password)) {
                    Settings settings = user.loadSettings();
                    if (!tokenCache.containsKey(user)) {
                        tokenCache.put(user, new HashSet<>());
                    }
                    if (tokenCache.get(user).size() < settings.getConcurrentSessions()) {
                        Token token = new Token(username, false);
                        Sys.debug("Assigning token.", user, ip);
                        tokenCache.get(user).add(token.getId());
                        scheduler.schedule(() -> {
                            synchronized (tokenCache) {
                                tokenCache.get(user).remove(token.getId());
                                failedLogins.remove(user);
                            }
                        }, token.secondsUntilExpiration(), SECONDS);
                        return token;
                    } else {
                        Sys.debug("Rejecting user because too many concurrent users.", user, ip);
                        throw new TooManyConcurrentSessionsException();
                    }
                } else {
                    failedLogins.replace(user, failedLogins.get(user) + 1);
                    return null;
                }
            } else {
                throw new TooManyFailedLogins();
            }
        }
    }

    /**
     * Returns a verified instance of the provided token.
     *
     * @param token     token to verify
     * @param twoFACode code sent by the {@link TwoFactorAuthHandler}
     * @return A verified token, null if the provided code was never sent.
     * @throws InvalidTokenException       If the Token was never assigned by the monitor to this user, or has timed out.
     * @throws TooMany2FAAttemptsException If the user has attempted to do 2FA more than the
     *                                     {@link TwoFactorAuthHandler} allows.
     */
    public static Token acquireVerifiedToken(Token token, int twoFACode) throws InvalidTokenException, TooMany2FAAttemptsException {
        synchronized (tokenCache) {
            if (tokenCache.containsKey(token.getUser()) && tokenCache.get(token.getUser()).contains(token.getId())) {
                try {
                    if (TwoFactorAuthHandler.verifyAuthMessage(token.getUser(), twoFACode)) {
                        TwoFactorAuthHandler.removeUser(token.getUser());
                        return token.verify();
                    } else {
                        return null;
                    }
                } catch (TooMany2FAAttemptsException err) {
                    banUser(token.getUser(), token.getIp());
                    throw err;
                }
            } else {
                throw new InvalidTokenException();
            }
        }
    }

}
