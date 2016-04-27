package vault5431.auth;

import com.twilio.sdk.TwilioRestException;
import vault5431.Sys;
import vault5431.auth.exceptions.*;
import vault5431.io.Base64String;
import vault5431.users.Settings;
import vault5431.users.User;
import vault5431.users.exceptions.CouldNotLoadPhoneNumberException;
import vault5431.users.exceptions.CouldNotLoadSettingsException;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Created by papacharlie on 2016-04-26.
 */
public class AuthenticationHandler {

    private static final int MAX_FAILED_LOGINS = 2;
    private static final int BAN_LENGTH = 60 * 60; // One hour

    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private static final HashMap<User, HashSet<UUID>> tokenCache = new HashMap<>();
    private static final HashMap<User, Integer> failedLogins = new HashMap<>();
    private static final HashSet<User> bannedUsers = new HashSet<>();

    public static Token parseFromCookie(String cookie, String ip) throws CouldNotParseTokenException, InvalidTokenException {
        Token token = Token.parseCookie(cookie.trim(), ip);
        if (token != null && tokenCache.containsKey(token.getUser()) && tokenCache.get(token.getUser()).contains(token.getId())) {
            return token;
        } else {
            return null;
        }
    }

    public static void logout(User user, Token token) {

    }

    public static void send2FACode(User user) throws CouldNotLoadPhoneNumberException, IOException, TwilioRestException {
        TwoFactorAuthHandler.sendAuthMessage(user);
    }

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

    public static Token acquireUnverifiedToken(User user, Base64String password, String ip)
            throws TooManyConcurrentSessionsException, TooManyFailedLogins, CouldNotLoadSettingsException, IOException {
        synchronized (tokenCache) {
            if (!bannedUsers.contains(user)) {
                if (!failedLogins.containsKey(user)) {
                    failedLogins.put(user, 0);
                }
                if (failedLogins.get(user) > MAX_FAILED_LOGINS) {
                    banUser(user, ip);
                    throw new TooManyFailedLogins();
                }
                if (user.verifyPassword(password)) {
                    Settings settings = user.loadSettings();
                    if (!tokenCache.containsKey(user)) {
                        tokenCache.put(user, new HashSet<>());
                    }
                    if (tokenCache.get(user).size() < settings.getConcurrentSessions()) {
                        Token token = new Token(user, false);
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

    public static Token acquireVerifiedToken(Token token, int twoFACode) throws InvalidTokenException, TooMany2FAAttemptsException {
        synchronized (tokenCache) {
            if (tokenCache.containsKey(token.getUser()) && tokenCache.get(token.getUser()).contains(token.getId())) {
                try {
                    if (TwoFactorAuthHandler.verifyAuthMessage(token.getUser(), twoFACode)) {
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
