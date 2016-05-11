package vault5431.auth;

import com.twilio.sdk.TwilioRestException;
import org.apache.commons.csv.CSVRecord;
import vault5431.Sys;
import vault5431.auth.exceptions.*;
import vault5431.crypto.Utils;
import vault5431.io.Base64String;
import vault5431.logging.CSVUtils;
import vault5431.users.Settings;
import vault5431.users.User;
import vault5431.users.UserManager;
import vault5431.users.exceptions.CouldNotLoadSettingsException;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.HashSet;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Reference monitor for {@link Token} distribution. The only way to acquire a Token instance is through this class,
 * since it is an internal class. In other words, in order for a request to become authorized to do anything, it must
 * pass through this class at least once.
 * <p>
 * Here are the conditions for allowing a Token instance to be created:
 * - A new Token can only be assigned iff doing so does not violate the User's maximum concurrent users setting. On the
 * other hand, changing said setting does not currently active Tokens.
 * - A Token must expire at or before the time dictated by the User's maximum session length. On the other hand,
 * changing the session length does not affect currently active Tokens. All Tokens expire at midnight EST, regardless
 * of settings.
 * - If an account has more than 3 failed login attempts per hour, no new Tokens will be assigned for said User for
 * an hour.
 * - A User may attempt 2FA no more than 10 times on the same code. Doing so will result in a one hour login ban.
 * - Changing the master password voids all active Tokens, and assigns a new Token to the machine that made the change.
 * - An instance of the Token class will only enter the system if it has been assigned by this monitor for that User.
 *
 * @author papacharlie
 */
public class AuthenticationHandler {

    private static final int MAX_FAILED_LOGINS = 2;
    private static final int BAN_LENGTH = 60 * 60; // One hour
    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private static final HashMap<User, HashSet<UUID>> tokenCache = new HashMap<>(10);
    private static final HashMap<User, Integer> failedLogins = new HashMap<>(10);
    private static final HashSet<User> bannedUsers = new HashSet<>(10);

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
            throw new InvalidTokenException();
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
     *                                            concurrent sessions policy (see {@see #Settings} for more information).
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
                        tokenCache.put(user, new HashSet<>(settings.getConcurrentSessions()));
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
     * Changes the user's master password. Assigns a new Token and voids all other active Tokens. Requires a Token
     * assigned by this monitor, and the user's old password.
     *
     * @param oldToken previously active token
     * @param oldPassword user's current password
     * @return A new Token instance.
     * @throws TooManyFailedLogins If #oldPassword is not the user's current password.
     * @throws IOException If the user's current password could not be loaded from disk.
     * @throws CouldNotLoadSettingsException If the user's settings could not be loaded.
     */
    public static Token changeMasterPassword(Token oldToken, Base64String oldPassword) throws TooManyFailedLogins, IOException, CouldNotLoadSettingsException {
        synchronized (tokenCache) {
            oldToken.getUser().warning("Received request to change master password. Stay tuned.", oldToken.getIp());
            User user = oldToken.getUser();
            if (!bannedUsers.contains(user)) {
                if (failedLogins.get(user) > MAX_FAILED_LOGINS) {
                    banUser(user, oldToken.getIp());
                    Sys.debug("Banning user because too many failed logins.", oldToken);
                    throw new TooManyFailedLogins();
                }
                if (user.verifyMasterPassword(oldPassword)) {
                    Token newToken = new Token(oldToken.getUsername(), true);
                    Sys.debug("Assigning token.", newToken);
                    tokenCache.replace(user, new HashSet<>(1));
                    tokenCache.get(user).add(newToken.getId());
                    scheduler.schedule(() -> {
                        synchronized (tokenCache) {
                            tokenCache.get(user).remove(newToken.getId());
                            failedLogins.remove(user);
                        }
                    }, newToken.secondsUntilExpiration(), SECONDS);
                    return newToken;
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
                throw new InvalidTokenException("This Token was never assigned.");
            }
        }
    }

    /**
     * Token class. A token is required for all authorization with respect to the Vault.
     *
     * @author papacharlie
     */
    public static final class Token {

        private static final SecureRandom random = new SecureRandom();

        private final String username;
        private final LocalDateTime creationDate;
        private final LocalDateTime expiresAt;
        private final UUID id;
        private final boolean verified;
        private final Base64String signature;
        private final String ip;

        private Token(String username, boolean verified) throws CouldNotLoadSettingsException {
            this(username, verified, Sys.NO_IP);
        }

        /**
         * Generate a new Token for {@code user}.
         *
         * @param username user for which to generate token
         * @param verified whether or not {@code user} has successfully completed 2FA
         */
        private Token(String username, boolean verified, String ip) throws CouldNotLoadSettingsException {
            if (!UserManager.userExists(username)) {
                throw new IllegalArgumentException("No such username!");
            }
            User user = UserManager.getUser(username);
            this.username = username;
            this.creationDate = LocalDateTime.now();
            LocalDateTime expires = LocalDateTime.now().plusMinutes((long) user.loadSettings().getSessionLength());
            this.expiresAt = RollingKeys.getEndOfCurrentWindow().isBefore(expires) ? RollingKeys.getEndOfCurrentWindow() : expires;
            this.id = Utils.randomUUID();
            byte[] randomBytes = new byte[16];
            random.nextBytes(randomBytes);
            this.verified = verified;
            this.signature = RollingKeys.sign(toSignatureBody(username, this.creationDate, this.expiresAt, id, verified));
            this.ip = ip;
        }

        /**
         * Private constructor used for {@link #parseCookie(String, String)}.
         *
         * @throws InvalidTokenException thrown when parsed token is not valid
         */
        private Token(String username, LocalDateTime creationDate, LocalDateTime expiresAt, UUID id, boolean verified, Base64String signature, String ip) throws InvalidTokenException {
            this.username = username;
            this.ip = ip;
            if (creationDate.isBefore(LocalDateTime.now())) {
                this.creationDate = creationDate;
            } else {
                throw new InvalidTokenException("Token was created after right now!");
            }

            if (expiresAt.isAfter(LocalDateTime.now())) {
                this.expiresAt = expiresAt;
            } else {
                throw new InvalidTokenException("Token has expired.");
            }

            if (RollingKeys.verifySignature(toSignatureBody(username, creationDate, expiresAt, id, verified), signature)) {
                this.id = id;
                this.signature = signature;
                this.verified = verified;
            } else {
                throw new InvalidTokenException("Could not verify token's signature.");
            }
        }

        public boolean isExpired() {
            return LocalDateTime.now().isAfter(expiresAt);
        }

        private static byte[] toSignatureBody(String username, LocalDateTime creationDate, LocalDateTime expiresAt, UUID id, boolean verified) {
            return (username + creationDate.toString() + expiresAt.toString() + id.toString() + verified).getBytes();
        }

        /**
         * Parse a cookie given by the client.
         *
         * @param cookie raw cookie from request
         * @param ip     ip that presented this token
         * @return the parsed token
         * @throws CouldNotParseTokenException if the token cannot be parsed
         * @throws InvalidTokenException       if the signature does not match or if the current time is outside
         *                                     the token's validity window
         */
        private static Token parseCookie(String cookie, String ip) throws CouldNotParseTokenException, InvalidTokenException {
            try {
                CSVRecord record = CSVUtils.parseRecord(cookie).getRecords().get(0);
                String username = record.get(0);
                LocalDateTime creationDate = LocalDateTime.parse(record.get(1));
                LocalDateTime expiresAt = LocalDateTime.parse(record.get(2));
                UUID id = UUID.fromString(record.get(3));
                boolean verified = record.get(4).trim().equals("true");
                Base64String signature = Base64String.fromBase64(record.get(5));
                return new Token(username, creationDate, expiresAt, id, verified, signature, ip);
            } catch (IOException | IndexOutOfBoundsException | DateTimeParseException | IllegalArgumentException err) {
                throw new CouldNotParseTokenException();
            }
        }

        public User getUser() {
            return UserManager.getUser(this.username);
        }

        /**
         * Calcuates the number of in which the Token should expire, dictated by the user's settings and the current
         * time.
         * @return The calculated time.
         */
        public int secondsUntilExpiration() {
            return (int) LocalDateTime.now().until(expiresAt, ChronoUnit.SECONDS);
        }

        public UUID getId() {
            return id;
        }

        public String getIp() {
            return ip;
        }

        public String getUsername() {
            return username;
        }

        public boolean isVerified() {
            return verified;
        }

        /**
         * Return a token that's been verified. Only to be called when user has completed 2FA.
         *
         * @return The verified Token.
         * @throws InvalidTokenException if the token has expired or the signature cannot be verified.
         */
        private Token verify() throws InvalidTokenException {
            return new Token(
                    username, creationDate, expiresAt, id, true,
                    RollingKeys.sign(toSignatureBody(username, creationDate, expiresAt, id, true)),
                    this.ip);
        }

        /**
         * Dump to string for HTML cookie.
         *
         * @return The string representation of the Token.
         * @throws IOException If the cookie body cannot be serialized (impossible).
         */
        public String toCookie() throws IOException {
            return CSVUtils.makeRecord(username, creationDate, expiresAt, id, verified, signature);
        }

        public int hashCode() {
            return id.hashCode();
        }

        public boolean equals(Object obj) {
            if (obj instanceof Token) {
                Token other = (Token) obj;
                return this.id.equals(other.id) && this.username.equals(other.username);
            } else {
                return false;
            }
        }

        public boolean deepEquals(Object obj) {
            if (obj instanceof Token) {
                Token other = (Token) obj;
                return id.equals(other.id)
                        && username.equals(other.username)
                        && creationDate.equals(other.creationDate)
                        && expiresAt.equals(other.expiresAt)
                        && verified == other.verified
                        && signature.equals(other.signature);
            } else {
                return false;
            }
        }
    }

}
