package vault5431.auth;

import org.apache.commons.csv.CSVRecord;
import vault5431.Sys;
import vault5431.auth.exceptions.CouldNotParseTokenException;
import vault5431.auth.exceptions.InvalidTokenException;
import vault5431.io.Base64String;
import vault5431.logging.CSVUtils;
import vault5431.users.User;
import vault5431.users.UserManager;
import vault5431.users.exceptions.CouldNotLoadSettingsException;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.util.UUID;

import static java.time.temporal.ChronoUnit.SECONDS;


/**
 * Token class. A token is required for all authorization with respect to the Vault.
 *
 * @author papacharlie
 */
public final class Token {

    private static final SecureRandom random = new SecureRandom();

    private final String username;
    private final LocalDateTime creationDate;
    private final LocalDateTime expiresAt;
    private final UUID id;
    private final boolean verified;
    private final Base64String signature;
    private final String ip;

    /**
     * Generate a new Token for {@code user}.
     *
     * @param user     user for which to generate token
     * @param verified whether or not {@code user} has successfully completed 2FA
     */
    protected Token(String username, boolean verified) throws CouldNotLoadSettingsException {
        if (!UserManager.userExists(username)) {
            throw new IllegalArgumentException("No such username!");
        }
        User user = UserManager.getUser(username);
        this.username = username;
        this.creationDate = LocalDateTime.now();
        LocalDateTime expires = LocalDateTime.now().plusMinutes((long) user.loadSettings().getSessionLength());
        this.expiresAt = RollingKeys.getEndOfCurrentWindow().isBefore(expires) ? RollingKeys.getEndOfCurrentWindow() : expires;
        this.id = UUID.randomUUID();
        byte[] randomBytes = new byte[16];
        random.nextBytes(randomBytes);
        this.verified = verified;
        this.signature = RollingKeys.sign(toSignatureBody(username, this.creationDate, this.expiresAt, id, verified));
        this.ip = Sys.NO_IP;
    }

    /**
     * Private constructor used for {@link #parseCookie(String)}.
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

    private static byte[] toSignatureBody(String username, LocalDateTime creationDate, LocalDateTime expiresAt, UUID id, boolean verified) {
        return (username + creationDate.toString() + expiresAt.toString() + id.toString() + verified).getBytes();
    }

    protected static Token parseCookie(String cookie) throws CouldNotParseTokenException, InvalidTokenException {
        return parseCookie(cookie, Sys.NO_IP);
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
    protected static Token parseCookie(String cookie, String ip) throws CouldNotParseTokenException, InvalidTokenException {
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

    public int secondsUntilExpiration() {
        return (int) LocalDateTime.now().until(expiresAt, SECONDS);
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
    protected Token verify() throws InvalidTokenException {
        return new Token(
                username, creationDate, expiresAt, id, true,
                RollingKeys.sign(toSignatureBody(username, creationDate, expiresAt, id, true)),
                this.ip);
    }

    /**
     * Dump to string for cookie
     *
     * @throws IOException
     */
    public String toCookie() throws IOException {
        return CSVUtils.makeRecord(username, creationDate, expiresAt, id, verified, signature);
    }

    public int hashCode() {
        return id.hashCode();
    }

    public boolean equals(Object object) {
        if (object instanceof Token) {
            Token other = (Token) object;
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
