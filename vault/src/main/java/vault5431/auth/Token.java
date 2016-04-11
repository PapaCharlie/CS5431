package vault5431.auth;

import org.apache.commons.csv.CSVRecord;
import vault5431.Sys;
import vault5431.auth.exceptions.CouldNotParseTokenException;
import vault5431.auth.exceptions.InvalidTokenException;
import vault5431.crypto.SymmetricUtils;
import vault5431.io.Base64String;
import vault5431.logging.CSVUtils;
import vault5431.users.User;
import vault5431.users.UserManager;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.util.UUID;


/**
 * Token class. A token is required for all authorization with respect to the Vault
 */
public class Token {

    private static final SecureRandom random = new SecureRandom();

    private final Base64String username;
    private final LocalDateTime creationDate;
    private final LocalDateTime expiresAt;
    private final UUID id;
    private final Base64String randomString;
    private final Base64String signature;
    private final String ip;

    public Token(User user) {
        this.username = user.hash;
        this.creationDate = LocalDateTime.now();
        this.expiresAt = RollingKeys.getEndOfCurrentWindow();
        this.id = UUID.randomUUID();
        byte[] randomBytes = new byte[16];
        random.nextBytes(randomBytes);
        this.randomString = new Base64String(randomBytes);
        this.signature = RollingKeys.sign((creationDate.toString() + expiresAt.toString() + id.toString() + randomString.toString()).getBytes());
        this.ip = Sys.NO_IP;
    }

    private Token(Base64String username, LocalDateTime creationDate, LocalDateTime expiresAt, UUID id, Base64String randomString, Base64String signature, String ip) throws InvalidTokenException {
        this.username = username;
        this.randomString = randomString;
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

        if (RollingKeys.verifySignature((creationDate.toString() + expiresAt.toString() + id.toString() + randomString.toString()).getBytes(), signature)) {
            this.id = id;
            this.signature = signature;
        } else {
            throw new InvalidTokenException("Could not verify token's signature.");
        }
    }

    public User getUser() {
        return UserManager.getUser(this.username);
    }

    public String getIp() {
        return this.ip;
    }

    public Base64String getUsername() {
        return username;
    }

    /**
     * For Testing
     */
    public static Token parseToken(String cookie) throws CouldNotParseTokenException, InvalidTokenException {
        return parseToken(cookie, Sys.NO_IP);
    }

    public static Token parseToken(String cookie, String ip) throws CouldNotParseTokenException, InvalidTokenException {
        try {
            CSVRecord record = CSVUtils.parseRecord(cookie).getRecords().get(0);
            Base64String username = Base64String.fromBase64(record.get(0));
            LocalDateTime creationDate = LocalDateTime.parse(record.get(1));
            LocalDateTime expiresAt = LocalDateTime.parse(record.get(2));
            UUID id = UUID.fromString(record.get(3));
            Base64String encryptedKey = Base64String.fromBase64(record.get(4));
            Base64String signature = Base64String.fromBase64(record.get(5));
            return new Token(username, creationDate, expiresAt, id, encryptedKey, signature, ip);
        } catch (IOException | IndexOutOfBoundsException | DateTimeParseException | IllegalArgumentException err) {
            throw new CouldNotParseTokenException();
        }
    }

    public String toCookie() throws IOException {
        return CSVUtils.makeRecord(username, creationDate, expiresAt, id, randomString, signature);
    }

    public boolean equals(Object object) {
        if (object instanceof Token) {
            Token other = (Token) object;
            return this.creationDate.equals(other.creationDate)
                    && this.expiresAt.equals(other.expiresAt)
                    && this.id.equals(other.id)
                    && this.randomString.equals(other.randomString)
                    && this.signature.equals(other.signature)
                    && this.username.equals(other.username)
                    && this.ip.equals(other.ip);
        } else {
            return false;
        }
    }

}
