package vault5431.auth;

import org.apache.commons.csv.CSVRecord;
import vault5431.auth.exceptions.CouldNotParseTokenException;
import vault5431.auth.exceptions.InvalidTokenException;
import vault5431.crypto.exceptions.BadCiphertextException;
import vault5431.io.Base64String;
import vault5431.logging.CSVUtils;
import vault5431.users.User;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.util.UUID;

import static vault5431.auth.RollingKeys.getEncryptionKey;
import static vault5431.auth.RollingKeys.getSigningKey;
import static vault5431.crypto.SigningUtils.getSignature;
import static vault5431.crypto.SigningUtils.verifySignature;
import static vault5431.crypto.SymmetricUtils.*;
import static vault5431.logging.CSVUtils.makeRecord;

/**
 * Token class. A token is required for all authorization with respect to the Vault
 */
public class Token {

    private final Base64String username;
    private final LocalDateTime creationDate;
    private final LocalDateTime expiresAt;
    private final UUID id;
    private final SecretKey key;
    private final Base64String signature;

    public Token(User user, SecretKey key) {
        this.username = user.hash;
        this.creationDate = LocalDateTime.now();
        this.expiresAt = RollingKeys.getEndOfCurrentWindow();
        this.id = UUID.randomUUID();
        this.key = key;
        Base64String signature = null;
        try {
            signature = getSignature((creationDate.toString() + expiresAt.toString() + id.toString() + key.toString()).getBytes(), getSigningKey());
        } catch (InvalidKeyException err) {
            err.printStackTrace();
            System.err.println("Current rolling key is invalid. Halting.");
            System.exit(1);
        }
        this.signature = signature;
    }

    private Token(Base64String username, LocalDateTime creationDate, LocalDateTime expiresAt, UUID id, SecretKey key, Base64String signature) throws InvalidTokenException {
        this.username = username;
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

        boolean verified = false;
        try {
            verified = verifySignature((creationDate.toString() + expiresAt.toString() + id.toString() + key.toString()).getBytes(), signature, getSigningKey());
        } catch (InvalidKeyException err) {
            err.printStackTrace();
            System.err.println("Current rolling key is invalid. Halting.");
            System.exit(1);
        }

        if (verified) {
            this.id = id;
            this.key = key;
            this.signature = signature;
        } else {
            throw new InvalidTokenException("Could not verify token's signature.");
        }
    }

    public static Token parseToken(String cookie) throws CouldNotParseTokenException, InvalidTokenException {
        try {
            CSVRecord record = CSVUtils.parseRecord(cookie).getRecords().get(0);
            Base64String username = Base64String.fromBase64(record.get(0));
            LocalDateTime creationDate = LocalDateTime.parse(record.get(1));
            LocalDateTime expiresAt = LocalDateTime.parse(record.get(2));
            UUID id = UUID.fromString(record.get(3));
            SecretKey key = keyFromBytes(decrypt(Base64String.fromBase64(record.get(4)), getEncryptionKey()));
            Base64String signature = Base64String.fromBase64(record.get(5));
            return new Token(username, creationDate, expiresAt, id, key, signature);
        } catch (IOException | IndexOutOfBoundsException | DateTimeParseException | IllegalArgumentException | BadCiphertextException | InvalidKeyException err) {
            throw new CouldNotParseTokenException();
        }
    }

    public String toCookie() throws IOException {
        String cookie = null;
        try {
            cookie = makeRecord(username, creationDate, expiresAt, id, encrypt(key.getEncoded(), getEncryptionKey()), signature);
        } catch (InvalidKeyException err) {
            err.printStackTrace();
            System.err.println("Current rolling key is invalid. Halting.");
            System.exit(1);
        } catch (BadCiphertextException err) {
            err.printStackTrace();
            System.err.println("Could not encrypt SecretKey.getEncoded()... Let's fix that. Halting.");
            System.exit(1);
        }
        return cookie;
    }

}