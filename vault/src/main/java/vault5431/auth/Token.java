package vault5431.auth;

import org.apache.commons.csv.CSVRecord;
import vault5431.auth.exceptions.CouldNotParseTokenException;
import vault5431.auth.exceptions.InvalidTokenException;
import vault5431.crypto.SigningUtils;
import vault5431.crypto.SymmetricUtils;
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


/**
 * Token class. A token is required for all authorization with respect to the Vault
 */
public class Token {

    private final Base64String username;
    private final LocalDateTime creationDate;
    private final LocalDateTime expiresAt;
    private final UUID id;
    private final SecretKey key;
    private final Base64String encryptedKey;
    private final Base64String signature;

    public Token(User user, SecretKey key) {
        this.username = user.hash;
        this.creationDate = LocalDateTime.now();
        this.expiresAt = RollingKeys.getEndOfCurrentWindow();
        this.id = UUID.randomUUID();
        this.key = key;
        Base64String encryptedKey = null;
        Base64String signature = null;
        try {
            encryptedKey = SymmetricUtils.encrypt(key.getEncoded(), RollingKeys.getEncryptionKey());
            signature = SigningUtils.getSignature((creationDate.toString() + expiresAt.toString() + id.toString() + encryptedKey.toString()).getBytes(), RollingKeys.getSigningKey());
        } catch (InvalidKeyException | BadCiphertextException err) {
            err.printStackTrace();
            System.err.println("Current rolling key is invalid. Halting.");
            System.exit(1);
        }
        this.encryptedKey = encryptedKey;
        this.signature = signature;
    }

    private Token(Base64String username, LocalDateTime creationDate, LocalDateTime expiresAt, UUID id, Base64String encryptedKey, Base64String signature) throws InvalidTokenException {
        this.username = username;
        this.encryptedKey = encryptedKey;
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
            verified = SigningUtils.verifySignature((creationDate.toString() + expiresAt.toString() + id.toString() + encryptedKey.toString()).getBytes(), signature, RollingKeys.getSigningKey());
        } catch (InvalidKeyException err) {
            err.printStackTrace();
            System.err.println("Current rolling key is invalid. Halting.");
            System.exit(1);
        }

        if (verified) {
            this.id = id;
            SecretKey key = null;
            try {
                key = SymmetricUtils.keyFromBytes(SymmetricUtils.decrypt(encryptedKey, RollingKeys.getEncryptionKey()));
            } catch (BadCiphertextException err) {
                throw new InvalidTokenException("Key could not be decrypted (weird, because it was signed...)!");
            } catch (InvalidKeyException err) {
                err.printStackTrace();
                System.err.println("Current rolling key is invalid. Halting.");
                System.exit(1);
            }
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
            Base64String encryptedKey = Base64String.fromBase64(record.get(4));
            Base64String signature = Base64String.fromBase64(record.get(5));
            return new Token(username, creationDate, expiresAt, id, encryptedKey, signature);
        } catch (IOException | IndexOutOfBoundsException | DateTimeParseException | IllegalArgumentException err) {
            throw new CouldNotParseTokenException();
        }
    }

    public String toCookie() throws IOException {
        return CSVUtils.makeRecord(username, creationDate, expiresAt, id, encryptedKey, signature);
    }

    public boolean equals(Object object) {
        if (object instanceof Token) {
            Token other = (Token) object;
            return this.creationDate.equals(other.creationDate)
                    && this.expiresAt.equals(other.expiresAt)
                    && this.id.equals(other.id)
                    && this.key.equals(other.key)
                    && this.signature.equals(other.signature)
                    && this.username.equals(other.username);
        } else {
            return false;
        }
    }

}
