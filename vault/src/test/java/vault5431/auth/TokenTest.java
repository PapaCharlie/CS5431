package vault5431.auth;

import org.junit.Test;
import vault5431.Sys;
import vault5431.VaultTest;
import vault5431.auth.AuthenticationHandler.Token;
import vault5431.auth.exceptions.InvalidTokenException;
import vault5431.crypto.HashUtils;
import vault5431.io.Base64String;
import vault5431.users.User;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Created by papacharlie on 4/5/16.
 */
public class TokenTest extends VaultTest {

    @Test(expected = InvalidTokenException.class)
    public void testTokenSerialization() throws Exception {
        TempUser tempUser = getTempUser();
        Token token = AuthenticationHandler.acquireUnverifiedToken(tempUser.username, new Base64String(tempUser.password), Sys.NO_IP);
        assertNotNull(token);
        System.out.println(token.toCookie());
        Thread.sleep(100);
        Token parsedToken = AuthenticationHandler.parseFromCookie(token.toCookie(), Sys.NO_IP);
        assertTrue(token.deepEquals(parsedToken));

        token = AuthenticationHandler.acquireUnverifiedToken(tempUser.username, new Base64String(tempUser.password), Sys.NO_IP);
        assertNotNull(token);
        Thread.sleep(100);
        parsedToken = AuthenticationHandler.parseFromCookie(token.toCookie(), Sys.NO_IP);
        assertTrue(token.deepEquals(parsedToken));

        AuthenticationHandler.parseFromCookie(token.toCookie().replace("false", "true"), Sys.NO_IP);
    }

}
