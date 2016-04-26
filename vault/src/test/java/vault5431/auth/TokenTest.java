package vault5431.auth;

import org.junit.Test;
import vault5431.Vault;
import vault5431.VaultTest;
import vault5431.auth.exceptions.InvalidTokenException;

import static org.junit.Assert.assertTrue;

/**
 * Created by papacharlie on 4/5/16.
 */
public class TokenTest extends VaultTest {

    @Test(expected = InvalidTokenException.class)
    public void testTokenSerialization() throws Exception {
        Token token = new Token(Vault.getDemoUser(), false);
        System.out.println(token.toCookie());
        Thread.sleep(100);
        Token parsedToken = Token.parseCookie(token.toCookie());
        assertTrue(token.equals(parsedToken));

        token = new Token(Vault.getDemoUser(), true);
        Thread.sleep(100);
        parsedToken = Token.parseCookie(token.toCookie());
        assertTrue(token.equals(parsedToken));

        Token.parseCookie(token.toCookie().replace("true", "false"));
    }

}
