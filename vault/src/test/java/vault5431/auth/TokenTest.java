package vault5431.auth;

import org.junit.Test;
import vault5431.VaultTest;
import vault5431.users.User;

import static org.junit.Assert.assertTrue;

/**
 * Created by papacharlie on 4/5/16.
 */
public class TokenTest extends VaultTest {

    static User user;
    static {
        try {
            user = getTempUser("password");
        } catch (Exception err) {
            err.printStackTrace();
            System.out.println("Could not create temp user!");
            System.exit(1);
        }
    }

    @Test
    public void testTokenSerialization() throws Exception {
        Token token = new Token(user);
        System.out.println(token.toCookie());
        Thread.sleep(100);
        Token parsedToken = Token.parseToken(token.toCookie());
        assertTrue(token.equals(parsedToken));
    }

}
