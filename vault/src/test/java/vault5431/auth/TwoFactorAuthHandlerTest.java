package vault5431.auth;

import org.junit.Test;
import vault5431.Vault;
import vault5431.VaultTest;
import vault5431.users.User;

import static org.junit.Assert.assertTrue;

/**
 * Created by cyj on 4/12/16.
 */
public class TwoFactorAuthHandlerTest extends VaultTest {

    @Test
    public void testAddToManager() throws Exception {
        User user = getTempUser("test");
        int number = TwoFactorAuthHandler.sendAuthMessage(user);
        assertTrue(TwoFactorAuthHandler.verifyAuthMessage(user, number));
//        try {
//            Thread.sleep(60000);
//        } catch (InterruptedException ie) {
//            System.out.println("Interrupted");
//        }
        assertTrue(TwoFactorAuthHandler.isWaiting(user));
    }
}
