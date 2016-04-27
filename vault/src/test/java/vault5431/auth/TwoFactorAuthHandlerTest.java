package vault5431.auth;

import org.junit.Test;
import vault5431.Vault;

import static org.junit.Assert.assertTrue;

/**
 * Created by cyj on 4/12/16.
 */
public class TwoFactorAuthHandlerTest {

    @Test
    public void testAddToManager() throws Exception {
        int number = TwoFactorAuthHandler.sendAuthMessage(Vault.getDemoUser());
        assertTrue(TwoFactorAuthHandler.verifyAuthMessage(Vault.getDemoUser(), number));
//        try {
//            Thread.sleep(60000);
//        } catch (InterruptedException ie) {
//            System.out.println("Interrupted");
//        }
        assertTrue(TwoFactorAuthHandler.isWaiting(Vault.getDemoUser()));
    }
}
