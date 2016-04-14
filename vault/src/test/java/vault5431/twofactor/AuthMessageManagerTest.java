package vault5431.twofactor;

import org.junit.Test;
import vault5431.Vault;

import static org.junit.Assert.*;

/**
 * Created by cyj on 4/12/16.
 */
public class AuthMessageManagerTest {

    @Test
    public void testAddToManager() throws Exception {
        int number = AuthMessageManager.sendAuthMessage(Vault.getDemoUser());
        assertTrue(AuthMessageManager.verifyAuthMessage(Vault.getDemoUser(), number));
        try {
            Thread.sleep(60000);
        } catch (InterruptedException ie) {
            System.out.println("Interrupted");
        }
        assertFalse(AuthMessageManager.isWaiting(Vault.getDemoUser()));
    }
}
