package vault5431.twofactor;

import org.junit.Test;
import static org.junit.Assert.*;
/**
 * Created by cyj on 4/12/16.
 */
public class AuthMessageManagerTest {

    @Test
    public void testAddToManager() {
        AuthMessage authMsg = new AuthMessage();
        AuthMessageManager.addToManager("hello", authMsg);
        try{
            Thread.sleep(60000);
        } catch (InterruptedException ie) {
            System.out.println("Interrupted");
        }
        assertEquals(null, AuthMessageManager.authCodeManager.get("hello"));
    }
}
