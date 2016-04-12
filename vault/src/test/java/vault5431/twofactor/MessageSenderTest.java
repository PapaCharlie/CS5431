package vault5431.twofactor;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Created by cyj on 4/8/16.
 */
public class MessageSenderTest {
    @Test
    public void sendAuthMessageTest() {
        String sendPhone = "+16109455656";
        Integer recvMsg = MessageSender.sendAuthMessage(sendPhone);
        try{
            Thread.sleep(10000);
        } catch (InterruptedException ie) {
            assertFalse(true);
        }
        AuthMessage test1 = AuthMessageManager.authCodeManager.get("+16109455656");
        assertFalse(null == test1);
        Integer recvMsg2 = MessageSender.sendAuthMessage(sendPhone);
        try{
            Thread.sleep(30000);
        } catch (InterruptedException ie) {
            assertFalse(true);
        }
        System.out.println(AuthMessageManager.authCodeManager.values());
        assertEquals(2, AuthMessageManager.authCodeManager.size());
        AuthMessage test2 = AuthMessageManager.authCodeManager.get("+16109455656");
        try{
            Thread.sleep(40000);
        } catch (InterruptedException ie) {
            assertFalse(true);
        }
        assertEquals(null, test1);
        assertEquals(null, test2);
    }
}
