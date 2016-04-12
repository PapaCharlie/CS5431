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
        assertEquals(null, recvMsg);
        try{
            Thread.sleep(60000);
        } catch (InterruptedException ie) {
            assertFalse(true);
        }
        AuthMessage test = AuthMessageManager.authCodeManager.get("+16109455656");
        assertEquals(null, test);
    }
}
