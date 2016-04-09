package vault5431.twilio;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Created by cyj on 4/8/16.
 */
public class MessageSenderTest {
    MessageSender msgSender = new MessageSender();

    @Test
    public void sendAuthMessageTest() {
        AuthMessage authMsg = new AuthMessage();
        Integer recvMsg = msgSender.sendAuthMessage("+16109455656", authMsg.toString());
        assertEquals(null, recvMsg);
    }
}
