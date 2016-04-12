package vault5431.twofactor;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Created by cyj on 4/8/16.
 */
public class MessageSenderTest {
    @Test
    public void sendAuthMessageTest() {
        Integer recvMsg = MessageSender.sendAuthMessage("+16109455656");
        assertEquals(null, recvMsg);
    }
}
