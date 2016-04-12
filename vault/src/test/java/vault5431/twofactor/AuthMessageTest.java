package vault5431.twofactor;

import org.junit.Test;

/**
 * Created by cyj on 4/8/16.
 */
public class AuthMessageTest {

    @Test
    public void testToString() {
        AuthMessage authMsg = new AuthMessage();
        System.out.println(authMsg.toString());
    }
}
