package vault5431;

import org.junit.Test;
import vault5431.crypto.Base64String;

import static org.junit.Assert.*;

/**
 * Created by papacharlie on 3/14/16.
 */
public class UserTest extends VaultTest {

    @Test
    public void testUserCreation() throws Exception {
        String username = "testusername";
        String password = "password";
        User user = User.create(username, password);
        assertNotNull(user);
//        String data = "Hello!";
//        user.appendToLog(data);

    }

}
