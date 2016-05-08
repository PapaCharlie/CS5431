package vault5431;

import org.junit.Test;

/**
 * Created by papacharlie on 2016-04-25.
 */
public class GeneratorTest extends VaultTest {

    @Test
    public void testGenerator() throws Exception {
        System.out.println(PasswordGenerator.generatePassword(15, true, false, false, false, true));
    }

}
