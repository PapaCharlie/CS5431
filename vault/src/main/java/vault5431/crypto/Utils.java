package vault5431.crypto;

import java.security.SecureRandom;
import java.util.UUID;

/**
 * Created by papacharlie on 2016-05-10.
 */
public class Utils {

    private static final SecureRandom random = new SecureRandom();

    public static UUID randomUUID() {
        byte[] name = new byte[16];
        random.nextBytes(name);
        return UUID.nameUUIDFromBytes(name);
    }

}
