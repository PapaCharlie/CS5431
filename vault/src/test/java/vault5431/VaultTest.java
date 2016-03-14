package vault5431;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 * Created by papacharlie on 2016-03-13.
 */
public abstract class VaultTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

}
