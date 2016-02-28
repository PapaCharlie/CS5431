package vault5431;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created by papacharlie on 2/23/16.
 */
public class Utils {

    public static AsymmetricCipherKeyPair generateKeyPair() {
        RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
        gen.init(new RSAKeyGenerationParameters(
                BigInteger.valueOf(65537L),
                new SecureRandom(),
                4096,
                95)
        );
        return gen.generateKeyPair();
    }

}
