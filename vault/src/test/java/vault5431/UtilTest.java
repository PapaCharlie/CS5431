package vault5431;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.junit.Test;

/**
 * Created by papacharlie on 2016-02-27.
 */
public class UtilTest {

    public static String getHexString(byte[] b) throws Exception {
        String result = "";
        for (int i = 0; i < b.length; i++) {
            result +=
                    Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }

    @Test
    public void tryGenerator() {
        AsymmetricCipherKeyPair keyPair = Utils.generateKeyPair();
        AsymmetricBlockCipher e = new RSAEngine();
        e = new PKCS1Encoding(e);
        e.init(true, keyPair.getPublic());
        byte[] inputData = "testEncryptData".getBytes();
        byte[] encryptedData;
        try {
            encryptedData = e.processBlock(inputData, 0, inputData.length);
            System.out.println(new String(inputData));
            System.out.println(getHexString(encryptedData));
        } catch (Exception err) {
            System.out.println(err);
        }
    }

}
