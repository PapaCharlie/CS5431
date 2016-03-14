package vault5431;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Before;

import java.io.File;
import java.io.IOError;
import java.io.IOException;
import java.nio.file.Files;
import java.security.Security;
import static org.junit.Assert.*;

/**
 * Created by papacharlie on 2016-03-13.
 */
public abstract class VaultTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Before
    public void createTempHomeDir() throws IOException {
        File dir = Files.createTempDirectory("test").toFile();
        assertNotNull(dir);
        Vault.home = dir;
    }

}
