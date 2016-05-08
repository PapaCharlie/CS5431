package vault5431.users;

import org.junit.Test;
import vault5431.VaultTest;
import vault5431.crypto.SymmetricUtils;

import javax.crypto.SecretKey;
import java.io.File;

import static org.junit.Assert.assertEquals;

/**
 * Created by papacharlie on 2016-04-26.
 */
public class SettingsTest extends VaultTest {

    @Test
    public void testSettingsSave() throws Exception {
        File tmp = getTempFile("settings");
        SecretKey crypto = SymmetricUtils.getNewKey();
        SecretKey signing = SymmetricUtils.getNewKey();
        Settings settings = new Settings("123-123-1234");
        settings.saveToFile(tmp, crypto, signing);
        Settings loadedSettings = Settings.loadFromFile(tmp, crypto, signing);
        assertEquals(settings.getConcurrentSessions(), loadedSettings.getConcurrentSessions());
        assertEquals(settings.getSessionLength(), loadedSettings.getSessionLength());
        assertEquals(settings.getPhoneNumber(), loadedSettings.getPhoneNumber());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBadSettings() throws Exception {
        new Settings("123");
    }

}
