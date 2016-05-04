package vault5431.routes;

import org.json.JSONArray;
import spark.ModelAndView;
import vault5431.auth.Token;
import vault5431.crypto.sjcl.SJCLSymmetricField;
import vault5431.io.Base64String;
import vault5431.users.Password;
import vault5431.users.Settings;

import java.util.HashMap;

/**
 * Routes for displaying and editing users' settings.
 *
 * @author papacharlie
 */
final class SettingsRoutes extends Routes {

    private Integer parseNumberField(String formField) {
        if (formField != null && formField.length() > 0) {
            try {
                return Integer.parseInt(formField);
            } catch (NumberFormatException err) {
                return null;
            }
        } else {
            return null;
        }
    }

    protected void routes() {

        authenticatedGet("/settings", (req, res, token) -> {
            HashMap<String, Object> attributes = new HashMap<>(3);
            Settings settings = token.getUser().loadSettings();
            attributes.put("phoneNumber", settings.getPhoneNumber());
            attributes.put("concurrentSessions", settings.getConcurrentSessions());
            attributes.put("sessionLength", settings.getSessionLength());
            return new ModelAndView(attributes, "settings.ftl");
        });

        authenticatedPost("/settings", (req, res, token) -> {
            String concurrentSessions = req.queryParams("concurrentSessions");
            if (provided(concurrentSessions)) {
                Integer cS = parseNumberField(concurrentSessions);
                if (cS != null) {
                    try {
                        Settings settings = token.getUser().loadSettings();
                        if (settings.getConcurrentSessions() != cS) {
                            token.getUser().changeSettings(settings.withConcurrentSessions(cS));
                            token.getUser().info("Changed maximum number of concurrent users.", token.getIp());
                        }
                    } catch (IllegalArgumentException err) {
                        return failure(err.getMessage());
                    }
                } else {
                    return failure("concurrentSessions must be an integer!");
                }
            }
            String sessionLength = req.queryParams("sessionLength");
            if (provided(sessionLength)) {
                Integer sL = parseNumberField(sessionLength);
                if (sL != null) {
                    try {
                        Settings settings = token.getUser().loadSettings();
                        if (settings.getSessionLength() != sL) {
                            token.getUser().changeSettings(settings.withSessionLength(sL));
                            token.getUser().info("Changed maximum session length.", token.getIp());
                        }
                    } catch (IllegalArgumentException err) {
                        return failure(err);
                    }
                } else {
                    return failure("sessionLength must be an integer!");
                }
            }
            String phoneNumber = req.queryParams("phoneNumber");
            if (provided(phoneNumber)) {
                Settings settings = token.getUser().loadSettings();
                if (!settings.getPhoneNumber().equals(phoneNumber)) {
                    try {
                        token.getUser().changeSettings(settings.withPhoneNumber(phoneNumber));
                        token.getUser().info("Changed maximum session length.", token.getIp());
                    } catch (IllegalArgumentException err) {
                        return failure(err);
                    }
                }
            }
            return success();
        });

        authenticatedPost("/changepassword", (req, res, token) -> {
            System.out.println(req.queryParams().toString());
            String oldPassword = req.queryParams("oldPassword");
            String newPassword1 = req.queryParams("newPassword1");
            String newPassword2 = req.queryParams("newPassword2");
            String reEncryptedPasswords = req.queryParams("reEncryptedPasswords");
            String newPrivateEncryptionKey = req.queryParams("newPrivateEncryptionKey");
            String newPrivateSigningKey = req.queryParams("newPrivateSigningKey");
            if (!provided(oldPassword, newPassword1, newPassword2, reEncryptedPasswords, newPrivateEncryptionKey, newPrivateSigningKey)) {
                return allFieldsRequired();
            }
            if (!(Base64String.isValidBase64Data(newPassword1) && Base64String.isValidBase64Data(newPassword2) && Base64String.isValidBase64Data(oldPassword))) {
                return invalidRequest();
            }
            if (!newPassword1.equals(newPassword2)) {
                return failure("New passwords must be equal.");
            }
            try {
                Password[] newPasswords = Password.fromJSON(new JSONArray(reEncryptedPasswords));
                Token newToken = token.getUser().changeMasterPassword(
                        Base64String.fromBase64(oldPassword),
                        Base64String.fromBase64(newPassword1),
                        newPasswords,
                        new SJCLSymmetricField(newPrivateEncryptionKey, 100),
                        new SJCLSymmetricField(newPrivateSigningKey, 100),
                        token
                );
                if (newToken == null) {
                    return failure("Provided password is not the master password. This activity has been flagged.");
                } else {
                    res.cookie("token", newToken.toCookie());
                    return success();
                }
            } catch (IllegalArgumentException err) {
                return failure(err);
            }
        });

    }
}
