package vault5431.routes;

import org.json.JSONArray;
import org.json.JSONObject;
import spark.ModelAndView;
import vault5431.Password;
import vault5431.auth.AuthenticationHandler;
import vault5431.auth.Token;
import vault5431.io.Base64String;
import vault5431.users.Settings;
import vault5431.users.exceptions.CouldNotLoadSettingsException;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Set;

import static spark.Spark.get;

/**
 * Created by papacharlie on 2016-04-27.
 */
public class SettingsRoutes extends Routes {

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
            HashMap<String, Object> attributes = new HashMap<>();
            Settings settings = token.getUser().loadSettings();
            attributes.put("concurrentSessions", settings.getConcurrentSessions());
            attributes.put("sessionLength", settings.getSessionLength());
            return new ModelAndView(attributes, "settings.ftl");
        });

        authenticatedPost("/settings", (req, res, token) -> {
            String concurrentSessions = req.queryParams("concurrentSessions");
            if (concurrentSessions != null && concurrentSessions.length() > 0) {
                Integer cS = parseNumberField(concurrentSessions);
                if (cS != null) {
                    try {
                        Settings settings = token.getUser().loadSettings();
                        if (settings.getConcurrentSessions() != cS) {
                            token.getUser().changeSettings(settings.withConcurrentSessions(cS));
                            token.getUser().info("Changed maximum number of concurrent users.", token.getIp());
                        }
                    } catch (IllegalArgumentException err) {
                        return String.format(invalidRequestWithError, err.getMessage());
                    }
                } else {
                    return String.format(invalidRequestWithError, "concurrentSessions must be an integer!");
                }
            }
            String sessionLength = req.queryParams("sessionLength");
            if (sessionLength != null && sessionLength.length() > 0) {
                Integer sL = parseNumberField(sessionLength);
                if (sL != null) {
                    try {
                        Settings settings = token.getUser().loadSettings();
                        if (settings.getSessionLength() != sL) {
                            token.getUser().changeSettings(settings.withSessionLength(sL));
                            token.getUser().info("Changed maximum session length.", token.getIp());
                        }
                    } catch (IllegalArgumentException err) {
                        return String.format(invalidRequestWithError, err.getMessage());
                    }
                } else {
                    return String.format(invalidRequestWithError, "sessionLength must be an integer!");
                }
            }
            return success;
        });

        authenticatedPost("/changepassword", (req, res, token) -> {
            System.out.println(req.queryParams().toString());
            String oldPassword = req.queryParams("oldPassword");
            String newPassword1 = req.queryParams("newPassword1");
            String newPassword2 = req.queryParams("newPassword2");
            String reEncryptedPasswords = req.queryParams("reEncryptedPasswords");
            if (!provided(oldPassword, newPassword1, newPassword2, reEncryptedPasswords)) {
                return allFieldsRequired;
            }
            if (!newPassword1.equals(newPassword2)) {
                return String.format(invalidRequestWithError, "New passwords must be equal.");
            }
            try {
                Password[] newPasswords = Password.fromJSON(new JSONArray(reEncryptedPasswords));
                Token newToken = token.getUser().changeMasterPassword(
                        Base64String.fromBase64(oldPassword),
                        Base64String.fromBase64(newPassword1),
                        newPasswords,
                        token
                );
                if (newToken == null) {
                    return String.format(invalidRequestWithError, "Provided password is not the master password. This activity has been flagged.");
                } else {
                    res.cookie("token", newToken.toCookie());
                    return success;
                }
            } catch (IllegalArgumentException err) {
                return String.format(invalidRequestWithError, err.getMessage());
            }
        });

    }
}
