package vault5431.routes;

import org.json.JSONArray;
import spark.ModelAndView;
import vault5431.Sys;
import vault5431.auth.Token;
import vault5431.io.Base64String;
import vault5431.users.Password;
import vault5431.users.Settings;
import vault5431.users.User;
import vault5431.users.UserManager;

import java.util.HashMap;

/**
 * Created by papacharlie on 2016-04-27.
 */
class SettingsRoutes extends Routes {

    private static final String successWithData = "{\"\":true,\"%s\":\"%s\"}";

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
                        return unSuccessful().put("error", err.getMessage());
                    }
                } else {
                    return unSuccessful().put("error", "concurrentSessions must be an integer!");
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
                        return unSuccessful().put("error", err.getMessage());
                    }
                } else {
                    return unSuccessful().put("error", "sessionLength must be an integer!");
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
                return unSuccessful().put("error", "New passwords must be equal.");
            }
            try {
                Password[] newPasswords = Password.fromJSON(new JSONArray(reEncryptedPasswords));
                Token newToken = token.getUser().changeMasterPassword(
                        Base64String.fromBase64(oldPassword),
                        Base64String.fromBase64(newPassword1),
                        newPasswords,
                        newPrivateEncryptionKey,
                        newPrivateSigningKey,
                        token
                );
                if (newToken == null) {
                    return unSuccessful().put("error", "Provided password is not the master password. This activity has been flagged.");
                } else {
                    res.cookie("token", newToken.toCookie());
                    return success();
                }
            } catch (IllegalArgumentException err) {
                return unSuccessful().put("error", err.getMessage());
            }
        });

        authenticatedGet("/privateEncryptionKey", (req, res, token) ->
                success().put("privateEncryptionKey", token.getUser().loadPrivateEncryptionKey(token))
        );

        authenticatedGet("/privateSigningKey", (req, res, token) ->
                success().put("privateSigningKey", token.getUser().loadPrivateSigningKey(token))
        );

        authenticatedGet("/publicEncryptionKey/:username", (req, res, token) -> {
            String username = req.params("username");
            if (!provided(username)) {
                return unSuccessful().put("error", "Username must be provided!");
            }
            if (!UserManager.userExists(username)) {
                return unSuccessful().put("error", "No such username!");
            }
            User user = UserManager.getUser(username);
            Sys.debug(String.format("Loading %s's public encryption key.", user.getShortHash()), token);
            return success().put("publicEncryptionKey", user.loadPublicEncryptionKey());
        });

        authenticatedGet("/publicSigningKey/:username", (req, res, token) -> {
            String username = req.params("username");
            if (!provided(username)) {
                return unSuccessful().put("error", "Username must be provided!");
            }
            if (!UserManager.userExists(username)) {
                return unSuccessful().put("error", "No such username!");
            }
            User user = UserManager.getUser(username);
            Sys.debug(String.format("Loading %s's public signing key.", user.getShortHash()), token);
            return success().put("publicSigningKey", user.loadPublicSigningKey());
        });

    }
}
