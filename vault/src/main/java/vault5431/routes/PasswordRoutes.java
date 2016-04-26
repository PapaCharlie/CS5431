package vault5431.routes;

import org.json.JSONException;
import org.json.JSONObject;
import spark.ModelAndView;
import vault5431.Password;
import vault5431.Sys;
import vault5431.io.Base64String;
import vault5431.users.User;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.UUID;

/**
 * Created by papacharlie on 3/25/16.
 */
class PasswordRoutes extends Routes {

    private static final String invalidRequest = "{\"success\":false, \"error\": \"Invalid request!\"}";
    private static final String invalidRequestWithError = "{\"success\":false, \"error\": \"%s\"}";
    private static final String allFieldsRequired = "{\"success\":false, \"error\": \"All fields are required!\"}";
    private static final String success = "{\"success\":true, \"error\": \"\"}";

    protected void routes() {

        authenticatedGet("/home", (req, res, token) -> {
            Map<String, Object> attributes = new HashMap<>();
            User user = token.getUser();
            Base64String salt = user.loadVaultSalt();
            LinkedList<Password> passwords = user.loadPasswords(token);
            StringBuilder array = new StringBuilder();
            array.append("[");
            if (passwords.size() > 0) {
                for (int i = 0; i < passwords.size() - 1; i++) {
                    array.append(passwords.get(i).toJSON());
                    array.append(',');
                }
                array.append(passwords.get(passwords.size() - 1).toJSON());
            } else {
                attributes.put("empty", true);
            }
            array.append(']');
            attributes.put("payload", String.format("{\"salt\":\"%s\",\"passwords\":%s}", salt.toString(), array.toString()));
            return new ModelAndView(attributes, "home.ftl");
        }, freeMarkerEngine);

        authenticatedPost("/deletepassword", (req, res, token) -> {
            String id = req.queryParams("id");
            if (id != null && id.length() > 0) {
                UUID uuid;
                try {
                    uuid = UUID.fromString(id);
                } catch (IllegalArgumentException err) {
                    return invalidRequest;
                }
                token.getUser().deletePassword(uuid, token);
                return success;
            } else {
                return allFieldsRequired;
            }
        });

        authenticatedPost("/changepassword", (req, res, token) -> {
            Sys.debug("Received POST to /changepassword.", req.ip());
            UUID uuid;
            try {
                String id = req.queryParams("id");
                if (id != null && id.length() > 0) {
                    uuid = UUID.fromString(id);
                } else {
                    return allFieldsRequired;
                }
            } catch (IllegalArgumentException err) {
                return invalidRequest;
            }
            String changedPassword = req.queryParams("changedPassword");
            if (changedPassword != null && changedPassword.length() > 0) {
                try {
                    JSONObject pass = new JSONObject(changedPassword);
                    pass.put("id", uuid.toString());
                    token.getUser().changePassword(Password.fromJSON(pass), token);
                    return success;
                } catch (JSONException err) {
                    return invalidRequest;
                }
            } else {
                return allFieldsRequired;
            }
        });

        authenticatedPost("/savepassword", (req, res, token) -> {
            String password = req.queryParams("newPassword");
            if (password != null && password.length() > 0) {
                JSONObject pass;
                try {
                    pass = new JSONObject(password);
                    pass.put("id", UUID.randomUUID().toString());
                    Password newPassword = Password.fromJSON(pass);
                    token.getUser().addPasswordToVault(newPassword, token);
                } catch (JSONException err) {
                    err.printStackTrace();
                    return invalidRequest;
                } catch (IllegalArgumentException err) {
                    return String.format(invalidRequestWithError, err.getMessage());
                }
                return success;
            } else {
                return allFieldsRequired;
            }
        });
    }

}
