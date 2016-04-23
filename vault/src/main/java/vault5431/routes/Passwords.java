package vault5431.routes;

import org.json.JSONException;
import spark.ModelAndView;
import vault5431.Password;
import vault5431.Sys;
import vault5431.auth.Token;
import vault5431.io.Base64String;
import vault5431.users.User;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.json.JSONObject;

import static spark.Spark.get;
import static spark.Spark.post;

/**
 * Created by papacharlie on 3/25/16.
 */
class Passwords extends Routes {

    private static final String invalidRequest = "{\"success\":false, \"error\": \"Invalid request!\"}";
    private static final String invalidRequestWithError = "{\"success\":false, \"error\": \"%s\"}";
    private static final String allFieldsRequired = "{\"success\":false, \"error\": \"All fields are required!\"}";
    private static final String success = "{\"success\":true, \"error\": \"\"}";

    protected void routes() {

        get("/home", (req, res) -> {
            Token token = validateToken(req);
            if (token != null && token.isVerified()) {
                Sys.debug("Received GET to /home.", req.ip());
                Map<String, Object> attributes = new HashMap<>();

                User user = token.getUser();
                Base64String salt = user.loadVaultSalt();
                Base64String[] passwords = user.loadPasswords(token);
                StringBuilder array = new StringBuilder();
                array.append("[");
                if (passwords.length > 0) {
                    for (int i = 0; i < passwords.length - 1; i++) {
                        array.append(passwords[i].decodeString());
                        array.append(',');
                    }
                    array.append(passwords[passwords.length - 1].decodeString());
                } else {
                    attributes.put("empty", true);
                }
                array.append(']');
                attributes.put("payload", String.format("{\"salt\":\"%s\",\"passwords\":%s}", salt.toString(), array.toString()));

                return new ModelAndView(attributes, "home.ftl");
            } else {
                Sys.debug("Received unauthorized GET to /home.");
                res.removeCookie("token");
                res.redirect("/");
                return emptyPage;
            }
        }, freeMarkerEngine);

        post("/changepassword", (req, res) -> {
            Token token = validateToken(req);
            if (token != null && token.isVerified()) {
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
                        pass.put("id", uuid);
                        System.out.println(pass.toString());
                        token.getUser().changePassword(uuid, new Base64String(pass.toString()), token);
                        return success;
                    } catch (JSONException err) {
                        return invalidRequest;
                    }
                } else {
                    return allFieldsRequired;
                }

            } else {
                Sys.debug("Received unauthorized POST to /changepassword.");
                res.redirect("/");
                return "";
            }
        });

        post("/deletepassword", (req, res) -> {
            Token token = validateToken(req);
            if (token != null && token.isVerified()) {
                Sys.debug("Received POST to /deletepassword.", req.ip());
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
            } else {
                Sys.debug("Received unauthorized POST to /deletepassword.");
                res.redirect("/");
                return "";
            }
        });

        post("/savepassword", (req, res) -> {
            Token token = validateToken(req);
            if (token != null && token.isVerified()) {
                Sys.debug("Received POST to /savepassword.", req.ip());
                String password = req.queryParams("newPassword");
                System.out.println(Arrays.toString(req.queryParams().toArray()));
                if (password != null && password.length() > 0) {
                    System.out.println(password);
                    JSONObject pass;
                    try {
                        pass = new JSONObject(password);
                        pass.put("id", UUID.randomUUID().toString());
                        Password.fromJSON(pass);
                    } catch (JSONException err) {
                        err.printStackTrace();
                        return invalidRequest;
                    } catch (IllegalArgumentException err) {
                        System.out.println("Zerp?");
                        return String.format(invalidRequestWithError, err.getMessage());
                    }
                    Base64String newPassword = new Base64String(pass.toString());
                    token.getUser().addPasswordToVault(newPassword, token);
                    return success;
                } else {
                    return allFieldsRequired;
                }
            } else {
                Sys.debug("Received unauthorized POST to /savepassword.");
                res.redirect("/");
                return "";
            }
        });
    }

}
