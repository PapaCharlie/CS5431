package vault5431.routes;

import spark.ModelAndView;
import vault5431.Sys;
import vault5431.auth.Token;
import vault5431.io.Base64String;
import vault5431.users.User;

import java.util.HashMap;
import java.util.Map;

import static spark.Spark.get;
import static spark.Spark.post;

/**
 * Created by papacharlie on 3/25/16.
 */
class Passwords extends Routes {

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
                String id = req.queryParams("id");
                String changedPassword = req.queryParams("changedPassword");
                if (id != null
                        && id.length() > 0
                        && changedPassword != null
                        && changedPassword.length() > 0) {
                    token.getUser().changePassword(id, new Base64String(changedPassword), token);
                    return "{\"success\":true, \"error\": \"\"}";
                } else {
                    return "{\"success\":false, \"error\": \"All fields are required!\"}";
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
                    System.out.println(id);
                    token.getUser().deletePassword(id, token);
                    return "{\"success\":true, \"error\": \"\"}";
                } else {
                    return "{\"success\":false, \"error\": \"All fields are required!\"}";
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
                if (password != null && password.length() > 0) {
                    Base64String newPassword = new Base64String(password);
                    token.getUser().addPasswordToVault(newPassword, token);
                    return "{\"success\":true, \"error\": \"\"}";
                } else {
                    return "{\"success\":false, \"error\": \"All fields are required!\"}";
                }
            } else {
                Sys.debug("Received unauthorized POST to /savepassword.");
                res.redirect("/");
                return "";
            }
        });
    }

}
