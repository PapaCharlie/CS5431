package vault5431.routes;

import com.google.gson.Gson;
import spark.ModelAndView;
import vault5431.Sys;
import vault5431.auth.Token;
import vault5431.io.Base64String;
import vault5431.users.User;
import vault5431.users.UserManager;

import java.util.HashMap;
import java.util.Map;

import static spark.Spark.get;
import static spark.Spark.post;
import static vault5431.Vault.demoUser;

/**
 * Created by papacharlie on 3/25/16.
 */
class Passwords extends Routes {

    private class Vault {
        private String salt;
        private String[] passwords;

        Vault(Base64String salt, Base64String[] passwords) {
            this.salt = salt.toString();
            this.passwords = new String[passwords.length];
            for (int i = 0; i < passwords.length; i++) {
                this.passwords[i] = passwords[i].toString();
            }
        }
    }

    protected void routes() {

        get("/home", (req, res) -> {
            Token token = validateToken(req);
//            Token token = new Token(Vault.demoUser);
            if (token != null) {
                Sys.debug("Received GET to /home.", req.ip());
                Map<String, Object> attributes = new HashMap<>();

                User user = UserManager.getUser(token.getUsername());
                Base64String salt = user.loadVaultSalt();
                Base64String[] passwords = user.loadPasswords(token);
                StringBuilder array = new StringBuilder();
                array.append("[");
                if (passwords.length > 0) {
                    for (int i = 0; i < passwords.length - 1; i++) {
                        array.append(passwords[i].toString());
                        array.append(',');
                    }
                    array.append(passwords[passwords.length - 1].toString());
                } else {
                    attributes.put("empty", true);
                }
                array.append(']');
                attributes.put("payload", String.format("{\"salt\":\"%s\",\"passwords\":%s}", salt.toString(), array.toString()));
//                Gson gson = new Gson();
//                attributes.put("payload", gson.toJson(new Vault(salt, passwords)));
                return new ModelAndView(attributes, "home.ftl");
            } else {
                Sys.debug("Received unauthorized GET to /home.");
                res.removeCookie("token");
                res.redirect("/");
                return emptyPage;
            }
        }, freeMarkerEngine);

        post("/vault/changepassword", (req, res) -> {
            Token token = Authentication.validateToken(req);
            if (token != null) {
                Sys.debug("Received POST to /vault/changepassword.", req.ip());
                String w = req.queryParams("name");
                if (w != null && w.length() > 0) {
                    demoUser.info("Changed Password for " + w, req.ip());
                }
                res.redirect("/home");
                return emptyPage;
            } else {
                Sys.debug("Received unauthorized POST to /vault/changepassword.");
                res.redirect("/");
                return emptyPage;
            }
        });

        post("/savepassword", (req, res) -> {
            Token token = Authentication.validateToken(req);
            if (token != null) {
                Sys.debug("Received POST to /savepassword.", req.ip());
                if (req.queryParams("newPassword") != null && req.queryParams("newPassword").length() > 0) {
                    System.out.println(req.queryParams("newPassword"));
                    Base64String newPassword = Base64String.fromBase64(req.queryParams("newPassword"));
                    try {
//                        Password p = new Password(web, url, username, password);
                        demoUser.addPasswordToVault(newPassword, token);
                        return "{\"success\":true, \"error\": \"\"}";
                    } catch (IllegalArgumentException err) {
                        return "{\"success\":false, \"error\": \"" + err.getLocalizedMessage() + "\"}";
                    }
                }
                res.redirect("/home");
                return emptyPage;
            } else {
                Sys.debug("Received unauthorized POST to /savepassword.");
                res.redirect("/");
                return emptyPage;
            }
        });

    }

}
