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
import vault5431.users.User;
import vault5431.users.UserManager;

/**
 * Created by papacharlie on 3/25/16.
 */
class Passwords extends Routes {

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
                    getDemoUser().info("Changed Password for " + w, req.ip());
                }
                res.redirect("/home");
                return emptyPage;
            } else {
                Sys.debug("Received unauthorized POST to /vault/changepassword.");
                res.redirect("/");
                return emptyPage;
            }
        });

        post("/vault/savepassword", (req, res) -> {
            Sys.debug("Received POST to /vault/savepassword.", req.ip());
            String web = req.queryParams("web");
            String url = req.queryParams("url");
            String username = req.queryParams("username");
            String password = req.queryParams("password");
            if (web != null && url != null && username != null && password != null) {
                try {
                    System.out.println(password);
                    System.out.println(username);
                    Password p = new Password(web, url, username, password);
                    User user = UserManager.getUser(username);
                    user.addPassword(p);
                    //demoUser.addPassword(p);
                } catch (IllegalArgumentException err) {
                    String errorMessage = err.getLocalizedMessage();
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
