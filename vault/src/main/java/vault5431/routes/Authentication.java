package vault5431.routes;

import spark.ModelAndView;
import spark.Request;
import vault5431.Password;
import vault5431.Sys;
import vault5431.auth.Token;
import vault5431.auth.exceptions.CouldNotParseTokenException;
import vault5431.auth.exceptions.InvalidTokenException;
import vault5431.crypto.PasswordUtils;
import vault5431.io.Base64String;
import vault5431.users.User;
import vault5431.users.UserManager;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static spark.Spark.get;
import static spark.Spark.post;
import static vault5431.Vault.adminEncryptionKey;
import static vault5431.Vault.demoUser;

/**
 * Created by papacharlie on 3/25/16.
 */
class Authentication extends Routes {

    protected void routes() {

        get("/", (req, res) -> {
            Sys.debug("Received GET to /.", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            return new ModelAndView(attributes, "login.ftl");
        }, freeMarkerEngine);

        post("/", (req, res) -> {
            Sys.debug("Received POST to /.", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            String username = req.queryParams("username");
            String password = req.queryParams("password");
            if (username != null
                    && username.length() > 0
                    && password != null
                    && password.length() > 0) {
                if (UserManager.userExists(username) && UserManager.getUser(username).verifyPassword(Base64String.fromBase64(password))) {
                    Token token = new Token(UserManager.getUser(username));
                    res.cookie("token", token.toCookie());
                    res.redirect("/home");
                    return emptyPage;
                } else {
                    Sys.debug("Failed login attempt.", req.ip());
                    String errorMessage = "This username/password combination does not exist!";
                    attributes.put("error", errorMessage);
                    return new ModelAndView(attributes, "login.ftl");
                }
            } else {
                Sys.debug("Failed login attempt.", req.ip());
                String errorMessage = "This username/password combination does not exist!";
                attributes.put("error", errorMessage);
                return new ModelAndView(attributes, "login.ftl");
            }
        }, freeMarkerEngine);

        get("/logout", (req, res) -> {
            res.removeCookie("token");
            res.redirect("/");
            return emptyPage;
        });

        get("/unauthorized", (req, res) -> {
            Sys.debug("Displaying unauthorized page.", req.ip());
            res.status(401);
            if (req.cookie("token") != null && req.cookie("token").length() > 0) {
                res.removeCookie("token");
            }
            Map<String, Object> attributes = new HashMap<>();
            return new ModelAndView(attributes, "unauthorized.ftl");
        }, freeMarkerEngine);

    }

}
