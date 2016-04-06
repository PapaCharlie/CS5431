package vault5431.routes;

import spark.ModelAndView;
import vault5431.Password;
import vault5431.Sys;
import vault5431.auth.Token;
import vault5431.auth.exceptions.CouldNotParseTokenException;
import vault5431.auth.exceptions.InvalidTokenException;
import vault5431.io.Base64String;
import vault5431.users.User;
import vault5431.users.UserManager;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static spark.Spark.*;
import static vault5431.Vault.demoUser;

/**
 * Created by papacharlie on 3/25/16.
 */
class Authentication extends Routes {

    private static boolean validateToken(String cookie, String ip) {
        if (cookie != null && cookie.length() > 0) {
            try {
                Token.parseToken(cookie.trim());
                return true;
            } catch (CouldNotParseTokenException err) {
                Sys.debug("Received invalid token.", ip);
                return false;
            } catch (InvalidTokenException err) {
                Sys.warning("Received tampered token. There is reason to believe this IP is acting maliciously.", ip);
                return false;
            }
        } else {
            return false;
        }
    }


    protected void routes() {

        get("/vault", (req, res) -> {
            res.redirect("/vault/home");
            return null;
        });

        get("/", (req, res) -> {
            Sys.debug("Received GET to /.", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            return new ModelAndView(attributes, "login.ftl");
        }, freeMarkerEngine);

        post("/authenticate", (req, res) -> {
            Sys.debug("Received POST to /authenticate.", req.ip());
            if (req.queryParams("username") != null &&
                    UserManager.userExists(req.queryParams("username")) &&
                    req.queryParams("password") != null &&
                    req.queryParams("password").length() > 0) {
                User user = UserManager.getUser(req.queryParams("username"));
                if (user.verifyPassword(req.queryParams("password"))) {
                    Token token = new Token(user, user.getSecretKey(req.queryParams("password")));
                    res.cookie("token", token.toCookie());
                    res.redirect("/vault/home");
                    user.info("Succesful login.", req.ip());
                } else {
                    user.warning("Failed login attempt.", req.ip());
                    res.redirect("/loginerror");
                }
            } else {
                Sys.debug("Failed login attempt.", req.ip());
                res.redirect("/loginerror");
            }
            return null;
        });

        get("/loginerror", (req, res) -> {
            Sys.debug("Received GET to /.", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            return new ModelAndView(attributes, "loginerror.ftl");
        }, freeMarkerEngine);

        before("/", (req, res) -> {
            if (validateToken(req.cookie("token"), req.ip())) {
                res.redirect("/vault/home");
            }
        });

        before("/vault/*", (req, res) -> {
            if (!validateToken(req.cookie("token"), req.ip())) {
                res.redirect("/unauthorized");
                halt(401);
            }
        });

        get("/logout", (req, res) -> {
            res.removeCookie("token");
            res.redirect("/");
            return null;
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

        get("/vault/home", (req, res) -> {
            Sys.debug("Received GET to /vault/home.", req.ip());
            Map<String, Object> attributes = new HashMap<>();

            Password[] plist = demoUser.loadPasswords();

            List<Map<String, String>> listofmaps = new ArrayList<>();

            for (Password p : plist) {
                listofmaps.add(p.toMap());
            }

            attributes.put("storedpasswords", listofmaps);

            return new ModelAndView(attributes, "home.ftl");
        }, freeMarkerEngine);

    }

}
