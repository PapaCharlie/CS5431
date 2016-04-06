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
                Token token = new Token(user, user.)
                res.redirect("/vault/home");
                demoUser.info("Action: Log In", req.ip());
            } else {
                res.redirect("/");
            }
            return null;
        });

        before("/vault/*", (req, res) -> {
            if (req.cookie("token") != null) {
                try {
                    Token.parseToken(req.cookie("token"));
                } catch (CouldNotParseTokenException err) {
                    res.removeCookie("token");
                    res.redirect("/unauthorized");
                } catch (InvalidTokenException err) {
                    Sys.warning("Received invalid token. There is reason to believe this IP is acting malicious.", req.ip());
                    res.removeCookie("token");
                    res.redirect("/unauthorized");
                }
            } else {
                res.removeCookie("token");
                res.redirect("/unauthorized");
            }
        });

        get("/logout", (req, res) -> {
            res.removeCookie("token");
            res.redirect("/");
            return null;
        });

        get("/unauthorized", (req, res) -> {
            res.status(401);
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
