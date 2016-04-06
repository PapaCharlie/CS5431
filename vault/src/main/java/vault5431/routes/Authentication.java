package vault5431.routes;

import spark.ModelAndView;
import spark.Request;
import spark.Response;
import vault5431.Password;
import vault5431.Sys;
import vault5431.auth.Token;
import vault5431.auth.exceptions.CouldNotParseTokenException;
import vault5431.auth.exceptions.InvalidTokenException;
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

    public static Token validateToken(Request req) {
        if (req.cookie("token") != null && req.cookie("token").length() > 0) {
            try {
                return Token.parseToken(req.cookie("token").trim(), req.ip());
            } catch (CouldNotParseTokenException err) {
                Sys.debug("Received invalid token.", req.ip());
                return null;
            } catch (InvalidTokenException err) {
                Sys.warning("Received tampered token. There is reason to believe this IP is acting maliciously.", req.ip());
                return null;
            }
        } else {
            return null;
        }
    }


    protected void routes() {

        get("/vault", (req, res) -> {
            res.redirect("/vault/home");
            return null;
        });

        get("/", (req, res) -> {
            Sys.debug("Received GET to /.", req.ip());
            if (validateToken(req) != null) {
                res.redirect("/vault/home");
                return null;
            } else {
                Map<String, Object> attributes = new HashMap<>();
                return new ModelAndView(attributes, "login.ftl");
            }
        }, freeMarkerEngine);

        post("/", (req, res) -> {
            Sys.debug("Received POST to /.", req.ip());
            if (req.queryParams("username") != null
                    && req.queryParams("username").length() > 0
                    && UserManager.userExists(req.queryParams("username"))
                    && req.queryParams("password") != null
                    && req.queryParams("password").length() > 0) {
                User user = UserManager.getUser(req.queryParams("username"));
                if (user.verifyPassword(req.queryParams("password"))) {
                    Token token = new Token(user, user.deriveSecretKey(req.queryParams("password")));
                    res.cookie("token", token.toCookie());
                    res.redirect("/vault/home");
                    user.info("Succesful login.", req.ip());
                } else {
                    user.warning("Failed login attempt.", req.ip()); // Thoughts?
                    Sys.debug("Failed login attempt.", req.ip());    // ????
                    Map<String, Object> attributes = new HashMap<>();
                    String errorMessage = "This username/password combination does not exist!";
                    attributes.put("error", errorMessage);
                    return new ModelAndView(attributes, "login.ftl");
                }
            } else {
                Sys.debug("Failed login attempt.", req.ip());
                Map<String, Object> attributes = new HashMap<>();
                String errorMessage = "This username/password combination does not exist!";
                attributes.put("error", errorMessage);
                return new ModelAndView(attributes, "login.ftl");
            }
            return null;
        }, freeMarkerEngine);

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
            Token token = validateToken(req);
            if (token != null) {
                Sys.debug("Received GET to /vault/home.", req.ip());
                Map<String, Object> attributes = new HashMap<>();

                Password[] plist = demoUser.loadPasswords(token);

                List<Map<String, String>> listofmaps = new ArrayList<>();

                for (Password p : plist) {
                    listofmaps.add(p.toMap());
                }

                attributes.put("storedpasswords", listofmaps);

                return new ModelAndView(attributes, "home.ftl");
            } else {
                Sys.debug("Received unauthorized GET to /vault/home.");
                res.redirect("/");
                return null;
            }
        }, freeMarkerEngine);

    }

}
