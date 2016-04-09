package vault5431.routes;

import spark.ModelAndView;
import vault5431.Sys;
import vault5431.auth.RollingKeys;
import vault5431.auth.Token;
import vault5431.io.Base64String;
import vault5431.users.UserManager;
import vault5431.users.User;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import static spark.Spark.get;
import static spark.Spark.post;
import static java.time.temporal.ChronoUnit.SECONDS;


/**
 * Created by papacharlie on 3/25/16.
 */
class Authentication extends Routes {

    protected void routes() {

        get("/", (req, res) -> {
            Token token = validateToken(req);
            if (token != null) {
                res.redirect("/home");
                return emptyPage;
            } else {
                Sys.debug("Received GET to /.", req.ip());
                Map<String, Object> attributes = new HashMap<>();
                return new ModelAndView(attributes, "login.ftl");
            }
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
                if (UserManager.userExists(username)
                        && UserManager.getUser(username).verifyPassword(Base64String.fromBase64(password))) {
                    Token token = new Token(UserManager.getUser(username));
                    res.cookie(
                            home,
                            "token",
                            token.toCookie(),
                            (int) LocalDateTime.now().until(RollingKeys.getEndOfCurrentWindow(), SECONDS),
                            true);
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

        get("/register", (req, res) -> {
            Sys.debug("Received GET to /register", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            return new ModelAndView(attributes, "register.ftl");
        }, freeMarkerEngine);

        post("/register", (req, res) -> {
            Sys.debug("Received POST to /register.", req.ip());
            if (req.queryParams("username") != null && req.queryParams("password") != null && !UserManager.userExists(req.queryParams("username"))) {
                System.out.println("New user Created");
                try {
                    UserManager.create(req.queryParams("username"), Base64String.fromBase64(req.queryParams("password")));
                } catch (Exception err) {
                    err.printStackTrace();
                    System.err.println("Could not create user!");
                    System.exit(1);
                }
                res.redirect("/vault/home");
                User user = UserManager.getUser(req.queryParams("username"));
                user.info("Action: Log In", req.ip());


            } else {
                res.redirect("/");
            }
            return null;
        });


//        before("/vault/*", (req, res) -> {
//            if (req.cookie("token") != null) {
//                try {
//                    Token token = Token.parseToken(req.cookie("token"));
//                } catch (CouldNotParseTokenException err) {
//                    res.removeCookie("token");
//                    res.redirect("/unauthorized");
//                } catch (InvalidTokenException err) {
//                    Sys.warning("Received invalid token. There is reason to believe this IP is acting malicious.", req.ip());
//                    res.removeCookie("token");
//                    res.redirect("/unauthorized");
//                }
//            } else {
//                res.removeCookie("token");
//                res.redirect("/unauthorized");
//            }
//        });

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
