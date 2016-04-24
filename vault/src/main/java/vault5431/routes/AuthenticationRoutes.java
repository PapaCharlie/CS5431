package vault5431.routes;

import spark.ModelAndView;
import vault5431.Sys;
import vault5431.auth.RollingKeys;
import vault5431.auth.Token;
import vault5431.io.Base64String;
import vault5431.twofactor.AuthMessageManager;
import vault5431.users.UserManager;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.Pack200;

import static java.time.temporal.ChronoUnit.SECONDS;
import static spark.Spark.get;
import static spark.Spark.post;

/**
 * Created by papacharlie on 3/25/16.
 */
class AuthenticationRoutes extends Routes {

    protected void routes() {

        get("/", (req, res) -> {
            Token token = validateToken(req);
            if (token != null && token.isVerified()) {
                res.redirect("/home");
                return emptyPage;
            } else {
                res.removeCookie("token");
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
                    Token token = new Token(UserManager.getUser(username), false);
                    res.cookie(
                            "token",
                            token.toCookie(),
                            (int) LocalDateTime.now().until(RollingKeys.getEndOfCurrentWindow(), SECONDS),
                            true
                    );
                    res.redirect("/twofactor");
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

        get("/twofactor", (req, res) -> {
            Token token = validateToken(req);
            if (token != null) {
                if (!token.isVerified()) {
                    AuthMessageManager.sendAuthMessage(token.getUser());
                    Sys.debug("Received GET to /twofactor", req.ip());
                    Map<String, Object> attributes = new HashMap<>();
                    return new ModelAndView(attributes, "twofactor.ftl");
                } else {
                    res.redirect("/home");
                    return emptyPage;
                }
            } else {
                res.redirect("/");
                return emptyPage;
            }
        }, freeMarkerEngine);

        post("/twofactor", (req, res) -> {
            Token token = validateToken(req);
            if (token != null) {
                if (!token.isVerified()) {
                    String authCode = req.queryParams("authCode");
                    if (authCode != null && authCode.length() > 0) {
                        try {
                            int code = Integer.parseInt(authCode);
                            if (AuthMessageManager.verifyAuthMessage(token.getUser(), code)) {
                                Sys.debug("Two factor auth succesful!", token.getUser(), token.getIp());
                                token.getUser().info("Succesful login.", token.getIp());
                                res.cookie(
                                        "token",
                                        token.verify().toCookie(),
                                        (int) LocalDateTime.now().until(RollingKeys.getEndOfCurrentWindow(), SECONDS),
                                        true
                                );
                                res.redirect("/home");
                                return emptyPage;
                            } else {
                                res.removeCookie("token");
                                res.redirect("/");
                                return emptyPage;
                            }
                        } catch (NumberFormatException err) {
                            err.printStackTrace();
                            Map<String, Object> attributes = new HashMap<>();
                            attributes.put("error", "Code must be a number!");
                            return new ModelAndView(attributes, "twofactor.ftl");
                        }
                    } else {
                        Map<String, Object> attributes = new HashMap<>();
                        attributes.put("error", "Code is required!");
                        return new ModelAndView(attributes, "twofactor.ftl");
                    }
                } else {
                    res.redirect("/home");
                    return emptyPage;
                }
            } else {
                res.redirect("/");
                return emptyPage;
            }
        }, freeMarkerEngine);

        get("/register", (req, res) -> {
            Sys.debug("Received GET to /register", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            return new ModelAndView(attributes, "register.ftl");
        }, freeMarkerEngine);

        post("/register", (req, res) -> {
            Sys.debug("Received POST to /register.", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            String username = req.queryParams("username");
            String password = req.queryParams("password");
            String phoneNumnber = req.queryParams("phoneNumber");
            if (username != null
                    && username.length() > 0
                    && password != null
                    && password.length() > 0
                    && phoneNumnber != null
                    && phoneNumnber.length() > 0) {
                if (!UserManager.userExists(username)) {
                    try {
                        UserManager.create(username, Base64String.fromBase64(password), phoneNumnber);
                    } catch (Exception err) {
                        err.printStackTrace();
                        System.err.println("Could not create user!");
                        System.exit(1);
                    }
                    res.redirect("/");
                    return emptyPage;
                } else {
                    attributes.put("error", "This username is already taken!");
                    return new ModelAndView(attributes, "register.ftl");
                }
            } else {
                attributes.put("error", "All fields are required!");
                return new ModelAndView(attributes, "register.ftl");
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