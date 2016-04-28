package vault5431.routes;

import spark.ModelAndView;
import vault5431.Sys;
import vault5431.auth.AuthenticationHandler;
import vault5431.auth.Token;
import vault5431.io.Base64String;
import vault5431.users.User;
import vault5431.users.UserManager;

import java.util.HashMap;
import java.util.Map;

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
            if (!provided(username, password)) {
                attributes.put("error", "All fields are required!");
                return new ModelAndView(attributes, "login.ftl");
            }
            if (UserManager.userExists(username)) {
                User user = UserManager.getUser(username);
                Token token = AuthenticationHandler.acquireUnverifiedToken(user, Base64String.fromBase64(password), req.ip());
                if (token != null) {
                    res.cookie(
                            "token",
                            token.toCookie(),
                            token.secondsUntilExpiration(),
                            true
                    );
                    res.redirect("/twofactor");
                    return emptyPage;
                } else {
                    user.warning("Failed password verification attempt.", req.ip());
                }
            }
            Sys.debug("Failed login attempt.", req.ip());
            String errorMessage = "This username/password combination does not exist!";
            attributes.put("error", errorMessage);
            return new ModelAndView(attributes, "login.ftl");
        }, freeMarkerEngine);

        get("/twofactor", (req, res) -> {
            Token token = validateToken(req);
            if (token != null) {
                if (!token.isVerified()) {
                    AuthenticationHandler.send2FACode(token.getUser());
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
            Map<String, Object> attributes = new HashMap<>();
            if (token != null) {
                if (!token.isVerified()) {
                    String authCode = req.queryParams("authCode");
                    if (!provided(authCode)) {
                        attributes.put("error", "Code is required!");
                        return new ModelAndView(attributes, "twofactor.ftl");
                    }
                    try {
                        int code = Integer.parseInt(authCode);
                        Token verifiedToken = AuthenticationHandler.acquireVerifiedToken(token, code);
                        if (verifiedToken != null) {
                            Sys.debug("Two factor auth succesful!", verifiedToken.getUser(), verifiedToken.getIp());
                            verifiedToken.getUser().info("Succesful login.", verifiedToken.getIp());
                            res.cookie(
                                    "token",
                                    verifiedToken.toCookie(),
                                    verifiedToken.secondsUntilExpiration(),
                                    true
                            );
                            res.redirect("/home");
                            return emptyPage;
                        } else {
                            token.getUser().warning("Invalid two factor authentication attempt!", token.getIp());
                            attributes.put("error", "This isn't the right code!");
                            return new ModelAndView(attributes, "twofactor.ftl");
                        }
                    } catch (NumberFormatException err) {
                        err.printStackTrace();
                        attributes.put("error", "Code must be a number!");
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
            if (!provided(username, password, phoneNumnber)) {
                attributes.put("error", "All fields are required!");
                return new ModelAndView(attributes, "register.ftl");
            }
            if (!UserManager.userExists(username)) {
                try {
                    UserManager.create(username, Base64String.fromBase64(password), phoneNumnber);
                } catch (IllegalArgumentException err) {
                    err.printStackTrace();
                    attributes.put("error", "Invalid password!");
                    return new ModelAndView(attributes, "register.ftl");
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

        }, freeMarkerEngine);

        authenticatedGet("/logout", (req, res, token) -> {
            AuthenticationHandler.logout(token);
            res.removeCookie("token");
            res.redirect("/");
            return emptyPage;
        });

        get("/unauthorized", (req, res) -> {
            Sys.debug("Displaying unauthorized page.", req.ip());
            res.status(401);
            res.removeCookie("token");
            Map<String, Object> attributes = new HashMap<>();
            return new ModelAndView(attributes, "unauthorized.ftl");
        }, freeMarkerEngine);

    }

}
