package vault5431.routes;

import com.twilio.sdk.TwilioRestException;
import spark.ModelAndView;
import vault5431.Sys;
import vault5431.auth.AuthenticationHandler;
import vault5431.auth.AuthenticationHandler.Token;
import vault5431.crypto.sjcl.SJCLSymmetricField;
import vault5431.io.Base64String;
import vault5431.users.User;
import vault5431.users.UserManager;

import java.util.HashMap;
import java.util.Map;

import static spark.Spark.get;
import static spark.Spark.post;

/**
 * Contains the routes like "/" and "/twofactor", that a user must go through to acquire a token.
 *
 * @author papacharlie
 */
final class AuthenticationRoutes extends Routes {

    protected void routes() {

        get("/", (req, res) -> {
            Token token = validateToken(req);
            if (token != null) {
                if (token.isVerified()) {
                    res.redirect("/home");
                    return emptyPage;
                } else {
                    res.redirect("/twofactor");
                    return emptyPage;
                }
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
            if (!Base64String.isValidBase64Data(password)) {
                attributes.put("error", "Invalid password.");
                return new ModelAndView(attributes, "login.ftl");
            }
            if (UserManager.userExists(username)) {
                User user = UserManager.getUser(username);
                Token token = AuthenticationHandler.acquireUnverifiedToken(username, Base64String.fromBase64(password), req.ip());
                if (token != null) {
                    res.cookie(
                            "token",
                            token.toCookie(),
                            token.secondsUntilExpiration(),
                            true
                    );
                    res.redirect("/twofactor");
                    user.info("Successful password login.", token.getIp());
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
            Map<String, Object> attributes = new HashMap<>();
            if (token != null) {
                if (!token.isVerified()) {
                    try {
                        AuthenticationHandler.send2FACode(token);
                    } catch (TwilioRestException err) {
                        err.printStackTrace();
                        attributes.put("error", "The number you gave in at registration was invalid.");
                        return new ModelAndView(attributes, "twofactor.ftl");
                    }
                    Sys.debug("Received GET to /twofactor", req.ip());
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
                            Sys.debug("Two factor auth succesful!", verifiedToken);
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
            String confirm = req.queryParams("confirm");
            String pubCryptoKey = req.queryParams("pubCryptoKey");
            String privCryptoKey = req.queryParams("privCryptoKey");
            String pubSigningKey = req.queryParams("pubSigningKey");
            String privSigningKey = req.queryParams("privSigningKey");
            String phoneNumber = req.queryParams("phoneNumber");
            if (!provided(username, password, phoneNumber, confirm, pubCryptoKey, privCryptoKey, pubSigningKey, privSigningKey)) {
                attributes.put("error", "All fields are required!");
                return new ModelAndView(attributes, "register.ftl");
            }
            if (!(Base64String.isValidBase64Data(password)
                    && Base64String.isValidBase64Data(confirm)
                    && Base64String.isValidBase64Data(pubCryptoKey)
                    && Base64String.isValidBase64Data(pubSigningKey))) {
                attributes.put("error", "All fields are not of valid format. Please use the proper means.");
                return new ModelAndView(attributes, "login.ftl");
            }
            if (!password.equals(confirm)) {
                attributes.put("error", "Passwords are not equal!");
                return new ModelAndView(attributes, "register.ftl");
            }
            if (!UserManager.isValidUsername(username)) {
                attributes.put("error", "A username may only contain letters, numbers and underscores (_).");
                return new ModelAndView(attributes, "register.ftl");
            }
            if (!UserManager.userExists(username)) {
                try {
                    UserManager.create(username,
                            Base64String.fromBase64(password),
                            phoneNumber,
                            Base64String.fromBase64(pubCryptoKey),
                            new SJCLSymmetricField(privCryptoKey, 100, true),
                            Base64String.fromBase64(pubSigningKey),
                            new SJCLSymmetricField(privSigningKey, 100, true));
                } catch (IllegalArgumentException err) {
                    err.printStackTrace();
                    attributes.put("error", "Invalid password!");
                    return new ModelAndView(attributes, "register.ftl");
                } catch (Exception err) {
                    System.err.println("Could not create user!");
                    throw new RuntimeException(err);
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
