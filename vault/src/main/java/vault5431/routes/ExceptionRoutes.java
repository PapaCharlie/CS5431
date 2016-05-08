package vault5431.routes;

import spark.ModelAndView;
import spark.Request;
import spark.Response;
import spark.Spark;
import vault5431.Sys;
import vault5431.auth.exceptions.*;
import vault5431.routes.exceptions.SessionExpiredException;
import vault5431.users.exceptions.IllegalTokenException;

import java.util.HashMap;

import static spark.Spark.exception;
import static spark.Spark.get;

/**
 * Catches and renders commonly thrown errors.
 *
 * @author papacharlie
 */
final class ExceptionRoutes extends Routes {

    /**
     * Render the login screen with the error in red text.
     *
     * @param errorMessage message to render on the login screen
     * @param req          request on which to render the error
     * @param res          response on which to render the error
     */
    private void renderFatalError(String errorMessage, Request req, Response res) {
        res.removeCookie("token");
        req.session().attribute("error", errorMessage);
        res.redirect("/");
    }

    protected void routes() {
        exception(SessionExpiredException.class, (e, req, res) -> renderFatalError("Session has expired!", req, res));


        exception(InvalidTokenException.class, (e, req, res) -> {
            Sys.warning(String.format("Rejecting token. Reason: \"%s\". There is reason to believe this IP is acting maliciously.", e.getMessage()), req.ip());
            renderFatalError("Session has expired!", req, res);
        });

        exception(CouldNotParseTokenException.class, (e, req, res) -> {
            Sys.debug("Received invalid token.", req.ip());
            renderFatalError("Session has expired!", req, res);
        });

        exception(TooManyFailedLogins.class, (e, req, res) ->
                renderFatalError("Suspicious activity has been observed on your account, and no further logins will be accepted. Try again later.", req, res));

        exception(TooManyConcurrentSessionsException.class, (e, req, res) ->
                renderFatalError("You are logged from too many places. Please log out of other devices before using this one.", req, res));

        exception(TooMany2FAAttemptsException.class, (e, req, res) ->
                renderFatalError("You've attempted two factor authentication too many times!", req, res));

        exception(IllegalTokenException.class, (e, req, res) -> {
            res.redirect("/unauthorized");
        });

        exception(NoSuchUserException.class, (e, req, res) ->
                renderFatalError("This account has been deleted!", req, res)
        );

        get("/unauthorized", (req, res) ->
                new ModelAndView(new HashMap<>(0), "unauthorized.ftl")
        );

    }

}
