package vault5431.routes;

import spark.ModelAndView;
import spark.Response;
import vault5431.auth.exceptions.*;
import vault5431.routes.exceptions.SessionExpiredException;

import java.util.HashMap;
import java.util.Map;

import static spark.Spark.exception;

/**
 * Created by papacharlie on 2016-04-26.
 */
public class ExceptionRoutes extends Routes {

    private void renderFatalError(String message, Response res) {
        res.removeCookie("token");
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("error", message);
        ModelAndView model = new ModelAndView(attributes, "login.ftl");
        res.body(freeMarkerEngine.render(model));
    }

    protected void routes() {
        exception(SessionExpiredException.class, (e, req, res) -> {
            renderFatalError("Session has expired!", res);
        });


        exception(InvalidTokenException.class, (e, req, res) -> {
            renderFatalError("Session has expired!", res);
        });

        exception(CouldNotParseTokenException.class, (e, req, res) -> {
            renderFatalError("Session has expired!", res);
        });

        exception(TooManyFailedLogins.class, (e, req, res) -> {
            renderFatalError("Suspicious activity has been observed on your account, and no further logins will be accepted. Try again later.", res);
        });

        exception(TooManyConcurrentSessionsException.class, (e, req, res) -> {
            renderFatalError("You are logged from too many places. Please log out of other devices before using this one.", res);
        });

        exception(TooMany2FAAttemptsException.class, (e, req, res) -> {
            renderFatalError("You've attempted two factor authentication too many times!", res);
        });

    }

}
