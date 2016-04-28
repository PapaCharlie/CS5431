package vault5431.routes;

import freemarker.template.Configuration;
import spark.*;
import spark.template.freemarker.FreeMarkerEngine;
import vault5431.Sys;
import vault5431.auth.AuthenticationHandler;
import vault5431.auth.Token;
import vault5431.auth.exceptions.CouldNotParseTokenException;
import vault5431.auth.exceptions.InvalidTokenException;
import vault5431.routes.exceptions.SessionExpiredException;

import java.io.IOException;
import java.util.HashMap;

import static spark.Spark.*;

/**
 * Created by papacharlie on 3/25/16.
 */
public abstract class Routes {

    protected static final ModelAndView emptyPage = new ModelAndView(new HashMap<>(), "");
    protected static final String invalidRequest = "{\"success\":false, \"error\": \"Invalid request!\"}";
    protected static final String invalidRequestWithError = "{\"success\":false, \"error\": \"%s\"}";
    protected static final String allFieldsRequired = "{\"success\":false, \"error\": \"All fields are required!\"}";
    protected static final String success = "{\"success\":true, \"error\": \"\"}";

    private static boolean initialized = false;

    protected static Token validateToken(Request req) {
        if (req.cookie("token") != null && req.cookie("token").length() > 0) {
            try {
                return AuthenticationHandler.parseFromCookie(req.cookie("token").trim(), req.ip());
            } catch (CouldNotParseTokenException err) {
                Sys.debug("Received invalid token.", req.ip());
                return null;
            } catch (InvalidTokenException err) {
                Sys.warning(String.format("Rejecting token. Reason: %s. There is reason to believe this IP is acting maliciously.", err.getMessage()), req.ip());
                return null;
            }
        } else {
            return null;
        }
    }

    protected interface AuthenticatedRoute extends Route {
        Object authenticatedHandle(Request request, Response response, Token token) throws Exception;

        default Object handle(Request request, Response response) throws Exception {
            Token token = validateToken(request);
            if (token != null) {
                Sys.debug(String.format("Received authorized %s to %s.", request.requestMethod(), request.pathInfo()), token.getUser(), token.getIp());
                Object res = authenticatedHandle(request, response, token);
                if (res instanceof ModelAndView) {
                    return freeMarkerEngine.render((ModelAndView) res);
                } else {
                    return res;
                }
            } else {
                Sys.debug(String.format("Received unauthorized %s to %s.", request.requestMethod(), request.pathInfo()), request.ip());
                throw new SessionExpiredException();
            }
        }
    }

    protected static void authenticatedGet(String path, AuthenticatedRoute route) {
        get(path, route);
    }

    protected static void authenticatedPost(String path, AuthenticatedRoute route) {
        post(path, route);
    }

    protected static void authenticatedPut(String path, AuthenticatedRoute route) {
        put(path, route);
    }

    protected static void authenticatedDelete(String path, AuthenticatedRoute route) {
        delete(path, route);
    }

    protected static boolean provided(String... formFields) {
        for (String field : formFields) {
            if (!(field != null && field.length() > 0)) {
                return false;
            }
        }
        return true;
    }

    protected static final String vault = "/vault";
    private static final Configuration freeMarkerConfiguration = new Configuration(Configuration.VERSION_2_3_23);
    protected static final FreeMarkerEngine freeMarkerEngine = new FreeMarkerEngine(freeMarkerConfiguration);

    protected abstract void routes();

    public static void initialize() throws IOException {
        if (initialized) {
            return;
        } else {
            initialized = true;
        }

        staticFileLocation("static");
        freeMarkerConfiguration.setClassForTemplateLoading(Routes.class, "/freemarker");
        new AuthenticationRoutes().routes();
        new ExceptionRoutes().routes();
        new SettingsRoutes().routes();
        new GeneratorRoutes().routes();
        new LogRoutes().routes();
        new PasswordRoutes().routes();
    }

}
