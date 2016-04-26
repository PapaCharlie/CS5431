package vault5431.routes;

import freemarker.template.Configuration;
import spark.*;
import spark.template.freemarker.FreeMarkerEngine;
import vault5431.Sys;
import vault5431.auth.Token;
import vault5431.auth.exceptions.CouldNotParseTokenException;
import vault5431.auth.exceptions.InvalidTokenException;

import java.io.IOException;
import java.util.HashMap;

import static spark.Spark.*;

/**
 * Created by papacharlie on 3/25/16.
 */
public abstract class Routes {

    public static final ModelAndView emptyPage = new ModelAndView(new HashMap<>(), "");
    private static boolean initialized = false;

    public static Token validateToken(Request req) {
        if (req.cookie("token") != null && req.cookie("token").length() > 0) {
            try {
                return Token.pareCookie(req.cookie("token").trim(), req.ip());
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

    protected interface AuthenticatedViewRoute extends TemplateViewRoute {
        ModelAndView authenticatedHandle(Request request, Response response, Token token) throws Exception;

        default ModelAndView handle(Request request, Response response) throws Exception {
            Token token = validateToken(request);
            if (token != null) {
                return authenticatedHandle(request, response, token);
            } else {
                Sys.debug(String.format("Received unauthorized %s to %s.", request.requestMethod(), request.pathInfo()));
                response.redirect("/");
                return emptyPage;
            }
        }
    }

    protected interface AuthenticatedRoute extends Route {
        Object authenticatedHandle(Request request, Response response, Token token) throws Exception;

        default Object handle(Request request, Response response) throws Exception {
            Token token = validateToken(request);
            if (token != null) {
                Sys.debug(String.format("Received authorized %s to %s.", request.requestMethod(), request.pathInfo()));
                return authenticatedHandle(request, response, token);
            } else {
                Sys.debug(String.format("Received unauthorized %s to %s.", request.requestMethod(), request.pathInfo()));
                response.redirect("/");
                return "";
            }
        }
    }

    public static void authenticatedGet(String path, AuthenticatedViewRoute route, TemplateEngine engine) {
        get(path, route, engine);
    }

    public static void authenticatedGet(String path, AuthenticatedRoute route) {
        get(path, route);
    }

    public static void authenticatedPost(String path, AuthenticatedViewRoute route, TemplateEngine engine) {
        post(path, route, engine);
    }

    public static void authenticatedPost(String path, AuthenticatedRoute route) {
        post(path, route);
    }

    public static final String vault = "/vault";
    private static final Configuration freeMarkerConfiguration = new Configuration(Configuration.VERSION_2_3_23);
    public static final FreeMarkerEngine freeMarkerEngine = new FreeMarkerEngine(freeMarkerConfiguration);

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
        new GeneratorRoutes().routes();
        new LogRoutes().routes();
        new PasswordRoutes().routes();
    }

}
