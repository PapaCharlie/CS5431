package vault5431.routes;

import freemarker.template.Configuration;
import org.apache.commons.io.output.StringBuilderWriter;
import org.json.JSONObject;
import spark.ModelAndView;
import spark.Request;
import spark.Response;
import spark.Route;
import spark.template.freemarker.FreeMarkerEngine;
import vault5431.Sys;
import vault5431.auth.AuthenticationHandler;
import vault5431.auth.AuthenticationHandler.Token;
import vault5431.auth.SMSHandler;
import vault5431.auth.exceptions.CouldNotParseTokenException;
import vault5431.auth.exceptions.InvalidTokenException;
import vault5431.auth.exceptions.NoSuchUserException;
import vault5431.routes.exceptions.SessionExpiredException;
import vault5431.users.exceptions.CorruptedLogException;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;

import static spark.Spark.*;

/**
 * Basic Routes abstract class. Classes that extend Routes will have access to all required API for serving web pages.
 *
 * @author papacharlie
 */
public abstract class Routes {

    static final ModelAndView emptyPage = new ModelAndView(new HashMap<>(0), "");
    private static final Configuration freeMarkerConfiguration = new Configuration(Configuration.VERSION_2_3_23);
    static final FreeMarkerEngine freeMarkerEngine = new FreeMarkerEngine(freeMarkerConfiguration);
    private static boolean initialized = false;

    static JSONObject failure(String error) {
        return new JSONObject().put("success", false).put("error", error);
    }

    static JSONObject failure(Exception error) {
        return new JSONObject().put("success", false).put("error", error.getMessage());
    }

    static JSONObject userDoesNotExist() {
        return new JSONObject().put("success", false).put("error", "This user does not exist!");
    }

    static JSONObject invalidRequest() {
        return new JSONObject().put("success", false).put("error", "Invalid request!");
    }

    static JSONObject allFieldsRequired() {
        return new JSONObject().put("success", false).put("error", "All fields are required!");
    }

    static JSONObject success() {
        return new JSONObject().put("success", true).put("error", "");
    }

    static JSONObject success(String message) {
        return new JSONObject().put("success", true).put("error", "").put("message", message);
    }

    static Token validateToken(Request req) throws NoSuchUserException, CouldNotParseTokenException, InvalidTokenException {
        if (req.cookie("token") != null && req.cookie("token").length() > 0) {
            return AuthenticationHandler.parseFromCookie(req.cookie("token").trim(), req.ip());
        } else {
            return null;
        }
    }

    static void authenticatedGet(String path, AuthenticatedRoute route) {
        get(path, route);
    }

    static void authenticatedPost(String path, AuthenticatedRoute route) {
        post(path, route);
    }

    static void authenticatedPut(String path, AuthenticatedRoute route) {
        put(path, route);
    }

    static void authenticatedDelete(String path, AuthenticatedRoute route) {
        delete(path, route);
    }

    static boolean provided(String... formFields) {
        for (String field : formFields) {
            if (!(field != null && field.length() > 0)) {
                return false;
            }
        }
        return true;
    }

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
        new SharedPasswordRoutes().routes();
        new GeneratorRoutes().routes();
        new LogRoutes().routes();
        new PasswordRoutes().routes();

    }

    public static void panic(Exception err) {
        before("*", (req, res) -> {
            halt(500, freeMarkerEngine.render(new ModelAndView(new HashMap<>(0), "maintenance.ftl")));
        });
        err.printStackTrace();
        StringBuilderWriter trace = new StringBuilderWriter();
        err.printStackTrace(new PrintWriter(trace));
        if (!(err instanceof IOException || err instanceof CorruptedLogException)) {
            Sys.error(trace.toString());
        }
        try {
            SMSHandler.sendSms("646-339-1069", "We're under attack! Please check the logs to see the problem: " + err.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected abstract void routes();

    /**
     * This class guarantees routes defined using {@link #authenticatedGet} and co. will only be called with a valid
     * Token. Effectively, this is the Reference Monitor for route handling, i.e. route code is only called when
     * proper authentication has been presented.
     */
    interface AuthenticatedRoute extends Route {
        Object authenticatedHandle(Request request, Response response, Token token) throws Exception;

        default Object handle(Request request, Response response) throws Exception {
            Token token = validateToken(request);
            if (token != null) {
                if (!token.isVerified()) {
                    response.redirect("/twofactor");
                    return "";
                } else {
                    Sys.debug(String.format("Received authorized %s to %s.", request.requestMethod(), request.pathInfo()), token);
                    Object res = authenticatedHandle(request, response, token);
                    if (res instanceof ModelAndView) {
                        return freeMarkerEngine.render((ModelAndView) res);
                    } else if (res instanceof JSONObject) {
                        return res.toString();
                    } else {
                        return res;
                    }
                }
            } else {
                Sys.debug(String.format("Received unauthorized %s to %s.", request.requestMethod(), request.pathInfo()), request.ip());
                throw new SessionExpiredException();
            }
        }
    }

}
