package vault5431.routes;

import freemarker.template.Configuration;
import spark.ModelAndView;
import spark.Request;
import spark.template.freemarker.FreeMarkerEngine;
import vault5431.Sys;
import vault5431.auth.Token;
import vault5431.auth.exceptions.CouldNotParseTokenException;
import vault5431.auth.exceptions.InvalidTokenException;

import java.io.IOException;
import java.util.HashMap;

import static spark.Spark.staticFileLocation;

/**
 * Created by papacharlie on 3/25/16.
 */
public abstract class Routes {

    public static final ModelAndView emptyPage = new ModelAndView(new HashMap<>(), "");
    public static final String home = "https://localhost:5431/";

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

    public static final String vault = "/vault";
    private static final Configuration freeMarkerConfiguration = new Configuration();
    public static final FreeMarkerEngine freeMarkerEngine = new FreeMarkerEngine(freeMarkerConfiguration);

    protected abstract void routes();

    public static void initialize() throws IOException {
        staticFileLocation("templates");
        freeMarkerConfiguration.setClassForTemplateLoading(Routes.class, "/templates");
        new Authentication().routes();
        new Generator().routes();
        new Logs().routes();
        new Passwords().routes();
    }

}
