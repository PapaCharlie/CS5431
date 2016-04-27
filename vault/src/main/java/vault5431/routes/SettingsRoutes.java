package vault5431.routes;

import spark.ModelAndView;
import vault5431.users.Settings;

import java.util.HashMap;
import java.util.Set;

import static spark.Spark.get;

/**
 * Created by papacharlie on 2016-04-27.
 */
public class SettingsRoutes extends Routes {

    private Integer parseNumberField(String formField) {
        if (formField != null && formField.length() > 0) {
            try {
                return Integer.parseInt(formField);
            } catch (NumberFormatException err) {
                return null;
            }
        } else {
            return null;
        }
    }

    protected void routes() {

        authenticatedGet("/settings", (req, res, token) -> {
            HashMap<String, Object> attributes = new HashMap<>();
            Settings settings = token.getUser().loadSettings();
            attributes.put("concurrentSessions", settings.getConcurrentSessions());
            attributes.put("sessionLength", settings.getSessionLength());
            return new ModelAndView(attributes, "settings.ftl");
        });

        authenticatedPost("/settings", (req, res, token) -> {
            String concurrentSessions = req.queryParams("concurrentSessions");
            if (concurrentSessions != null && concurrentSessions.length() > 0) {
                Integer cS = parseNumberField(concurrentSessions);
                if (cS != null) {
                    try {
                        Settings settings = token.getUser().loadSettings();
                        if (settings.getConcurrentSessions() != cS) {
                            token.getUser().changeSettings(settings.withConcurrentSessions(cS));
                            token.getUser().info("Changed maximum number of concurrent users.", token.getIp());
                        }
                    } catch (IllegalArgumentException err) {
                        return String.format(invalidRequestWithError, err.getMessage());
                    }
                } else {
                    return String.format(invalidRequestWithError, "concurrentSessions must be an integer!");
                }
            }
            String sessionLength = req.queryParams("sessionLength");
            if (sessionLength != null && sessionLength.length() > 0) {
                Integer sL = parseNumberField(sessionLength);
                if (sL != null) {
                    try {
                        Settings settings = token.getUser().loadSettings();
                        if (settings.getSessionLength() != sL) {
                            token.getUser().changeSettings(settings.withSessionLength(sL));
                            token.getUser().info("Changed maximum session length.", token.getIp());
                        }
                    } catch (IllegalArgumentException err) {
                        return String.format(invalidRequestWithError, err.getMessage());
                    }
                } else {
                    return String.format(invalidRequestWithError, "sessionLength must be an integer!");
                }
            }
            return success;
        });

    }
}
