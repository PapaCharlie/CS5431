package vault5431.routes;

import spark.ModelAndView;
import vault5431.PasswordGenerator;
import vault5431.Sys;

import java.util.HashMap;
import java.util.Map;

import static spark.Spark.get;
import static spark.Spark.post;

/**
 * Created by papacharlie on 3/25/16.
 */
class GeneratorRoutes extends Routes {

    private static boolean parseCheckbox(String formField) {
        return formField != null && formField.trim().toLowerCase().equals("true");
    }

    protected void routes() {

        get("/generator", (req, res) -> {
            Sys.debug("Received GET to /generator.", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            return new ModelAndView(attributes, "generator.ftl");
        }, freeMarkerEngine);

        post("/generator", (req, res) -> {
            Sys.debug("Received POST to /generator.", req.ip());
            String length = req.queryParams("length");
            boolean lower = parseCheckbox(req.queryParams("lower"));
            boolean upper = parseCheckbox(req.queryParams("upper"));
            boolean numbers = parseCheckbox(req.queryParams("numbers"));
            boolean symbols = parseCheckbox(req.queryParams("symbols"));
            boolean pronounceable = parseCheckbox(req.queryParams("pronounceable"));
            if (!(lower || upper || numbers || symbols)) {
                return "{\"success\":false, \"error\":\"Need at least one set of letters!\"}";
            }
            if (length != null) {
                try {
                    int chars = Integer.parseInt(length);
                    if (6 <= chars && chars <= 100) {
                        String pass = PasswordGenerator.generatePassword(chars, lower, upper, numbers, symbols, pronounceable);
                        return String.format("{\"success\":true, \"password\":\"%s\"}", pass);
                    } else {
                        return "{\"success\":false, \"error\":\"Number must be between 6 and 100.\"}";
                    }
                } catch (NumberFormatException err) {
                    return "{\"success\":false, \"error\":\"Invalid number!\"}";
                } catch (IllegalArgumentException err) {
                    return String.format("{\"success\":false, \"error\":\"%s\"}", err.getMessage());
                }
            } else {
                return "{\"success\":false, \"error\":\"Length field is required!\"}";
            }
        });

    }
}
