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
class Generator extends Routes {

    protected void routes() {
        get("/generator", (req, res) -> {
            Sys.debug("Received GET to /generator.", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            return new ModelAndView(attributes, "generator.ftl");
        }, freeMarkerEngine);

        post("/generator", (req, res) -> {
            Sys.debug("Received POST to /generator.", req.ip());
            String length = req.queryParams("length");
            if (length != null) {
                try {
                    int chars = Integer.parseInt(length);
                    if (chars >= 6 && chars <= 100) {
                        String pass = PasswordGenerator.generatePassword(chars);
                        return String.format("{\"success\":true, \"password\":\"%s\"}", pass);
                    } else {
                        return "{\"success\":false, \"error\":\"Number must be between 6 and 100.\"}";
                    }
                } catch (NumberFormatException err) {
                    return "{\"success\":false, \"error\":\"Invalid number!\"}";
                }
            } else {
                return "{\"success\":false, \"error\":\"Length field is required!\"}";
            }
        });
    }
}
