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

    private final String randomPassword = "randompassword";
    private final String length = "length";

    protected void routes() {
        get("/generator", (req, res) -> {
            Sys.debug("Received GET to /generator.", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            attributes.put(randomPassword, PasswordGenerator.generatePassword(12));
            attributes.put(length, "12");
            return new ModelAndView(attributes, "generator.ftl");
        }, freeMarkerEngine);

        post("/generator", (req, res) -> {
            Sys.debug("Received POST to /generator.", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            attributes.put(randomPassword, "");
            String len = req.queryParams("length");
            if (len != null) {
                try {
                    int chars = Integer.parseInt(len);
                    if (chars >= 6 && chars <= 100) {
                        attributes.put(length, len);
                        String pass = PasswordGenerator.generatePassword(chars);
                        attributes.replace(randomPassword, pass);
                    } else {
                        res.redirect("/generator");
                    }
                } catch (NumberFormatException err) {
                    res.redirect("/generator");
                }
            }
            return new ModelAndView(attributes, "generator.ftl");
        }, freeMarkerEngine);
    }
}
