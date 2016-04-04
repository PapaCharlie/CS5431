package vault5431.routes;

import spark.ModelAndView;
import vault5431.Password;
import vault5431.Sys;
import vault5431.users.UserManager;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static spark.Spark.get;
import static spark.Spark.post;
import static vault5431.Vault.demoUser;

/**
 * Created by papacharlie on 3/25/16.
 */
class Authentication extends Routes {

    protected void routes() {

        get("/", (req, res) -> {
            Sys.debug("Received GET to /.", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            return new ModelAndView(attributes, "login.ftl");
        }, freeMarkerEngine);

        post("/authenticate", (req, res) -> {
            Sys.debug("Received POST to /authenticate.", req.ip());
            if (req.queryParams("username") != null) {
                if (UserManager.userExists(req.queryParams("username"))) {
                    System.out.println("exists");
                    res.redirect("/vault");
                    demoUser.info("Action: Log In", demoUser, req.ip());
                }
            }
            res.redirect("/");
            return "";
        });

        get("/vault", (req, res) -> {
            Sys.debug("Received GET to /vault.", req.ip());
            Map<String, Object> attributes = new HashMap<>();

            Password[] plist = demoUser.loadPasswords();

            List<Map<String, String>> listofmaps = new ArrayList<>();

            for (Password p : plist) {
                listofmaps.add(p.toMap());
            }

            attributes.put("storedpasswords", listofmaps);

            return new ModelAndView(attributes, "vault.ftl");
        }, freeMarkerEngine);

    }

}
