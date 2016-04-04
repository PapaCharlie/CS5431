package vault5431.routes;

import vault5431.Password;
import vault5431.Sys;

import static spark.Spark.post;
import static vault5431.Vault.demoUser;

/**
 * Created by papacharlie on 3/25/16.
 */
class Passwords extends Routes {

    protected void routes() {

        post("/changepassword", (req, res) -> {
            Sys.debug("Received POST to /changepassword.", req.ip());
            String w = req.queryParams("name");
            if (w != null && w.length() > 0) {
                demoUser.info("Changed Password for " + w, req.ip());
            }
            res.redirect("/vault");
            return "";
        });

        post("/savepassword", (req, res) -> {
            Sys.debug("Received POST to /savepassword.", req.ip());
            String web = req.queryParams("web");
            String url = req.queryParams("url");
            String username = req.queryParams("username");
            String password = req.queryParams("password");
            if (web != null && url != null && username != null && password != null) {
                try {
                    Password p = new Password(web, url, username, password);
                    demoUser.addPassword(p);
                } catch (IllegalArgumentException err) {
                    String errorMessage = err.getLocalizedMessage();
                }
            }
            res.redirect("/vault");
            return "";
        });

    }

}
