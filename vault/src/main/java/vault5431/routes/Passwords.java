package vault5431.routes;

import vault5431.Password;
import vault5431.Sys;
import vault5431.auth.Token;

import static spark.Spark.post;
import static vault5431.Vault.demoUser;

/**
 * Created by papacharlie on 3/25/16.
 */
class Passwords extends Routes {

    protected void routes() {

        post("/vault/changepassword", (req, res) -> {
            Token token = Authentication.validateToken(req);
            if (token != null) {
                Sys.debug("Received POST to /vault/changepassword.", req.ip());
                String w = req.queryParams("name");
                if (w != null && w.length() > 0) {
                    demoUser.info("Changed Password for " + w, req.ip());
                }
                res.redirect("/vault/home");
                return null;
            } else {
                Sys.debug("Received unauthorized POST to /vault/changepassword.");
                res.redirect("/");
                return null;
            }
        });

        post("/vault/savepassword", (req, res) -> {
            Token token = Authentication.validateToken(req);
            if (token != null) {
                Sys.debug("Received POST to /vault/savepassword.", req.ip());
                String web = req.queryParams("web");
                String url = req.queryParams("url");
                String username = req.queryParams("username");
                String password = req.queryParams("password");
                if (web != null
                        && web.length() > 0
                        && url != null
                        && url.length() > 0
                        && username != null
                        && username.length() > 0
                        && password != null
                        && password.length() > 0) {
                    try {
                        Password p = new Password(web, url, username, password);
                        demoUser.addPasswordToVault(p, token);
                    } catch (IllegalArgumentException err) {
                        String errorMessage = err.getLocalizedMessage();
                    }
                }
                res.redirect("/vault/home");
                return null;
            } else {
                Sys.debug("Received unauthorized POST to /vault/savepassword.");
                res.redirect("/");
                return null;
            }
        });

    }

}
