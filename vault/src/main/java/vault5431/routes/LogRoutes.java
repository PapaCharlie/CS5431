package vault5431.routes;


import spark.ModelAndView;
import vault5431.Sys;
import vault5431.Vault;
import vault5431.auth.Token;
import vault5431.auth.exceptions.CouldNotParseTokenException;
import vault5431.auth.exceptions.InvalidTokenException;
import vault5431.logging.SystemLogEntry;
import vault5431.logging.UserLogEntry;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static spark.Spark.before;
import static spark.Spark.get;
import static spark.Spark.halt;

/**
 * Created by papacharlie on 3/25/16.
 */
class LogRoutes extends Routes {

    protected void routes() {

        get("/userlog", (req, res) -> {
            Token token = validateToken(req);
            if (token != null && token.isVerified()) {
                Sys.debug("Received authenticated GET to /vault/userlog.", req.ip());
                Map<String, Object> attributes = new HashMap<>();
                List<Map<String, String>> loglst = new ArrayList<>();
                for (UserLogEntry u : token.getUser().loadLog(token)) {
                    loglst.add(u.toMap());
                }
                attributes.put("userloglist", loglst);
                return new ModelAndView(attributes, "userlog.ftl");
            } else {
                Sys.debug("Received unauthorized GET to /vault/userlog.");
                res.redirect("/");
                return emptyPage;
            }
        }, freeMarkerEngine);

    }

}