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
class Logs extends Routes {

    protected void routes() {

        get("/vault/userlog", (req, res) -> {
            Sys.debug("Received GET to /vault/userlog.", req.ip());
            Map<String, Object> attributes = new HashMap<>();

            List<Map<String, String>> loglst = new ArrayList<>();

            for (UserLogEntry u : Vault.demoUser.loadLog()) {
                loglst.add(u.toMap());
            }

            attributes.put("userloglist", loglst);
            return new ModelAndView(attributes, "userlog.ftl");
        }, freeMarkerEngine);

        get("/vault/syslog", (req, res) -> {
            Sys.debug("Received GET to /vault/syslog.", req.ip());
            Map<String, Object> attributes = new HashMap<>();

            List<Map<String, String>> sysloglist = new ArrayList<>();

            for (SystemLogEntry e : Sys.loadLog()) {
                sysloglist.add(e.toMap());
            }

            attributes.put("sysloglist", sysloglist);
            return new ModelAndView(attributes, "syslog.ftl");
        }, freeMarkerEngine);

    }

}