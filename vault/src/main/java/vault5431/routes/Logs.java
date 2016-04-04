package vault5431.routes;


import spark.ModelAndView;
import vault5431.Sys;
import vault5431.Vault;
import vault5431.logging.SystemLogEntry;
import vault5431.logging.UserLogEntry;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static spark.Spark.get;

/**
 * Created by papacharlie on 3/25/16.
 */
class Logs extends Routes {

    protected void routes() {

        get("/userlog", (req, res) -> {
            Sys.debug("Received GET to /userlog.", req.ip());
            java.lang.System.out.println("user log");
            Map<String, Object> attributes = new HashMap<>();

            List<Map<String, String>> loglst = new ArrayList<>();

            for (UserLogEntry u : Vault.demoUser.loadLog()) {
                loglst.add(u.toMap());
            }

            attributes.put("userloglist", loglst);
            return new ModelAndView(attributes, "userlog.ftl");
        }, freeMarkerEngine);

        get("/syslog", (req, res) -> {
            Sys.debug("Received GET to /syslog.", req.ip());
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