package vault5431.routes;


import spark.ModelAndView;
import vault5431.logging.UserLogEntry;

import java.util.*;

/**
 * Created by papacharlie on 3/25/16.
 */
final class LogRoutes extends Routes {

    protected void routes() {

        authenticatedGet("/userlog", (req, res, token) -> {
            Map<String, Object> attributes = new HashMap<>();
            LinkedList<Map<String, String>> loglst = new LinkedList<>();
            for (UserLogEntry u : token.getUser().loadLog(token)) {
                loglst.add(u.toMap());
            }
            attributes.put("userloglist", loglst);
            return new ModelAndView(attributes, "userlog.ftl");
        });

    }

}