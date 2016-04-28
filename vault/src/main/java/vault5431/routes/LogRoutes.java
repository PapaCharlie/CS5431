package vault5431.routes;


import spark.ModelAndView;
import vault5431.logging.UserLogEntry;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by papacharlie on 3/25/16.
 */
class LogRoutes extends Routes {

    protected void routes() {

        authenticatedGet("/userlog", (req, res, token) -> {
            Map<String, Object> attributes = new HashMap<>();
            List<Map<String, String>> loglst = new ArrayList<>();
            for (UserLogEntry u : token.getUser().loadLog(token)) {
                loglst.add(u.toMap());
            }
            attributes.put("userloglist", loglst);
            return new ModelAndView(attributes, "userlog.ftl");
        });

    }

}