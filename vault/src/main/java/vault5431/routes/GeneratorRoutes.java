package vault5431.routes;

import spark.ModelAndView;
import vault5431.PasswordGenerator;
import vault5431.Sys;

import java.util.HashMap;
import java.util.Map;

import static spark.Spark.get;
import static spark.Spark.post;

/**
 * Contains the routes for "/generator".
 *
 * @author papacharlie
 */
final class GeneratorRoutes extends Routes {

    /**
     * Returns true if a given checkbox was ticked.
     *
     * @param formField checkbox id to parse
     * @return true iff the field was given and exactly equals "true"
     */
    private static boolean parseCheckbox(String formField) {
        return formField != null && formField.trim().toLowerCase().equals("true");
    }

    protected void routes() {



    }
}
