package vault5431.routes;

import freemarker.template.Configuration;
import spark.template.freemarker.FreeMarkerEngine;

import java.io.IOException;

import static spark.Spark.staticFileLocation;

/**
 * Created by papacharlie on 3/25/16.
 */
public abstract class Routes {

    public static final String vaultHome = "/vault/home";
    public static final String vault = "/vault";
    public static final Configuration freeMarkerConfiguration = new Configuration();
    public static final FreeMarkerEngine freeMarkerEngine = new FreeMarkerEngine(freeMarkerConfiguration);

    protected abstract void routes();

    public static void initialize() throws IOException {
        staticFileLocation("templates");
        freeMarkerConfiguration.setClassForTemplateLoading(Routes.class, "/templates");
        new Authentication().routes();
        new Generator().routes();
        new Logs().routes();
        new Passwords().routes();
    }

}
