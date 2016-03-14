package vault5431;

import freemarker.template.Configuration;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import spark.ModelAndView;
import spark.template.freemarker.FreeMarkerEngine;

import java.io.File;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import static spark.Spark.*;


class Vault {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static File home = new File(System.getProperty("user.home") + File.separator + ".vault5431");

    public static void main(String[] args) throws Exception {
        if (!home.exists()) {
            if (!home.mkdir()) {
                System.err.println("Could not create ~/.vault5431 home!");
                System.exit(2);
            }
        } else if (home.exists() && !home.isDirectory()) {
            if (!home.delete() && !home.mkdir()) {
                System.err.println("Could not create ~/.vault5431 home!");
                System.exit(2);
            }
        }
        File templateDir = new File(Vault.class.getResource("/templates").getFile());
        staticFileLocation("templates");
        port(5431);
        secure("./keystore.jks", "vault5431", null, null);
        System.out.println("Hosting at: https://localhost:5431");
        Configuration freeMarkerConfiguration = new Configuration();
        freeMarkerConfiguration.setDirectoryForTemplateLoading(templateDir);
        get("/", (req, res) -> {
            Map<String, Object> attributes = new HashMap<>();
            System.out.println("Here");
            return new ModelAndView(attributes, "login.ftl");
        }, new FreeMarkerEngine(freeMarkerConfiguration));

        post("/authenticate", (req, res) -> {
            Map<String, Object>  attributes = new HashMap<>();
            System.out.println("authenticate login");
            return new ModelAndView(attributes,"vault5431/templates/vault.ftl");
        }, new FreeMarkerEngine(freeMarkerConfiguration));

        get("/vault", (req, res) -> {
            Map<String, Object> attributes = new HashMap<>();
            System.out.println("vault page");
            return new ModelAndView(attributes, "vault.ftl");
        }, new FreeMarkerEngine(freeMarkerConfiguration));

    }
}
