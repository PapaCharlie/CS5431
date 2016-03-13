package vault5431;

import static spark.Spark.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.security.Security;

import spark.ModelAndView;
import spark.template.freemarker.FreeMarkerEngine;
import freemarker.template.Configuration;
import java.util.HashMap;
import java.util.Map;


class Vault {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static final File home = new File(System.getProperty("user.home") + File.separator + ".vault5431");

    public static void main(String[] args) {
        if (!home.exists()) {
            if (!home.mkdir()){
                System.err.println("Could not create ~/.vault5431 home!");
                System.exit(2);
            }
        } else if (home.exists() && !home.isDirectory()) {
            if (!home.delete() && !home.mkdir()) {
                System.err.println("Could not create ~/.vault5431 home!");
                System.exit(2);
            }
        }
        staticFileLocation("vault5431/templates");
        port(5431);
        secure("./keystore.jks", "vault5431", null, null);
        System.out.println("Hosting at: https://localhost:5431");
        Configuration freeMarkerConfiguration = new Configuration();
        freeMarkerConfiguration.setClassForTemplateLoading(Vault.class, "/");
        get("/", (req, res)->{
            Map<String, Object>  attributes = new HashMap<>();
            System.out.println("Here");
           return new ModelAndView(attributes,"vault5431/templates/login.ftl");
        }, new FreeMarkerEngine(freeMarkerConfiguration));

    }
}
