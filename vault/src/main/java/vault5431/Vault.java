package vault5431;

import static spark.Spark.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

import spark.ModelAndView;
import spark.template.freemarker.FreeMarkerEngine;
import freemarker.template.Configuration;
import java.util.HashMap;
import java.util.Map;


class Vault {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        User test = new User("John", "Doe", "test@vaul5431.com");
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

        /*get("/", (req, res) -> {
            return "Hello World";
        });*/

    }
}
