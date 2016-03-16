package vault5431;

import freemarker.template.Configuration;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import spark.ModelAndView;
import spark.template.freemarker.FreeMarkerEngine;
import vault5431.logging.LogType;
import vault5431.logging.SystemLogEntry;
import vault5431.users.User;
import vault5431.users.UserManager;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import static spark.Spark.*;


public class Vault {

    public static final File home = new File(java.lang.System.getProperty("user.home") + File.separator + ".vault5431");

    static {
        Security.addProvider(new BouncyCastleProvider());
        if (!home.exists()) {
            if (!home.mkdir()) {
                java.lang.System.err.println("Could not create ~/.vault5431 home!");
                java.lang.System.exit(2);
            }
        } else if (home.exists() && !home.isDirectory()) {
            if (!home.delete() && !home.mkdir()) {
                java.lang.System.err.println("Could not create ~/.vault5431 home!");
                java.lang.System.exit(2);
            }
        }
        if (!Sys.logFile.exists()) {
            try {
                if (!Sys.logFile.createNewFile()) {
                    java.lang.System.err.printf("Could not create system log file at %s!\n", Sys.logFile.getAbsoluteFile());
                    java.lang.System.exit(2);
                }
            } catch (IOException err) {
                err.printStackTrace();
                java.lang.System.err.printf("Could not create system log file at %s!\n", Sys.logFile.getAbsoluteFile());
                java.lang.System.exit(2);
            }
        }
    }

    private static final String demoUsername = "demoUser";
    private static final String demoPassword = "password";

    static {
        if (!UserManager.userExists(demoUsername)) {
            try {
                UserManager.create(demoUsername, demoPassword);
            } catch (Exception err) {
                err.printStackTrace();
                System.err.println("Could not create demo user!");
                System.exit(1);
            }
        }
    }

    public static final User demoUser = UserManager.getUser(demoUsername);

    public static void main(String[] args) throws Exception {
        File templateDir = new File(Vault.class.getResource("/templates").getFile());
        staticFileLocation("templates");
        port(5431);
        secure("./keystore.jks", "vault5431", null, null);
        java.lang.System.out.println("Hosting at: https://localhost:5431");
        Configuration freeMarkerConfiguration = new Configuration();
        freeMarkerConfiguration.setDirectoryForTemplateLoading(templateDir);
        get("/", (req, res) -> {
            Sys.debug("Serving /.", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            java.lang.System.out.println("Here");
            return new ModelAndView(attributes, "login.ftl");
        }, new FreeMarkerEngine(freeMarkerConfiguration));

        post("/authenticate", (req, res) -> {
            Sys.debug("Serving /authenticate.", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            java.lang.System.out.println("authenticate login");
            return new ModelAndView(attributes, "vault5431/templates/vault.ftl");
        }, new FreeMarkerEngine(freeMarkerConfiguration));

        get("/vault", (req, res) -> {
            Sys.debug("Serving /vault.", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            java.lang.System.out.println("vault page");
            return new ModelAndView(attributes, "vault.ftl");
        }, new FreeMarkerEngine(freeMarkerConfiguration));
    }

}
