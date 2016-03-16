package vault5431;

import freemarker.template.Configuration;
import freemarker.template.DefaultObjectWrapper;
import freemarker.template.Template;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import spark.ModelAndView;
import spark.template.freemarker.FreeMarkerEngine;
import vault5431.logging.LogType;
import vault5431.logging.SystemLogEntry;
import vault5431.logging.UserLogEntry;
import vault5431.users.User;
import vault5431.users.UserManager;
import vault5431.logging.UserLogEntry;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.security.Security;
import java.time.LocalDateTime;
import java.util.*;


import static spark.Spark.*;


public class Vault {

    public static final File home = new File(java.lang.System.getProperty("user.home"), ".vault5431");

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
        System.out.println(home);
        File templateDir = new File(Vault.class.getResource("/templates").getFile());
        staticFileLocation("templates");
        port(5431);
        secure("./keystore.jks", "vault5431", null, null);
        System.out.println("Hosting at: https://localhost:5431");
        Configuration freeMarkerConfiguration = new Configuration();
        freeMarkerConfiguration.setDirectoryForTemplateLoading(templateDir);

        get("/", (req, res) -> {
            Sys.debug("Serving /.", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            java.lang.System.out.println("Here");
//            demoUser.appendToLog(new UserLogEntry(LogType.INFO, "some ip", "alicia", LocalDateTime.now(), "hi", "hi"));
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
            String message = "Action: Log In";
            demoUser.info(message, demoUser, req.ip());
            return new ModelAndView(attributes, "vault.ftl");
        }, new FreeMarkerEngine(freeMarkerConfiguration));

        post("/vault", (req, res) -> {
            Sys.debug("Serving /vault.", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            java.lang.System.out.println("vault page");
            //This is just a test for now.

            String username = req.queryParams("username");
            //String user_ip = req.queryParams("ip");
            String message = "Action: Log In";
            demoUser.info(message, demoUser, req.ip());
            return new ModelAndView(attributes, "vault.ftl");
        }, new FreeMarkerEngine(freeMarkerConfiguration));

        post("/genPasswordLog", (req, res) -> {
            Map<String, Object> attributes = new HashMap<>();
            String user_ip = req.queryParams("ip");
            System.out.println(user_ip);
            return new ModelAndView(attributes, "vault5431/templates/vault.ftl");
        }, new FreeMarkerEngine(freeMarkerConfiguration));

        post("/savepassword", (req, res) -> {
            Sys.debug("Serving /savepassword.", req.ip());
            String w = req.queryParams("web");
            demoUser.info("Saved Password from " + w, req.ip()); //type check this. incorrect types
            res.redirect("/vault");
            return "";
        });

        get("/generator", (req, res) -> {
            Sys.debug("Serving /password generator.", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            String p = req.cookie("randompass");
            if (p == null) {
                p = "";
            }
            System.out.println("cookie " + p);
            attributes.put("randompassword", p);
            java.lang.System.out.println("generator");
            res.removeCookie("randompass");
            return new ModelAndView(attributes, "generator.ftl");
        }, new FreeMarkerEngine(freeMarkerConfiguration));

        get("/generate", (req, res) -> {
            Sys.debug("Serving /savepassword.", req.ip());
            String len = req.queryParams("length");
            String pass = PasswordGenerator.generatePassword(Integer.parseInt(len));
            res.cookie("randompass", pass);
            res.redirect("/generator");
            return "";
        });

        get("/log", (req, res) -> {
            Sys.debug("Serving /log.", req.ip());
            java.lang.System.out.println("user log");
            Map<String, Object> attributes = new HashMap<>();

            List<String[]> loglst = new ArrayList<String[]>();

            for (UserLogEntry u : demoUser.loadLog()) {
                System.out.println(u);
                loglst.add(u.asArray());
            }
            attributes.put("userloglist", loglst);
            return new ModelAndView(attributes, "userlog.ftl");
        }, new FreeMarkerEngine(freeMarkerConfiguration));
    }

}