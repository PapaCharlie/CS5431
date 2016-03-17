package vault5431;

import freemarker.template.Configuration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import spark.ModelAndView;
import spark.template.freemarker.FreeMarkerEngine;
import vault5431.logging.SystemLogEntry;
import vault5431.logging.UserLogEntry;
import vault5431.users.User;
import vault5431.users.UserManager;

import java.io.File;
import java.io.IOException;
import java.security.Security;
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

    public static final Configuration freeMarkerConfiguration = new Configuration();
    public static final FreeMarkerEngine freeMarkerEngine =  new FreeMarkerEngine(freeMarkerConfiguration);

    public static final User demoUser = UserManager.getUser(demoUsername);

    public static void main(String[] args) throws Exception {
        System.out.println(home);
        File templateDir = new File(Vault.class.getResource("/templates").getFile());
        staticFileLocation("templates");
        port(5431);
        secure("./keystore.jks", "vault5431", null, null);
        System.out.println("Hosting at: https://localhost:5431");
        freeMarkerConfiguration.setDirectoryForTemplateLoading(templateDir);

        get("/", (req, res) -> {
            Sys.debug("Serving /.", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            return new ModelAndView(attributes, "login.ftl");
        }, freeMarkerEngine);

        post("/authenticate", (req, res) -> {
            Sys.debug("Serving /authenticate.", req.ip());
            if (UserManager.userExists(req.queryParams("username"))){
                System.out.println("exists");
                res.redirect("/vault");
            }
            else{
                res.redirect("/");
            }
            demoUser.info("Action: Log In", demoUser, req.ip());
            return "";
        });

        get("/vault", (req, res) -> {
            Sys.debug("Serving /vault.", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            Password[] plist = demoUser.loadPasswords();

            List<Map<String, String>> listofmaps = new ArrayList<>();

            for(Password p: plist){
                listofmaps.add(p.toMap());
            }

            attributes.put("storedpasswords", listofmaps);
            return new ModelAndView(attributes, "vault.ftl");
        }, freeMarkerEngine);

        post("/vault", (req, res) -> {
            Sys.debug("Serving /vault.", req.ip());
            Map<String, Object> attributes = new HashMap<>();
            return new ModelAndView(attributes, "vault.ftl");
        }, freeMarkerEngine);

        post("/genPasswordLog", (req, res) -> {
            Map<String, Object> attributes = new HashMap<>();
            String user_ip = req.queryParams("ip");
            System.out.println(user_ip);
            return new ModelAndView(attributes, "vault5431/templates/vault.ftl");
        }, freeMarkerEngine);

        post("/changepassword", (req, res) -> {
            Sys.debug("Serving /savepassword.", req.ip());
            String w = req.queryParams("name");
            //changepassword
            demoUser.info("Changed Password for " + w, req.ip());
            res.redirect("/vault");
            return "";
        });

        post("/savepassword", (req, res) -> {
            Sys.debug("Serving /savepassword.", req.ip());
            String w = req.queryParams("web");
            Password p = new Password(w, req.queryParams("url"), req.queryParams("username"), req.queryParams("password"));
            demoUser.addPassword(p);
            demoUser.info("Saved Password from " + w, req.ip());
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
        }, freeMarkerEngine);

        get("/generate", (req, res) -> {
            Sys.debug("Serving /savepassword.", req.ip());
            String len = req.queryParams("length");
            String pass = PasswordGenerator.generatePassword(Integer.parseInt(len));
            res.cookie("randompass", pass);
            res.redirect("/generator");
            return "";
        });

        get("/userlog", (req, res) -> {
            Sys.debug("Serving /log.", req.ip());
            java.lang.System.out.println("user log");
            Map<String, Object> attributes = new HashMap<>();

            List<Map<String, String>> loglst = new ArrayList<>();

            for (UserLogEntry u : demoUser.loadLog()) {
                loglst.add(u.toMap());
            }

            attributes.put("userloglist", loglst);
            return new ModelAndView(attributes, "userlog.ftl");
        }, freeMarkerEngine);

        get("/syslog", (req, res) -> {
            Sys.debug("Serving /syslog.", req.ip());
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
