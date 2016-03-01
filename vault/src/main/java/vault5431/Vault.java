package vault5431;

import static spark.Spark.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

class Vault {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        User test = new User("John", "Doe", "test@vaul5431.com");
        port(5431);
        secure("./keystore.jks", "vault5431", null, null);
        System.out.println("Hosting at: https://localhost:5431");
        get("/", (req, res) -> {
            return "Hello World";
        });
    }
}
