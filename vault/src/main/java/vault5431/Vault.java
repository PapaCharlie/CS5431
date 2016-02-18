package vault5431;

import static spark.Spark.*;

class Vault {
    public static void main(String[] args) {
        port(443);
        secure("./keystore.jks", "vault5431", null, null);
        get("/", (req, res) -> {
            return "Hello World";
        });
    }
}
