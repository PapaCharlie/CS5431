package vault5431;

import static spark.Spark.get;
import static spark.Spark.port;

public class Redirector {

    public static void main(String[] args) {
        port(80);
        get("*", (req, res) -> {
            res.redirect("https://www.vault5431.com/");
            return null;
        });
    }

}
