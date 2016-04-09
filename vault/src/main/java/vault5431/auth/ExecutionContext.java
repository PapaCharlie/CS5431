package vault5431.auth;

/**
 * Inspired by Scala's execution context. Contains the User's valid token and the IP the request is coming from.
 */
public class ExecutionContext {

    private final String ip;
    private final Token token;

    public ExecutionContext(String ip, Token token) {
        this.ip = ip;
        this.token = token;
    }

    public Token getToken() {
        return this.token;
    }

    public String getIp() {
        return this.ip;
    }

}
