package vault5431.routes;

import vault5431.Sys;
import vault5431.users.User;
import vault5431.users.UserManager;

/**
 * Created by papacharlie on 2016-05-01.
 */
final class PasswordSharingRoutes extends Routes {

    protected void routes() {
        authenticatedGet("/privateEncryptionKey", (req, res, token) ->
                success().put("privateEncryptionKey", token.getUser().loadPrivateEncryptionKey(token))
        );

        authenticatedGet("/privateSigningKey", (req, res, token) ->
                success().put("privateSigningKey", token.getUser().loadPrivateSigningKey(token))
        );

        authenticatedGet("/publicEncryptionKey/:username", (req, res, token) -> {
            String username = req.params("username");
            if (!provided(username)) {
                return failure().put("error", "Username must be provided!");
            }
            if (!UserManager.userExists(username)) {
                return userDoesNotExist();
            }
            User user = UserManager.getUser(username);
            Sys.debug(String.format("Loading %s's public encryption key.", user.getShortHash()), token);
            return success().put("publicEncryptionKey", user.loadPublicEncryptionKey());
        });

        authenticatedGet("/publicSigningKey/:username", (req, res, token) -> {
            String username = req.params("username");
            if (!provided(username)) {
                return failure().put("error", "Username must be provided!");
            }
            if (!UserManager.userExists(username)) {
                return userDoesNotExist();
            }
            User user = UserManager.getUser(username);
            Sys.debug(String.format("Loading %s's public signing key.", user.getShortHash()), token);
            return success().put("publicSigningKey", user.loadPublicSigningKey());
        });

        authenticatedPost("/sharepassword/:username", (req, res, token) -> {
            String username = req.params("username");
            String sharedPassword = req.queryParams("sharedPassword");
            String signature = req.queryParams("signature");
            if (!provided(username, sharedPassword, signature)){
                return allFieldsRequired();
            }
            if (!UserManager.userExists(username)) {
                return userDoesNotExist();
            }
            User user = UserManager.getUser(username);
            return invalidRequest();
        });

    }

}
