package vault5431.routes;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import spark.ModelAndView;
import vault5431.Sys;
import vault5431.users.Password;
import vault5431.users.SharedPassword;
import vault5431.users.User;
import vault5431.users.UserManager;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.UUID;

/**
 * Created by papacharlie on 2016-05-01.
 */
final class PasswordSharingRoutes extends Routes {

    protected void routes() {

        authenticatedGet("/numshared", (req, res, token) ->
                success().put("numshared", token.getUser().numSharedPasswords(token))
        );

        authenticatedGet("/sharedpasswords", (req, res, token) -> {
            Map<String, Object> attributes = new HashMap<>();
            return new ModelAndView(attributes, "sharedpasswords.ftl");
        });

        authenticatedGet("/privateEncryptionKey", (req, res, token) ->
                success().put("privateEncryptionKey", token.getUser().loadPrivateEncryptionKey(token))
        );

        authenticatedGet("/privateSigningKey", (req, res, token) ->
                success().put("privateSigningKey", token.getUser().loadPrivateSigningKey(token))
        );

        authenticatedGet("/publicEncryptionKey/:username", (req, res, token) -> {
            String username = req.params("username");
            if (!provided(username)) {
                return failure("Username must be provided!");
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
                return failure("Username must be provided!");
            }
            if (!UserManager.userExists(username)) {
                return userDoesNotExist();
            }
            User user = UserManager.getUser(username);
            Sys.debug(String.format("Loading %s's public signing key.", user.getShortHash()), token);
            return success().put("publicSigningKey", user.loadPublicSigningKey());
        });

        authenticatedGet("/shared", (req, res, token) -> {
            LinkedList<SharedPassword> sharedPasswords = token.getUser().loadSharedPasswords(token);
            JSONObject response = success();
            response.put("salt", token.getUser().loadVaultSalt().toString());
            if (sharedPasswords.size() > 0) {
                JSONArray passwords = new JSONArray();
                for (SharedPassword sharedPassword : sharedPasswords) {
                    JSONObject p = sharedPassword.toJSONObject();
                    p.put("sharerPublicSigningKey", sharedPassword.getSharerPublicSigningKey());
                    passwords.put(p);
                }
                response.put("sharedPasswords", passwords);
            } else {
                response.put("sharedPasswords", new LinkedList<>());
            }
            return response.put("privateEncryptionKey", token.getUser().loadPrivateEncryptionKey(token));
        });

        authenticatedPost("/shared/:username", (req, res, token) -> {
            String username = req.params("username");
            String sharedPassword = req.queryParams("sharedPassword");
            if (!provided(username, sharedPassword)) {
                return allFieldsRequired();
            }
            if (!UserManager.userExists(username)) {
                return userDoesNotExist();
            }
            try {
                JSONObject json = new JSONObject(sharedPassword);
                json.put("id", UUID.randomUUID().toString());
                SharedPassword password = SharedPassword.fromJSON(json);
                User user = UserManager.getUser(username);
                user.addSharedPassword(password);
                user.info(String.format("Received shared password from %s.", password.getSharer()), token.getIp());
                return success();
            } catch (JSONException err) {
                return invalidRequest();
            } catch (IllegalArgumentException err) {
                return failure(err);
            }
        });

        authenticatedPut("/shared/:id", (req, res, token) -> {
            String id = req.params("id");
            String acceptedPassword = req.queryParams("acceptedPassword");
            if (!provided(id, acceptedPassword)) {
                return allFieldsRequired();
            }
            try {
                UUID uuid = UUID.fromString(id);
                SharedPassword sharedPassword = token.getUser().deleteSharedPassword(uuid, token);
                if (sharedPassword != null) {
                    token.getUser().info(String.format("Accepting shared password from %s.", sharedPassword.getSharer()), token.getIp());
                    sharedPassword.getSharerUser().info("Your shared password was accepted.");
                    JSONObject pass = new JSONObject(acceptedPassword);
                    pass.put("id", UUID.randomUUID().toString());
                    Password newPassword = Password.fromJSON(pass);
                    token.getUser().addPasswordToVault(newPassword, token);
                    return success().put("message", "Successfully accepted shared password.");
                } else {
                    return failure("No such shared password");
                }
            } catch (IllegalArgumentException err) {
                return failure(err);
            }
        });

        authenticatedDelete("/shared/:id", (req, res, token) -> {
            String id = req.params("id");
            if (!provided(id)) {
                return allFieldsRequired();
            }
            try {
                UUID uuid = UUID.fromString(id);
                SharedPassword sharedPassword = token.getUser().deleteSharedPassword(uuid, token);
                if (sharedPassword != null) {
                    token.getUser().info(String.format("Rjecting shared password from %s.", sharedPassword.getSharer()), token.getIp());
                    sharedPassword.getSharerUser().info("Your shared password was rejected.");
                    return success().put("message", "Successfully rejected shared password");
                } else {
                    return failure("No such shared password");
                }
            } catch (IllegalArgumentException err) {
                return failure(err);
            }
        });

    }

}
