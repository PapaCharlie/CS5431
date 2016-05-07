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
import java.util.Set;
import java.util.UUID;

/**
 * Created by papacharlie on 2016-05-01.
 */
final class SharedPasswordRoutes extends Routes {

    protected void routes() {

        authenticatedGet("/numshared", (req, res, token) ->
                success().put("numshared", token.getUser().numSharedPasswords(token))
        );

        authenticatedGet("/sharedpasswords", (req, res, token) ->
                new ModelAndView(new HashMap<>(0), "sharedpasswords.ftl")
        );

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
            return success().put("publicEncryptionKey", user.loadAndVerifyPublicEncryptionKey());
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
            return success().put("publicSigningKey", user.loadAndVerifyPublicSigningKey());
        });

        authenticatedGet("/shared", (req, res, token) -> {
            Set<SharedPassword> sharedPasswords = token.getUser().loadSharedPasswords(token);
            JSONObject response = success();
            response.put("salt", token.getUser().loadVaultSalt(token).toString());
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

        authenticatedPost("/shared/:target", (req, res, token) -> {
            String target = req.params("target");
            String sharedPassword = req.queryParams("sharedPassword");
            if (!provided(target, sharedPassword)) {
                return allFieldsRequired();
            }
            if (!UserManager.userExists(target)) {
                return userDoesNotExist();
            }
            if (token.getUsername().equals(target)) {
                return failure("You cannot share a password with yourself!");
            }
            try {
                JSONObject json = new JSONObject(sharedPassword);
                json.put("id", UUID.randomUUID().toString());
                json.put("sharer", token.getUsername());
                SharedPassword password = SharedPassword.fromJSON(json);
                User user = UserManager.getUser(target);
                user.addSharedPassword(password, token);
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
                    sharedPassword.getSharerUser().info(String.format("%s has accepted your shared password.", token.getUsername()));
                    JSONObject pass = new JSONObject(acceptedPassword);
                    pass.put("id", UUID.randomUUID().toString());
                    Password newPassword = Password.fromJSON(pass);
                    token.getUser().savePassword(newPassword, token);
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
                    token.getUser().info(String.format("Rejecting shared password from %s.", sharedPassword.getSharer()), token.getIp());
                    sharedPassword.getSharerUser().info(String.format("%s has rejected your shared password.", token.getUsername()));
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
